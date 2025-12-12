const express = require("express");
const cors = require("cors");
const fs = require("fs");
require("dotenv").config();
const OpenAI = require("openai");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// ---- OpenAI ----
if (!process.env.OPENAI_API_KEY) {
  console.error("Missing OPENAI_API_KEY");
  process.exit(1);
}

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ---- Shopify ----
const SHOPIFY_STORE_DOMAIN = process.env.SHOPIFY_STORE_DOMAIN;
const SHOPIFY_API_TOKEN = process.env.SHOPIFY_API_TOKEN;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-01";

let shopifyClient = null;
if (SHOPIFY_STORE_DOMAIN && SHOPIFY_API_TOKEN) {
  shopifyClient = axios.create({
    baseURL: `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}`,
    headers: { "X-Shopify-Access-Token": SHOPIFY_API_TOKEN },
    timeout: 5000,
  });
} else {
  console.warn(
    "Shopify env vars missing; order lookup will be disabled until they are set."
  );
}

// ---- Sanitizing ----
const MAX_USER_MESSAGE_LENGTH = 1000;

function sanitizeUserMessage(input) {
  let text = String(input || "");
  text = text.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  text = text.replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, "");
  text = text.replace(/<\/?[^>]+>/g, "");
  text = text.replace(/\s+/g, " ").trim();
  if (text.length > MAX_USER_MESSAGE_LENGTH) {
    text = text.slice(0, MAX_USER_MESSAGE_LENGTH);
  }
  return text;
}

function sanitizeOrderNumber(orderNumber) {
  if (!orderNumber) return "";
  return String(orderNumber)
    .replace(/[^A-Za-z0-9#\- ]/g, "")
    .trim()
    .slice(0, 40);
}

// ---- Intent detection (simple baseline, unchanged) ----
function detectIntent(message) {
  const text = message.toLowerCase();

  const shipping = ["verzending", "bezorg", "track", "order", "shipping", "delivery"];
  const returns = ["retour", "refund", "terug", "herroep", "omruil"];
  const usage = ["gebruik", "how", "hoe", "tutorial", "uitleg"];

  let orderNumber = "";
  const matches = message.match(/(\d[\d\- ]*\d)/g);
  if (matches) {
    orderNumber = sanitizeOrderNumber(matches[matches.length - 1]);
  }

  let mainIntent = "general";
  if (shipping.some((w) => text.includes(w)) || orderNumber) {
    mainIntent = "shipping_or_order";
  }
  if (returns.some((w) => text.includes(w))) {
    mainIntent = "return_or_withdrawal";
  }
  if (usage.some((w) => text.includes(w)) && mainIntent === "general") {
    mainIntent = "product_usage";
  }

  return { mainIntent, orderNumber };
}

// ---- Shopify lookup (working simple version) ----
async function lookupShopifyOrder(orderNumberRaw) {
  if (!shopifyClient) return null;

  const orderNumber = sanitizeOrderNumber(orderNumberRaw);
  if (!orderNumber) return null;

  const nameParam = orderNumber.startsWith("#") ? orderNumber : `#${orderNumber}`;

  try {
    const res = await shopifyClient.get("/orders.json", {
      params: { name: nameParam, status: "any" },
    });

    const orders = (res.data && res.data.orders) ? res.data.orders : [];
    if (!orders.length) return null;

    const order = orders[0];
    const fulfillment = order.fulfillments && order.fulfillments[0] ? order.fulfillments[0] : null;

    return {
      orderName: order.name || null,
      fulfillmentStatus: order.fulfillment_status || null,
      financialStatus: order.financial_status || null,
      tracking: fulfillment && fulfillment.tracking_numbers && fulfillment.tracking_numbers[0]
        ? fulfillment.tracking_numbers[0]
        : null,
      trackingUrl: fulfillment && fulfillment.tracking_urls && fulfillment.tracking_urls[0]
        ? fulfillment.tracking_urls[0]
        : null,
      createdAt: order.created_at || null,
    };
  } catch (e) {
    console.error("Shopify lookup error:", e.message);
    return null;
  }
}

// ---- Knowledge loading + improved structure ----
function readFile(path) {
  try {
    return fs.existsSync(path) ? fs.readFileSync(path, "utf8") : "";
  } catch {
    return "";
  }
}

function normalizeText(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/[\u2019’]/g, "'")
    .replace(/[^a-z0-9à-ÿ#\-\s]/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// small stopword set (NL + EN) to avoid scoring noise
const STOPWORDS = new Set([
  "de","het","een","en","of","maar","want","dus","dat","dit","die","des","der",
  "ik","jij","je","u","hij","zij","ze","wij","we","jullie","hun","hen","mijn","jouw","uw",
  "is","zijn","was","waren","ben","bent","wordt","worden","kan","kunnen","zal","zullen",
  "met","voor","van","naar","op","in","aan","bij","als","om","uit","tot","over","onder",
  "the","a","an","and","or","but","because","so","that","this","these","those",
  "i","you","he","she","we","they","my","your","our","their",
  "is","are","was","were","be","been","being","can","could","will","would","should",
  "with","for","from","to","on","in","at","as","by","of","about","into","over","under"
]);

function extractKeywords(query) {
  const norm = normalizeText(query);
  const parts = norm.split(" ").filter(Boolean);
  const keywords = [];
  for (const p of parts) {
    if (p.length < 3) continue;
    if (STOPWORDS.has(p)) continue;
    keywords.push(p);
  }
  // de-dupe while preserving order
  return [...new Set(keywords)];
}

// Chunk markdown by headings + paragraphs.
// Each chunk keeps its "heading path" for better context.
function chunkMarkdown(source, markdown, maxChunkChars = 900) {
  const lines = String(markdown || "").split("\n");

  let h1 = "";
  let h2 = "";
  let h3 = "";

  const chunks = [];
  let buffer = "";

  function flushBuffer() {
    const text = buffer.trim();
    buffer = "";
    if (!text) return;

    // split oversized buffers into smaller parts
    if (text.length <= maxChunkChars) {
      chunks.push({
        source,
        heading: [h1, h2, h3].filter(Boolean).join(" > "),
        text,
      });
      return;
    }

    // hard split by paragraphs
    const paras = text.split(/\n{2,}/);
    let current = "";
    for (const p of paras) {
      const part = p.trim();
      if (!part) continue;

      if ((current + "\n\n" + part).trim().length > maxChunkChars && current.trim()) {
        chunks.push({
          source,
          heading: [h1, h2, h3].filter(Boolean).join(" > "),
          text: current.trim(),
        });
        current = part;
      } else {
        current = (current ? current + "\n\n" : "") + part;
      }
    }
    if (current.trim()) {
      chunks.push({
        source,
        heading: [h1, h2, h3].filter(Boolean).join(" > "),
        text: current.trim(),
      });
    }
  }

  for (const raw of lines) {
    const line = raw || "";
    const h1m = line.match(/^#\s+(.+)/);
    const h2m = line.match(/^##\s+(.+)/);
    const h3m = line.match(/^###\s+(.+)/);

    if (h1m) {
      flushBuffer();
      h1 = h1m[1].trim();
      h2 = "";
      h3 = "";
      continue;
    }
    if (h2m) {
      flushBuffer();
      h2 = h2m[1].trim();
      h3 = "";
      continue;
    }
    if (h3m) {
      flushBuffer();
      h3 = h3m[1].trim();
      continue;
    }

    buffer += line + "\n";
  }

  flushBuffer();

  // drop tiny chunks (noise)
  return chunks.filter((c) => c.text && c.text.trim().length >= 80);
}

// source weighting (structure improvement)
// policies/shipping matrix should win when query matches those topics
const SOURCE_WEIGHT = {
  "Policies.md": 3,
  "Shipping matrix.md": 3,
  "Customer support rules.md": 3,
  "Promotions & discounts.md": 2,
  "FAQ.md": 2,
  "Troubleshooting.md": 2,
  "Products.md": 1,
  "Product tutorials.md": 1,
  "Company overview.md": 1,
  "Legal.md": 1,
};

function loadClient(clientId) {
  const base = `./Clients/${clientId}`;

  const brandVoice = readFile(`${base}/Brand voice.md`);
  const supportRules = readFile(`${base}/Customer support rules.md`);

  const files = [
    "FAQ.md",
    "Policies.md",
    "Products.md",
    "Company overview.md",
    "Legal.md",
    "Product tutorials.md",
    "Promotions & discounts.md",
    "Shipping matrix.md",
    "Troubleshooting.md",
  ];

  const allChunks = [];

  for (const file of files) {
    const content = readFile(`${base}/${file}`);
    if (!content || !content.trim()) continue;

    const chunks = chunkMarkdown(file, content, 900);
    for (const c of chunks) {
      allChunks.push({
        source: file,
        heading: c.heading || "",
        text: c.text,
      });
    }
  }

  const clientConfig = JSON.parse(readFile(`${base}/client-config.json`) || "{}");

  return { brandVoice, supportRules, chunks: allChunks, clientConfig };
}

// ---- Relevance scoring (improved) ----
function countHits(textNorm, keyword) {
  // simple whole-word-ish match
  // we avoid expensive regex; we score by occurrences of " keyword " boundaries
  const k = keyword.trim();
  if (!k) return 0;
  let count = 0;
  let idx = 0;
  while (true) {
    idx = textNorm.indexOf(k, idx);
    if (idx === -1) break;
    count++;
    idx += k.length;
  }
  return count;
}

function scoreChunk(chunk, queryKeywords) {
  const textNorm = normalizeText(chunk.text);
  const headingNorm = normalizeText(chunk.heading || "");
  let score = 0;

  for (const kw of queryKeywords) {
    const hitsText = countHits(textNorm, kw);
    const hitsHeading = headingNorm ? countHits(headingNorm, kw) : 0;

    // heading hits are more important than body hits
    score += hitsText * 2 + hitsHeading * 4;
  }

  const weight = SOURCE_WEIGHT[chunk.source] || 1;
  score = score * weight;

  return score;
}

function isPolicyLikeQuestion(msgNorm) {
  const keys = [
    "verzend", "shipping", "bezorg", "delivery",
    "retour", "refund", "garantie", "warranty",
    "korting", "discount", "promot", "actie",
    "kosten", "price", "betaling", "payment"
  ];
  return keys.some((k) => msgNorm.includes(k));
}

// Select top chunks with a hard cap on total context size
function selectTopChunks(chunks, message, limit = 8, maxTotalChars = 4500) {
  const msgNorm = normalizeText(message);
  const keywords = extractKeywords(message);

  const scored = chunks
    .map((c) => ({
      ...c,
      score: scoreChunk(c, keywords),
    }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score);

  // If policy-like and nothing matched, still pick a few from Policies/Shipping
  if (!scored.length && isPolicyLikeQuestion(msgNorm)) {
    const fallback = chunks
      .filter((c) => c.source === "Policies.md" || c.source === "Shipping matrix.md")
      .slice(0, limit)
      .map((c) => ({ ...c, score: 1 }));
    return fallback;
  }

  const selected = [];
  let total = 0;

  for (const c of scored) {
    const block = `### ${c.source}${c.heading ? " — " + c.heading : ""}\n${c.text}\n`;
    if (total + block.length > maxTotalChars) continue;

    selected.push(c);
    total += block.length;

    if (selected.length >= limit) break;
  }

  return selected;
}

// ---- Route ----
app.post("/chat", async (req, res) => {
  const message = sanitizeUserMessage(req.body.message);
  if (!message) return res.status(400).json({ error: "Invalid message" });

  const clientId = req.query.client || "Advantum";
  const data = loadClient(clientId);
  const intent = detectIntent(message);

  let shopify = null;
  if (intent.mainIntent === "shipping_or_order" && intent.orderNumber) {
    shopify = await lookupShopifyOrder(intent.orderNumber);
  }

  const topChunks = selectTopChunks(data.chunks, message, 8, 4500);
  const context = topChunks
    .map((c) => `### ${c.source}${c.heading ? " — " + c.heading : ""}\n${c.text}`)
    .join("\n\n");

  const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName || clientId}.
Use the same language as the user. No emojis.
Never guess policies, prices, or shipping rules.
Only answer using the provided context. If the context does not contain the answer, say you are not sure and ask a short follow-up question.

BRAND VOICE:
${data.brandVoice || ""}

CUSTOMER SUPPORT RULES:
${data.supportRules || ""}

SHOPIFY ORDER DATA:
${shopify ? JSON.stringify(shopify, null, 2) : "none"}

RELEVANT KNOWLEDGE (selected excerpts):
${context || "No relevant knowledge matched."}
`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message },
      ],
    });

    return res.json({
      reply: response.choices[0].message.content,
      intent,
      shopify,
    });
  } catch (e) {
    console.error("Chat error:", e.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/", (req, res) => {
  res.send("AI support backend running.");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});








