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

function sanitizeClientId(id) {
  const fallback = "Advantum";
  const raw = String(id || "").trim();
  if (!raw) return fallback;
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) return fallback;
  return raw;
}

function sanitizeSessionId(id) {
  const raw = String(id || "").trim();
  if (!raw) return "";
  return raw.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 80);
}

// ---- Session memory + lightweight flow state ----
const SESSION_HISTORY_LIMIT = 10; // total messages (user + assistant)
const SESSION_TTL_MS = 1000 * 60 * 60 * 6; // 6 hours

// sessionId -> { updatedAt: number, messages: [{role, content}], meta: { expectedSlot?: string, lastIntent?: string } }
const sessionStore = new Map();

function getSession(sessionId) {
  if (!sessionId) return null;
  const existing = sessionStore.get(sessionId);
  if (!existing) return null;
  if (Date.now() - existing.updatedAt > SESSION_TTL_MS) {
    sessionStore.delete(sessionId);
    return null;
  }
  return existing;
}

function upsertSession(sessionId, messages, meta) {
  if (!sessionId) return;
  sessionStore.set(sessionId, {
    updatedAt: Date.now(),
    messages,
    meta: meta || {},
  });
}

function appendToHistory(sessionId, role, content) {
  if (!sessionId || !content) return;
  const existing = getSession(sessionId);
  const history = existing ? existing.messages.slice() : [];
  const meta = existing ? { ...(existing.meta || {}) } : {};

  history.push({ role, content });
  const trimmed = history.slice(-SESSION_HISTORY_LIMIT);

  upsertSession(sessionId, trimmed, meta);
}

function getMeta(sessionId) {
  const s = getSession(sessionId);
  return s && s.meta ? s.meta : {};
}

function setMeta(sessionId, patch) {
  if (!sessionId) return;
  const existing = getSession(sessionId);
  const messages = existing ? existing.messages.slice() : [];
  const meta = existing ? { ...(existing.meta || {}) } : {};
  const merged = { ...meta, ...(patch || {}) };
  upsertSession(sessionId, messages, merged);
}

function clearExpectedSlot(sessionId) {
  setMeta(sessionId, { expectedSlot: "" });
}

function buildHistoryMessages(sessionId) {
  const existing = getSession(sessionId);
  if (!existing) return [];
  return existing.messages.slice();
}

// periodic cleanup
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of sessionStore.entries()) {
    if (!val || now - val.updatedAt > SESSION_TTL_MS) sessionStore.delete(key);
  }
}, 1000 * 60 * 15);

// ---- Intent detection (baseline) ----
function detectIntent(message) {
  const text = message.toLowerCase();

  const shipping = ["verzending", "bezorg", "track", "order", "shipping", "delivery"];
  const returns = ["retour", "refund", "terug", "herroep", "omruil"];
  const usage = ["gebruik", "how", "hoe", "tutorial", "uitleg"];

  let orderNumber = "";
  const matches = message.match(/(\d[\d\- ]*\d)/g);
  if (matches) orderNumber = sanitizeOrderNumber(matches[matches.length - 1]);

  let mainIntent = "general";
  if (shipping.some((w) => text.includes(w)) || orderNumber) mainIntent = "shipping_or_order";
  if (returns.some((w) => text.includes(w))) mainIntent = "return_or_withdrawal";
  if (usage.some((w) => text.includes(w)) && mainIntent === "general") mainIntent = "product_usage";

  return { mainIntent, orderNumber };
}

// ---- Shopify lookup ----
async function lookupShopifyOrder(orderNumberRaw) {
  if (!shopifyClient) return null;

  const orderNumber = sanitizeOrderNumber(orderNumberRaw);
  if (!orderNumber) return null;

  const nameParam = orderNumber.startsWith("#") ? orderNumber : `#${orderNumber}`;

  try {
    const res = await shopifyClient.get("/orders.json", {
      params: { name: nameParam, status: "any" },
    });

    const orders = res.data && res.data.orders ? res.data.orders : [];
    if (!orders.length) return null;

    const order = orders[0];
    const fulfillment =
      order.fulfillments && order.fulfillments[0] ? order.fulfillments[0] : null;

    return {
      orderName: order.name || null,
      fulfillmentStatus: order.fulfillment_status || null,
      financialStatus: order.financial_status || null,
      tracking:
        fulfillment && fulfillment.tracking_numbers && fulfillment.tracking_numbers[0]
          ? fulfillment.tracking_numbers[0]
          : null,
      trackingUrl:
        fulfillment && fulfillment.tracking_urls && fulfillment.tracking_urls[0]
          ? fulfillment.tracking_urls[0]
          : null,
      createdAt: order.created_at || null,
    };
  } catch (e) {
    console.error("Shopify lookup error:", e.message);
    return null;
  }
}

// ---- Knowledge loading ----
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
  return [...new Set(keywords)];
}

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

    if (text.length <= maxChunkChars) {
      chunks.push({ source, heading: [h1, h2, h3].filter(Boolean).join(" > "), text });
      return;
    }

    const paras = text.split(/\n{2,}/);
    let current = "";
    for (const p of paras) {
      const part = p.trim();
      if (!part) continue;

      if ((current + "\n\n" + part).trim().length > maxChunkChars && current.trim()) {
        chunks.push({ source, heading: [h1, h2, h3].filter(Boolean).join(" > "), text: current.trim() });
        current = part;
      } else {
        current = (current ? current + "\n\n" : "") + part;
      }
    }
    if (current.trim()) chunks.push({ source, heading: [h1, h2, h3].filter(Boolean).join(" > "), text: current.trim() });
  }

  for (const raw of lines) {
    const line = raw || "";
    const h1m = line.match(/^#\s+(.+)/);
    const h2m = line.match(/^##\s+(.+)/);
    const h3m = line.match(/^###\s+(.+)/);

    if (h1m) { flushBuffer(); h1 = h1m[1].trim(); h2 = ""; h3 = ""; continue; }
    if (h2m) { flushBuffer(); h2 = h2m[1].trim(); h3 = ""; continue; }
    if (h3m) { flushBuffer(); h3 = h3m[1].trim(); continue; }

    buffer += line + "\n";
  }

  flushBuffer();
  return chunks.filter((c) => c.text && c.text.trim().length >= 80);
}

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

function safeJsonParse(raw, fallback = {}) {
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" ? obj : fallback;
  } catch {
    return fallback;
  }
}

function loadClient(clientIdRaw) {
  const clientId = sanitizeClientId(clientIdRaw);
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
    for (const c of chunks) allChunks.push({ source: file, heading: c.heading || "", text: c.text });
  }

  const clientConfigRaw = readFile(`${base}/client-config.json`) || "{}";
  const clientConfig = safeJsonParse(clientConfigRaw, {});

  return { clientId, brandVoice, supportRules, chunks: allChunks, clientConfig };
}

// ---- Relevance scoring ----
function countHits(textNorm, keyword) {
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
    score += countHits(textNorm, kw) * 2 + (headingNorm ? countHits(headingNorm, kw) * 4 : 0);
  }

  return score * (SOURCE_WEIGHT[chunk.source] || 1);
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

function selectTopChunks(chunks, message, limit = 8, maxTotalChars = 4500) {
  const msgNorm = normalizeText(message);
  const keywords = extractKeywords(message);

  const scored = chunks
    .map((c) => ({ ...c, score: scoreChunk(c, keywords) }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score);

  if (!scored.length && isPolicyLikeQuestion(msgNorm)) {
    return chunks
      .filter((c) => c.source === "Policies.md" || c.source === "Shipping matrix.md")
      .slice(0, limit)
      .map((c) => ({ ...c, score: 1 }));
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

// ---- Widget config endpoint (unchanged) ----
function buildWidgetConfig(clientConfig, clientId) {
  const brandName = clientConfig.brandName || clientId;

  const widgetTitle =
    (clientConfig.widget && clientConfig.widget.title) ||
    clientConfig.widgetTitle ||
    clientConfig.assistantName ||
    brandName;

  const widgetGreeting =
    (clientConfig.widget && clientConfig.widget.greeting) ||
    clientConfig.widgetGreeting ||
    `Hallo! Ik ben de ${brandName} klantenservice assistent. Waar kan ik je mee helpen?`;

  const logoUrl = clientConfig.logoUrl || null;

  const colors = clientConfig.colors
    ? {
        primary: clientConfig.colors.primary || clientConfig.primaryColor || "#000000",
        accent: clientConfig.colors.accent || clientConfig.accentColor || "#2563eb",
        background: clientConfig.colors.background || "#ffffff",
        userBubble:
          clientConfig.colors.userBubble ||
          clientConfig.colors.primary ||
          clientConfig.primaryColor ||
          "#000000",
        botBubble: clientConfig.colors.botBubble || "#ffffff",
      }
    : {
        primary: clientConfig.primaryColor || "#000000",
        accent: clientConfig.accentColor || "#2563eb",
        background: "#ffffff",
        userBubble: clientConfig.primaryColor || "#000000",
        botBubble: "#ffffff",
      };

  return {
    brandName,
    assistantName: clientConfig.assistantName || widgetTitle,
    language: clientConfig.language || "nl",
    noEmojis: clientConfig.noEmojis !== false,
    logoUrl,
    widget: { title: widgetTitle, greeting: widgetGreeting },
    colors,
    support: {
      email: clientConfig.supportEmail || null,
      contactFormUrl: clientConfig.contactFormUrl || null,
    },
    version: clientConfig.version || null,
  };
}

// ---- NEW: Smart follow-up router (slot filling) ----
function isTroubleshootingLike(message) {
  const t = normalizeText(message);
  const keys = ["werkt niet", "doet het niet", "kapot", "probleem", "storing", "error", "fout", "werkt", "broken", "doesnt work", "doesn't work"];
  return keys.some((k) => t.includes(k));
}

function buildFollowUpQuestion(language, intent, slot, brandName) {
  // Keep it short, one question, no emojis.
  const nl = {
    orderNumber: "Wat is je bestelnummer? Bijvoorbeeld #1055.",
    emailOrOrder: "Wat is je bestelnummer? Als je die niet hebt: met welk e-mailadres heb je besteld?",
    productName: "Welk product bedoel je precies?",
    problemDetails: "Wat gaat er precies mis, en wat heb je al geprobeerd?",
  };

  const en = {
    orderNumber: "What is your order number? For example #1055.",
    emailOrOrder: "What is your order number? If you don’t have it: what email address did you order with?",
    productName: "Which product is it exactly?",
    problemDetails: "What exactly is going wrong, and what have you tried already?",
  };

  const dict = (String(language || "nl").toLowerCase().startsWith("en")) ? en : nl;

  // slot -> text
  if (slot && dict[slot]) return dict[slot];

  // fallback per intent
  if (intent === "shipping_or_order") return dict.orderNumber;
  if (intent === "return_or_withdrawal") return dict.emailOrOrder;
  if (intent === "product_usage") return dict.problemDetails;

  // general fallback
  return (String(language || "nl").toLowerCase().startsWith("en"))
    ? `How can I help you with your ${brandName} question?`
    : `Waar kan ik je mee helpen?`;
}

function maybeHandleWithRouter({ sessionId, message, intent, clientConfig, brandName }) {
  const lang = clientConfig.language || "nl";

  const meta = getMeta(sessionId);
  const expected = meta.expectedSlot || "";

  // If we were expecting a specific slot, treat user message as that slot and continue (no immediate follow-up response here).
  // We just clear the slot so the model can move to the next step.
  if (expected) {
    clearExpectedSlot(sessionId);
    return { handled: false };
  }

  // Decide if we need to ask a follow-up BEFORE calling the model
  // 1) Shipping/order: require order number (for best assistance)
  if (intent.mainIntent === "shipping_or_order" && !intent.orderNumber) {
    setMeta(sessionId, { expectedSlot: "orderNumber", lastIntent: intent.mainIntent });
    const q = buildFollowUpQuestion(lang, intent.mainIntent, "orderNumber", brandName);
    return { handled: true, reply: q };
  }

  // 2) Returns: ask order number or email if missing
  if (intent.mainIntent === "return_or_withdrawal" && !intent.orderNumber) {
    setMeta(sessionId, { expectedSlot: "emailOrOrder", lastIntent: intent.mainIntent });
    const q = buildFollowUpQuestion(lang, intent.mainIntent, "emailOrOrder", brandName);
    return { handled: true, reply: q };
  }

  // 3) Troubleshooting-like: ask product name first if user didn't provide detail
  // We keep this conservative: only trigger when user is clearly describing a problem.
  if ((intent.mainIntent === "product_usage" || intent.mainIntent === "general") && isTroubleshootingLike(message)) {
    setMeta(sessionId, { expectedSlot: "productName", lastIntent: "product_troubleshooting" });
    const q = buildFollowUpQuestion(lang, "product_usage", "productName", brandName);
    return { handled: true, reply: q };
  }

  return { handled: false };
}

// ---- Routes ----
app.get("/", (req, res) => {
  res.send("AI support backend running.");
});

app.get("/widget-config", (req, res) => {
  const clientId = sanitizeClientId(req.query.client || "Advantum");
  try {
    const data = loadClient(clientId);
    const widgetConfig = buildWidgetConfig(data.clientConfig || {}, data.clientId);
    res.setHeader("Cache-Control", "public, max-age=300");
    return res.json(widgetConfig);
  } catch (e) {
    console.error("widget-config error:", e.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/chat", async (req, res) => {
  const message = sanitizeUserMessage(req.body.message);
  if (!message) return res.status(400).json({ error: "Invalid message" });

  const clientId = sanitizeClientId(req.query.client || "Advantum");
  const sessionId = sanitizeSessionId(req.body.sessionId);
  const data = loadClient(clientId);

  const intent = detectIntent(message);
  setMeta(sessionId, { lastIntent: intent.mainIntent });

  // ---- NEW: router follow-up (only when key info is missing) ----
  const router = maybeHandleWithRouter({
    sessionId,
    message,
    intent,
    clientConfig: data.clientConfig || {},
    brandName: data.clientConfig.brandName || data.clientId,
  });

  // Always append user message to history
  appendToHistory(sessionId, "user", message);

  if (router.handled) {
    // Router returns a follow-up question WITHOUT calling OpenAI
    appendToHistory(sessionId, "assistant", router.reply);
    return res.json({
      reply: router.reply,
      intent,
      shopify: null,
      routed: true,
    });
  }

  // ---- Shopify lookup ----
  let shopify = null;
  if (intent.mainIntent === "shipping_or_order" && intent.orderNumber) {
    shopify = await lookupShopifyOrder(intent.orderNumber);
  }

  // ---- Context ----
  const topChunks = selectTopChunks(data.chunks, message, 8, 4500);
  const context = topChunks
    .map((c) => `### ${c.source}${c.heading ? " — " + c.heading : ""}\n${c.text}`)
    .join("\n\n");

  const historyMessages = buildHistoryMessages(sessionId);
  const meta = getMeta(sessionId);

  // Extra hint for the model about what’s going on (helps a lot)
  const flowHint = meta.expectedSlot
    ? `EXPECTED_USER_INPUT: The user is answering the bot's question. Slot expected: ${meta.expectedSlot}.`
    : "EXPECTED_USER_INPUT: none";

  const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName || data.clientId}.
Use the same language as the user. No emojis.
Never guess policies, prices, or shipping rules.
Only answer using the provided context.

Conversation handling rules:
- Use the chat history to understand what the user is answering.
- If the user is answering a clarification question (e.g., product name, order number), treat it as an answer and continue.
- Ask only 1 short follow-up question at a time when needed.
- Do NOT respond with a full product description unless the user explicitly asks for product info.

${flowHint}

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
        ...historyMessages,
        { role: "user", content: message },
      ],
    });

    const reply = response.choices[0].message.content;

    appendToHistory(sessionId, "assistant", reply);

    return res.json({
      reply,
      intent,
      shopify,
      routed: false,
    });
  } catch (e) {
    console.error("Chat error:", e.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
