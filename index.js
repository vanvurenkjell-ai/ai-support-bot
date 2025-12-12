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

// ---- Intent detection ----
function detectIntent(message) {
  const text = message.toLowerCase();

  const shipping = ["verzending", "bezorg", "track", "order", "shipping"];
  const returns = ["retour", "refund", "terug"];
  const usage = ["gebruik", "how", "hoe"];

  let orderNumber = "";
  const matches = message.match(/(\d[\d\- ]*\d)/g);
  if (matches) {
    orderNumber = sanitizeOrderNumber(matches[matches.length - 1]);
  }

  let mainIntent = "general";
  if (shipping.some(w => text.includes(w)) || orderNumber) {
    mainIntent = "shipping_or_order";
  }
  if (returns.some(w => text.includes(w))) {
    mainIntent = "return_or_withdrawal";
  }
  if (usage.some(w => text.includes(w))) {
    mainIntent = "product_usage";
  }

  return { mainIntent, orderNumber };
}

// ---- Shopify lookup ----
async function lookupShopifyOrder(orderNumberRaw) {
  if (!shopifyClient) return null;

  const orderNumber = sanitizeOrderNumber(orderNumberRaw);
  if (!orderNumber) return null;

  const nameParam = orderNumber.startsWith("#")
    ? orderNumber
    : `#${orderNumber}`;

  try {
    const res = await shopifyClient.get("/orders.json", {
      params: { name: nameParam, status: "any" },
    });

    const orders = res.data.orders || [];
    if (!orders.length) return null;

    const order = orders[0];
    const fulfillment = order.fulfillments?.[0] || null;

    return {
      orderName: order.name,
      fulfillmentStatus: order.fulfillment_status,
      financialStatus: order.financial_status,
      tracking: fulfillment?.tracking_numbers?.[0] || null,
      trackingUrl: fulfillment?.tracking_urls?.[0] || null,
    };
  } catch {
    return null;
  }
}

// ---- Knowledge loading ----
function readFile(path) {
  return fs.existsSync(path) ? fs.readFileSync(path, "utf8") : "";
}

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

  const chunks = [];
  for (const file of files) {
    const content = readFile(`${base}/${file}`);
    content.split(/\n{2,}/).forEach(part => {
      if (part.trim().length > 50) {
        chunks.push({ source: file, text: part.trim() });
      }
    });
  }

  const clientConfig = JSON.parse(
    readFile(`${base}/client-config.json`) || "{}"
  );

  return { brandVoice, supportRules, chunks, clientConfig };
}

// ---- Relevance ----
function scoreChunk(text, query) {
  let score = 0;
  query.split(" ").forEach(w => {
    if (w.length > 3 && text.toLowerCase().includes(w.toLowerCase())) {
      score++;
    }
  });
  return score;
}

function selectTopChunks(chunks, query, limit = 5) {
  return chunks
    .map(c => ({ ...c, score: scoreChunk(c.text, query) }))
    .filter(c => c.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
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

  const topChunks = selectTopChunks(data.chunks, message);

  const context = topChunks
    .map(c => `### ${c.source}\n${c.text}`)
    .join("\n\n");

  const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName || clientId}.
Use the same language as the user. No emojis.
Never guess policies or prices.

BRAND VOICE:
${data.brandVoice}

SUPPORT RULES:
${data.supportRules}

SHOPIFY ORDER DATA:
${shopify ? JSON.stringify(shopify, null, 2) : "none"}

RELEVANT KNOWLEDGE:
${context}
`;

  const response = await openai.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: message },
    ],
  });

  res.json({
    reply: response.choices[0].message.content,
    intent,
    shopify,
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});








