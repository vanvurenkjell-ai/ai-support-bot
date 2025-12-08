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

// ---- OpenAI setup ----
if (!process.env.OPENAI_API_KEY) {
  console.error("Missing OPENAI_API_KEY");
  process.exit(1);
}

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ---- Shopify env vars ----
const SHOPIFY_STORE_DOMAIN = process.env.SHOPIFY_STORE_DOMAIN;
const SHOPIFY_API_TOKEN = process.env.SHOPIFY_API_TOKEN;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-01";

// preconfigured axios client for Shopify (with timeout)
let shopifyClient = null;
if (SHOPIFY_STORE_DOMAIN && SHOPIFY_API_TOKEN) {
  shopifyClient = axios.create({
    baseURL: `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}`,
    timeout: 5000,
    headers: {
      "X-Shopify-Access-Token": SHOPIFY_API_TOKEN,
    },
  });
} else {
  console.warn(
    "Shopify env vars missing; order lookup will be disabled until they are set."
  );
}

// ---- Simple sanitizers / limits ----
const MAX_USER_MESSAGE_LENGTH = 1000; // chars

// Strip dangerous HTML, scripts, styles
function stripHtml(input) {
  if (!input) return "";

  let text = String(input);

  // Remove <script>...</script> blocks
  text = text.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");

  // Remove <style>...</style> blocks
  text = text.replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, "");

  // Remove any remaining HTML tags
  text = text.replace(/<\/?[^>]+(>|$)/g, "");

  return text;
}

function sanitizeUserMessage(input) {
  let text = "";
  try {
    text = String(input || "");
  } catch {
    text = "";
  }

  // remove HTML, script, and style tags
  text = stripHtml(text);

  // strip control chars
  text = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");

  // collapse multiple spaces/newlines
  text = text.replace(/\s+/g, " ").trim();

  // enforce max length
  if (text.length > MAX_USER_MESSAGE_LENGTH) {
    text = text.slice(0, MAX_USER_MESSAGE_LENGTH);
  }

  return text;
}

function sanitizeClientId(id) {
  const fallback = "Advantum";
  if (!id) return fallback;

  const cleaned = String(id).trim();

  // allow only letters, numbers, _ and -
  if (!/^[A-Za-z0-9_-]+$/.test(cleaned)) {
    return fallback;
  }
  return cleaned;
}

function sanitizeOrderNumber(orderNumber) {
  if (!orderNumber) return "";
  let text = String(orderNumber);

  // keep only digits, letters, #, -, space
  text = text.replace(/[^A-Za-z0-9#\- ]/g, "").trim();

  // short sanity limit
  if (text.length > 40) {
    text = text.slice(0, 40);
  }

  return text;
}

// ---- Load client files (safe) ----
function loadClient(clientId) {
  const safeClientId = sanitizeClientId(clientId);
  const basePath = `./Clients/${safeClientId}`;

  if (!fs.existsSync(basePath)) {
    throw new Error(`Client folder not found for id: ${safeClientId}`);
  }

  try {
    const faq = fs.readFileSync(`${basePath}/FAQ.md`, "utf8");
    const policies = fs.readFileSync(`${basePath}/Policies.md`, "utf8");
    const products = fs.readFileSync(
      `${basePath}/Product Samples.md`,
      "utf8"
    );
    const brandVoice = fs.readFileSync(
      `${basePath}/Brand voice.md`,
      "utf8"
    );
    const clientConfig = JSON.parse(
      fs.readFileSync(`${basePath}/client-config.json`, "utf8")
    );

    return { faq, policies, products, brandVoice, clientConfig };
  } catch (err) {
    console.error(`Error loading client data for ${safeClientId}:`, err.message);
    throw new Error("Failed to load client data");
  }
}

// ---- Simple intent + order detection ----
function detectIntent(userMessage) {
  const text = (userMessage || "").toLowerCase();

  const shippingKeywords = [
    "verzending",
    "bezorging",
    "bezorgd",
    "pakket",
    "track",
    "trace",
    "where is my order",
    "waar is mijn bestelling",
    "zending",
    "levering",
    "shipment",
    "delivery",
    "shipping",
  ];

  const returnKeywords = [
    "retour",
    "retourneren",
    "terugsturen",
    "omruilen",
    "herroepingsrecht",
    "bedenktijd",
    "refund",
    "geld terug",
    "money back",
  ];

  const useKeywords = [
    "hoe gebruik ik",
    "hoe moet ik",
    "hoe doe ik",
    "how do i use",
    "how to use",
    "gebruiken",
    "uitleg",
    "tutorial",
  ];

  const hasShipping = shippingKeywords.some((k) => text.includes(k));
  const hasReturn = returnKeywords.some((k) => text.includes(k));
  const hasUse = useKeywords.some((k) => text.includes(k));

  // Extract an order-like number:
  // last number sequence (with optional spaces/dashes)
  let orderNumber = "";
  const numberMatches = (userMessage || "").match(/(\d[\d\- ]*\d)/g);
  if (numberMatches && numberMatches.length > 0) {
    orderNumber = numberMatches[numberMatches.length - 1].trim();
  }
  orderNumber = sanitizeOrderNumber(orderNumber);

  let mainIntent = "general";
  if (hasShipping || orderNumber) mainIntent = "shipping_or_order";
  if (hasReturn) mainIntent = "return_or_withdrawal";
  if (hasUse && !hasShipping && !hasReturn) mainIntent = "product_usage";

  return {
    mainIntent,
    hasShipping,
    hasReturn,
    hasUse,
    orderNumber,
  };
}

// ---- Shopify order lookup ----
async function lookupShopifyOrder(orderNumberRaw) {
  if (!shopifyClient) {
    console.warn("Shopify client not configured, skipping lookup.");
    return null;
  }

  const orderNumber = sanitizeOrderNumber(orderNumberRaw);
  if (!orderNumber) return null;

  // Shopify "name" is usually like "#1055"
  const nameParam = orderNumber.startsWith("#")
    ? orderNumber
    : `#${orderNumber}`;

  try {
    const res = await shopifyClient.get("/orders.json", {
      params: {
        name: nameParam,
        status: "any",
      },
    });

    const orders = res.data && res.data.orders ? res.data.orders : [];
    if (!orders.length) return null;

    const order = orders[0];

    const fulfillment =
      order.fulfillments && order.fulfillments[0]
        ? order.fulfillments[0]
        : null;

    const tracking =
      fulfillment &&
      fulfillment.tracking_numbers &&
      fulfillment.tracking_numbers[0]
        ? fulfillment.tracking_numbers[0]
        : null;

    const trackingUrl =
      fulfillment &&
      fulfillment.tracking_urls &&
      fulfillment.tracking_urls[0]
        ? fulfillment.tracking_urls[0]
        : null;

    return {
      orderName: order.name || null,
      orderNumber,
      fulfillmentStatus: order.fulfillment_status || "unfulfilled",
      financialStatus: order.financial_status || null,
      tracking,
      trackingUrl,
      createdAt: order.created_at || null,
    };
  } catch (err) {
    console.error("Shopify lookup error:", err.message);
    return null;
  }
}

// ---- Routes ----
app.get("/", (req, res) => {
  res.send("AI support backend running.");
});

app.post("/chat", async (req, res) => {
  const rawMessage = req.body.message;
  const message = sanitizeUserMessage(rawMessage);

  if (!message) {
    return res.status(400).json({ error: "Empty or invalid message." });
  }

  const clientId = sanitizeClientId(req.query.client || "Advantum");

  try {
    const data = loadClient(clientId);
    const intent = detectIntent(message);

    let shopifyData = null;
    if (intent.mainIntent === "shipping_or_order" && intent.orderNumber) {
      shopifyData = await lookupShopifyOrder(intent.orderNumber);
    }

    const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName}.
Use the same language as the user. No emojis.
Be honest and clear. If something is not in the context, say you are not sure.

INTENT_HINT:
- mainIntent: ${intent.mainIntent}
- hasShipping: ${intent.hasShipping}
- hasReturn: ${intent.hasReturn}
- hasUse: ${intent.hasUse}
- orderNumber: ${intent.orderNumber || "none"}

ORDER_LOOKUP_DATA (from Shopify, if available):
${shopifyData ? JSON.stringify(shopifyData, null, 2) : "none"}

CLIENT VOICE:
${data.brandVoice}

FAQ:
${data.faq}

POLICIES:
${data.policies}

PRODUCTS:
${data.products}
`;

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
      shopify: shopifyData,
    });
  } catch (err) {
    console.error("Chat error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});






