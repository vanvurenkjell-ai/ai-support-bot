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

// ---- Load client files ----
function loadClient(clientId) {
  const basePath = `./Clients/${clientId}`;

  const faq = fs.readFileSync(`${basePath}/FAQ.md`, "utf8");
  const policies = fs.readFileSync(`${basePath}/Policies.md`, "utf8");
  const products = fs.readFileSync(`${basePath}/Product Samples.md`, "utf8");
  const brandVoice = fs.readFileSync(`${basePath}/Brand voice.md`, "utf8");
  const clientConfig = JSON.parse(
    fs.readFileSync(`${basePath}/client-config.json`, "utf8")
  );

  return { faq, policies, products, brandVoice, clientConfig };
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

  // VERY SIMPLE: find a chunk containing digits (we'll improve later)
  const orderMatch = userMessage.match(/[A-Z0-9][A-Z0-9\- ]{2,}[0-9]/i);
  const orderNumber = orderMatch ? orderMatch[0].trim() : "";

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
async function lookupShopifyOrder(orderNumber) {
  if (!SHOPIFY_STORE_DOMAIN || !SHOPIFY_API_TOKEN) {
    console.warn("Shopify env vars missing, skipping lookup.");
    return null;
  }
  if (!orderNumber) return null;

  try {
    const url = `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/orders.json`;
    const res = await axios.get(url, {
      headers: {
        "X-Shopify-Access-Token": SHOPIFY_API_TOKEN,
      },
      params: {
        name: orderNumber, // search by order "name" like #1001 / 1001
        status: "any",
      },
    });

    const orders = res.data && res.data.orders ? res.data.orders : [];
    if (!orders.length) return null;

    const order = orders[0];

    const fulfillment = order.fulfillments && order.fulfillments[0]
      ? order.fulfillments[0]
      : null;

    const tracking = fulfillment && fulfillment.tracking_numbers && fulfillment.tracking_numbers[0]
      ? fulfillment.tracking_numbers[0]
      : null;

    const trackingUrl = fulfillment && fulfillment.tracking_urls && fulfillment.tracking_urls[0]
      ? fulfillment.tracking_urls[0]
      : null;

    return {
      orderName: order.name || null,
      orderNumber: orderNumber,
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
  const message = req.body.message || "";
  const clientId = req.query.client || "Advantum";

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






