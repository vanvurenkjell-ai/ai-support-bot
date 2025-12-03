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

// ---- OpenAI client ----
if (!process.env.OPENAI_API_KEY) {
  console.error("Missing OPENAI_API_KEY in .env file");
  process.exit(1);
}

const openaiClient = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ---- Shopify credentials ----
const SHOPIFY_STORE_DOMAIN = process.env.SHOPIFY_STORE_DOMAIN;
const SHOPIFY_API_TOKEN = process.env.SHOPIFY_API_TOKEN;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-01";

// ---------- PER-CLIENT DATA CACHE ----------
const clients = {};

// ---------- UTIL: CHUNKING & COSINE SIM ----------
function chunkText(text, maxChars = 800, overlap = 100) {
  const paragraphs = text.split(/\n\s*\n/);
  const chunks = [];
  let current = "";

  for (const para of paragraphs) {
    const p = para.trim();
    if (!p) continue;

    if ((current + "\n\n" + p).length <= maxChars) {
      current = current ? current + "\n\n" + p : p;
    } else {
      if (current) {
        chunks.push(current);
      }
      if (p.length > maxChars) {
        let start = 0;
        while (start < p.length) {
          chunks.push(p.slice(start, start + maxChars));
          start += maxChars - overlap;
        }
        current = "";
      } else {
        current = p;
      }
    }
  }

  if (current) chunks.push(current);
  return chunks;
}

function cosineSimilarity(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// ---------- LOAD CLIENT DATA ----------
async function loadClientData(clientId) {
  if (clients[clientId] && clients[clientId].knowledgeEmbeddings) {
    return clients[clientId];
  }

  const basePath = `../Clients/${clientId}`;

  try {
    const faq = fs.readFileSync(`${basePath}/FAQ.md`, "utf8");
    const policies = fs.readFileSync(`${basePath}/Policies.md`, "utf8");
    const products = fs.readFileSync(`${basePath}/Product Samples.md`, "utf8");
    const brandVoice = fs.readFileSync(`${basePath}/Brand voice.md`, "utf8");
    const clientConfig = JSON.parse(
      fs.readFileSync(`${basePath}/client-config.json`, "utf8")
    );

    const knowledgeText = [
      "# FAQ",
      faq,
      "",
      "# Policies",
      policies,
      "",
      "# Products",
      products,
    ].join("\n\n");

    const knowledgeChunks = chunkText(knowledgeText);

    let knowledgeEmbeddings = [];
    try {
      const embedResponse = await openaiClient.embeddings.create({
        model: "text-embedding-3-small",
        input: knowledgeChunks,
      });

      knowledgeEmbeddings = embedResponse.data.map((item, idx) => ({
        text: knowledgeChunks[idx],
        embedding: item.embedding,
      }));
    } catch (err) {
      console.error(`[${clientId}] Embedding error:`, err.message);
    }

    clients[clientId] = {
      faq,
      policies,
      products,
      brandVoice,
      clientConfig,
      knowledgeChunks,
      knowledgeEmbeddings,
    };

    return clients[clientId];
  } catch (err) {
    console.error(`Error loading client data:`, err.message);
    throw new Error(`Could not load client data for ${clientId}`);
  }
}

// ---------- SHOPIFY ORDER LOOKUP ----------
async function lookupShopifyOrder(orderNumber) {
  try {
    const url = `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/orders.json?name=${orderNumber}`;

    const res = await axios.get(url, {
      headers: {
        "X-Shopify-Access-Token": SHOPIFY_API_TOKEN,
      },
    });

    if (!res.data.orders || res.data.orders.length === 0) return null;

    const order = res.data.orders[0];

    const fulfillment = order.fulfillments?.[0] || {};
    const tracking = fulfillment.tracking_numbers?.[0] || null;
    const trackingUrl = fulfillment.tracking_urls?.[0] || null;

    return {
      orderNumber,
      fulfillmentStatus: order.fulfillment_status || "not fulfilled",
      tracking,
      trackingUrl,
    };
  } catch (err) {
    console.error("Shopify lookup failed:", err.message);
    return null;
  }
}

// ---------- ROUTES ----------

app.get("/", (req, res) => {
  res.send("Support backend is running.");
});

app.post("/chat", async (req, res) => {
  const message = req.body.message;
  const clientId = req.query.client || "Advantum";

  if (!message) {
    return res.status(400).json({ error: "No message provided." });
  }

  try {
    const clientData = await loadClientData(clientId);

    // Detect order number (simple numeric)
    const match = message.match(/\d{4,}/);
    const orderNumber = match ? match[0] : null;

    let shopifyData = null;
    if (orderNumber) {
      shopifyData = await lookupShopifyOrder(orderNumber);
    }

    const systemPrompt = `
You are the AI support assistant for ${clientData.clientConfig.brandName}.

Use the same language as customer.
No emojis.

If an order number is detected, use this Shopify data:

${shopifyData ? JSON.stringify(shopifyData, null, 2) : "None"}
`;

    const response = await openaiClient.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message },
      ],
    });

    return res.json({
      reply: response.choices[0].message.content,
      shopify: shopifyData,
    });
  } catch (err) {
    console.error("Chat error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});





