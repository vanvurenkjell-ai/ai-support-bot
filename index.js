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
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// ---- Shopify env vars ----
const SHOPIFY_STORE_DOMAIN = process.env.SHOPIFY_STORE_DOMAIN;
const SHOPIFY_API_TOKEN = process.env.SHOPIFY_API_TOKEN;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-01";

let shopifyClient = null;
if (SHOPIFY_STORE_DOMAIN && SHOPIFY_API_TOKEN) {
  shopifyClient = axios.create({
    baseURL: `https://${SHOPIFY_STORE_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}`,
    timeout: 5000,
    headers: {
      "X-Shopify-Access-Token": SHOPIFY_API_TOKEN,
    },
  });
}

// ---- Helpers ----
const MAX_USER_MESSAGE_LENGTH = 1000;

function sanitizeUserMessage(input) {
  let text = String(input || "");
  text = text.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  text = text.replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, "");
  text = text.replace(/<\/?[^>]+(>|$)/g, "");
  text = text.replace(/\s+/g, " ").trim();
  if (text.length > MAX_USER_MESSAGE_LENGTH) {
    text = text.slice(0, MAX_USER_MESSAGE_LENGTH);
  }
  return text;
}

function readFileIfExists(path) {
  if (fs.existsSync(path)) {
    return fs.readFileSync(path, "utf8");
  }
  return "";
}

// ---- Load client knowledge ----
function loadClient(clientId) {
  const basePath = `./Clients/${clientId}`;

  const files = {
    brandVoice: "Brand voice.md",
    faq: "FAQ.md",
    policies: "Policies.md",
    products: "Products.md",
    supportRules: "Customer support rules.md",
    extras: [
      "Company overview.md",
      "Legal.md",
      "Product tutorials.md",
      "Promotions & discounts.md",
      "Shipping matrix.md",
      "Troubleshooting.md",
    ],
  };

  const knowledgeChunks = [];

  function chunkText(source, text) {
    const parts = text.split(/\n{2,}/);
    for (const part of parts) {
      if (part.trim().length > 50) {
        knowledgeChunks.push({
          source,
          text: part.trim(),
        });
      }
    }
  }

  const brandVoice = readFileIfExists(`${basePath}/${files.brandVoice}`);
  const supportRules = readFileIfExists(`${basePath}/${files.supportRules}`);

  chunkText("FAQ", readFileIfExists(`${basePath}/${files.faq}`));
  chunkText("Policies", readFileIfExists(`${basePath}/${files.policies}`));
  chunkText("Products", readFileIfExists(`${basePath}/${files.products}`));

  for (const file of files.extras) {
    chunkText(file, readFileIfExists(`${basePath}/${file}`));
  }

  const clientConfig = JSON.parse(
    readFileIfExists(`${basePath}/client-config.json`) || "{}"
  );

  return {
    brandVoice,
    supportRules,
    knowledgeChunks,
    clientConfig,
  };
}

// ---- Relevance scoring ----
function scoreChunk(chunkText, query) {
  const words = query.toLowerCase().split(" ");
  let score = 0;
  for (const word of words) {
    if (word.length > 3 && chunkText.toLowerCase().includes(word)) {
      score++;
    }
  }
  return score;
}

function selectTopChunks(chunks, query, limit = 5) {
  return chunks
    .map(c => ({ ...c, score: scoreChunk(c.text, query) }))
    .filter(c => c.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}

// ---- Routes ----
app.post("/chat", async (req, res) => {
  const message = sanitizeUserMessage(req.body.message);
  if (!message) {
    return res.status(400).json({ error: "Invalid message" });
  }

  const clientId = req.query.client || "Advantum";
  const data = loadClient(clientId);

  const topChunks = selectTopChunks(data.knowledgeChunks, message);

  const context = topChunks
    .map(c => `### ${c.source}\n${c.text}`)
    .join("\n\n");

  const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName || clientId}.
Use the same language as the user. No emojis.
Never guess policies, prices, or shipping rules.
If the answer is not in the context, say you are not sure.

BRAND VOICE:
${data.brandVoice || ""}

CUSTOMER SUPPORT RULES:
${data.supportRules || ""}

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
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});







