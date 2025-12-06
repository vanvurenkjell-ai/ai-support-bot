const express = require("express");
const cors = require("cors");
const fs = require("fs");
require("dotenv").config();
const OpenAI = require("openai");

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

// ---- Load client files ----
function loadClient(clientId) {
  // Clients folder is in the SAME directory as index.js
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

  // Try to find something that looks like an order number:
  //  - 3+ digits, optionally mixed with letters, spaces, or dashes
  const orderMatch = userMessage.match(/[A-Z0-9][A-Z0-9\- ]{2,}[A-Z0-9]/i);
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
    });
  } catch (err) {
    console.error("Chat error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});





