const express = require("express");
const cors = require("cors");
const fs = require("fs");
require("dotenv").config();
const OpenAI = require("openai");

const app = express();
// use host-provided PORT in production, 3001 locally
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// ---- OpenAI client ----
if (!process.env.OPENAI_API_KEY) {
  console.error("Missing OPENAI_API_KEY in .env file");
  console.error("Set OPENAI_API_KEY in your .env file.");
  process.exit(1);
}

const openaiClient = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

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
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// ---------- LOAD CLIENT DATA (FILES + EMBEDDINGS) ----------

async function loadClientData(clientId) {
  if (clients[clientId] && clients[clientId].knowledgeEmbeddings) {
    return clients[clientId];
  }

  // IMPORTANT: index.js and Clients folder are in same directory
  const basePath = `./Clients/${clientId}`;

  try {
    const faq = fs.readFileSync(`${basePath}/FAQ.md`, "utf8");
    const policies = fs.readFileSync(`${basePath}/Policies.md`, "utf8");
    const products = fs.readFileSync(`${basePath}/Product Samples.md`, "utf8");
    const brandVoice = fs.readFileSync(`${basePath}/Brand voice.md`, "utf8");
    const clientConfig = JSON.parse(
      fs.readFileSync(`${basePath}/client-config.json`, "utf8")
    );

    let orders = [];
    try {
      const ordersRaw = fs.readFileSync(`${basePath}/orders.json`, "utf8");
      orders = JSON.parse(ordersRaw);
      console.log(
        `[${clientId}] Loaded orders.json with`,
        orders.length,
        "orders."
      );
    } catch (err) {
      console.warn(
        `[${clientId}] No orders.json found or invalid JSON. Offline order lookup disabled.`,
        err.message
      );
    }

    console.log(`Loaded client data for ${clientId}`);
    console.log(`[${clientId}] FAQ length:`, faq.length);
    console.log(`[${clientId}] Policies length:`, policies.length);
    console.log(`[${clientId}] Products length:`, products.length);
    console.log(`[${clientId}] Brand voice length:`, brandVoice.length);

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
      console.log(`[${clientId}] Creating embeddings for knowledge base… (once)`);

      const embedResponse = await openaiClient.embeddings.create({
        model: "text-embedding-3-small",
        input: knowledgeChunks,
      });

      knowledgeEmbeddings = embedResponse.data.map((item, idx) => ({
        text: knowledgeChunks[idx],
        embedding: item.embedding,
      }));

      console.log(
        `[${clientId}] Embeddings ready. Chunks:`,
        knowledgeEmbeddings.length
      );
    } catch (embedErr) {
      console.error(
        `[${clientId}] Error creating embeddings. Semantic search disabled:`,
        embedErr.message
      );
    }

    clients[clientId] = {
      faq,
      policies,
      products,
      brandVoice,
      clientConfig,
      orders,
      knowledgeChunks,
      knowledgeEmbeddings,
    };

    return clients[clientId];
  } catch (err) {
    console.error(`Error loading client data for ${clientId}:`, err.message);
    throw new Error(`Could not load client data for ${clientId}`);
  }
}

// ---------- CONTEXT LOOKUP PER CLIENT ----------

async function getRelevantContext(question, topK, clientId) {
  const clientData = await loadClientData(clientId);

  if (
    !clientData.knowledgeEmbeddings ||
    clientData.knowledgeEmbeddings.length === 0
  ) {
    console.warn(
      `[${clientId}] No embeddings available → returning empty context.`
    );
    return "";
  }

  const questionEmbed = await openaiClient.embeddings.create({
    model: "text-embedding-3-small",
    input: [question],
  });

  const qEmbedding = questionEmbed.data[0].embedding;

  const scored = clientData.knowledgeEmbeddings.map((chunk) => ({
    text: chunk.text,
    score: cosineSimilarity(qEmbedding, chunk.embedding),
  }));

  scored.sort((a, b) => b.score - a.score);

  return scored
    .slice(0, topK)
    .map((c) => c.text)
    .join("\n\n---\n\n");
}

// ---------- CONVERSATION MEMORY ----------
const sessions = {};
const MAX_HISTORY_MESSAGES = 10;

// ---------- INTENT DETECTION ----------
function detectIntent(userMessage) {
  const text = userMessage.toLowerCase();

  const shippingKeywords = [
    "verzending",
    "bezorging",
    "bezorgd",
    "pakket",
    "track",
    "trace",
    "track & trace",
    "track and trace",
    "where is my order",
    "waar is mijn bestelling",
    "zending",
    "levering",
    "shipment",
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
  ];

  const orderKeywords = [
    "bestelling",
    "order",
    "ordernummer",
    "order number",
    "order #",
    "#",
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
  const hasOrder = orderKeywords.some((k) => text.includes(k));
  const hasUse = useKeywords.some((k) => text.includes(k));

  const trackingMatch = text.match(/\b([A-Z0-9]{8,})\b/);

  const hashOrderMatch = text.match(/#\s*(\d{3,})/);
  const plainOrderMatch = text.match(/\b(\d{3,})\b/);

  let orderNumber = null;
  if (hashOrderMatch) orderNumber = hashOrderMatch[1];
  else if (plainOrderMatch) orderNumber = plainOrderMatch[1];

  const trackingCode = trackingMatch ? trackingMatch[1] : null;

  let mainIntent = "general";

  if (hasShipping || hasOrder || trackingCode || orderNumber) {
    mainIntent = "shipping_or_order";
  }
  if (hasReturn) {
    mainIntent = "return_or_withdrawal";
  }
  if (hasUse && !hasShipping && !hasReturn && !hasOrder) {
    mainIntent = "product_usage";
  }

  return {
    mainIntent,
    hasShipping,
    hasReturn,
    hasOrder,
    hasUse,
    trackingCode: trackingCode || "",
    orderNumber: orderNumber || "",
  };
}

// ---------- ORDER LOOKUP ----------
function findOrder(orderNumber, clientData) {
  if (!orderNumber) return null;
  if (!clientData.orders || !Array.isArray(clientData.orders)) return null;

  const cleaned = String(orderNumber).trim();
  const result = clientData.orders.find(
    (o) => String(o.orderNumber).trim() === cleaned
  );

  return result || null;
}

// ---------- ANALYTICS LOGGING (JSON PER CLIENT) ----------

function logAnalytics(clientId, entry) {
  // same base folder logic as loadClientData
  const basePath = `./Clients/${clientId}`;
  const filePath = `${basePath}/analytics.json`;

  try {
    let current = [];

    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf8").trim();
      if (raw) {
        try {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) {
            current = parsed;
          }
        } catch (parseErr) {
          console.warn(
            `[${clientId}] analytics.json invalid JSON, resetting file:`,
            parseErr.message
          );
        }
      }
    }

    current.push(entry);

    fs.writeFileSync(filePath, JSON.stringify(current, null, 2), "utf8");
  } catch (err) {
    console.error(`[${clientId}] Failed to write analytics:`, err.message);
  }
}

// ---------- ROUTES ----------

app.get("/", (req, res) => {
  res.send(
    "Support backend is running. Use /chat with ?client=Advantum (or another clientId)."
  );
});

app.get("/widget-config", async (req, res) => {
  const clientId = req.query.client || "Advantum";

  try {
    const clientData = await loadClientData(clientId);
    const cfg = clientData.clientConfig || {};

    return res.json({
      brandName: cfg.brandName || clientId,
      widgetTitle: cfg.widgetTitle || `${clientId} Support`,
      widgetGreeting:
        cfg.widgetGreeting ||
        "Hi, I'm your support assistant. How can I help you?",
      primaryColor: cfg.primaryColor || "#2563eb",
      accentColor: cfg.accentColor || "#16a34a",
    });
  } catch (err) {
    console.error("Error in /widget-config:", err.message);
    return res.status(500).json({
      error: "Could not load widget config for this client.",
    });
  }
});

app.post("/chat", async (req, res) => {
  const userMessage = req.body.message;
  const sessionId = req.body.sessionId || "default";
  const clientId = req.query.client || "Advantum";

  if (!userMessage) {
    return res
      .status(400)
      .json({ error: "No 'message' field in request body." });
  }

  const startTime = Date.now();

  try {
    const clientData = await loadClientData(clientId);

    let context = "";
    try {
      context = await getRelevantContext(userMessage, 5, clientId);
    } catch (ctxErr) {
      console.error(
        `[${clientId}] Error building context — continuing without context:`,
        ctxErr.message
      );
      context = "";
    }

    const intent = detectIntent(userMessage);
    const matchedOrder = findOrder(intent.orderNumber, clientData);

    const historyKey = `${clientId}:${sessionId}`;
    const history = sessions[historyKey] || [];

    const messages = [
      {
        role: "system",
        content: `
You are the AI customer support assistant for ${
          clientData.clientConfig.brandName
        }, a premium professional fitness and bodybuilding brand.

LANGUAGE RULES
- ALWAYS respond in the SAME language the customer uses in their most recent message.
- If the user mixes languages, follow the dominant one.
- No emojis.

INTRODUCTION RULES
- Only introduce yourself if the user clearly doesn't know who/what you are.
- Otherwise, answer directly.

GENERAL BEHAVIOUR
- For ORDER/SHIPPING: short, clear answers (2–4 sentences).
- For PRODUCT/TRAINING: more detailed, coaching-style answers.
- Assume the customer is serious about training.

FACT-CHECKING & HALLUCINATION RULES (VERY IMPORTANT)
- NEVER invent information.
- ONLY use facts from:
  1) The client’s files (FAQ, Policies, Products, Brand Voice)
  2) The conversation history
- If something is NOT in the context:
  - Say you cannot confirm it with certainty.
  - Offer general guidance if safe.
  - Suggest contacting support if needed.
- Never guess product features, policies, delivery times, or guarantees.
- Never give medical/injury advice — say you cannot provide medical guidance.
- When unsure: ALWAYS choose safety over guessing.

SCOPE & SAFETY
- If an answer is outside context → admit uncertainty.
- Never invent order statuses or tracking updates.
- Never claim real-time system access.

ORDER & SHIPPING HANDLING
- If mainIntent is "shipping_or_order":
  - Explain expected shipping rules from context.
  - If no order/tracking: ask for order number.
  - If order found in ORDER_LOOKUP_DATA: use it.
  - If not found: tell user the system could not locate it.

INTENT_HINT:
- mainIntent: ${intent.mainIntent}
- hasShipping: ${intent.hasShipping}
- hasReturn: ${intent.hasReturn}
- hasOrder: ${intent.hasOrder}
- hasUse: ${intent.hasUse}
- trackingCode: ${intent.trackingCode || "none"}
- orderNumber: ${intent.orderNumber || "none"}

ORDER_LOOKUP_DATA:
${matchedOrder ? JSON.stringify(matchedOrder, null, 2) : "none"}

RELEVANT CONTEXT:
${context}

BRAND VOICE:
${clientData.brandVoice}
        `,
      },
      ...history,
      {
        role: "user",
        content: userMessage,
      },
    ];

    const response = await openaiClient.chat.completions.create({
      model: "gpt-4.1-mini",
      messages,
    });

    const answer = response.choices[0].message.content;

    const newHistory = [
      ...history,
      { role: "user", content: userMessage },
      { role: "assistant", content: answer },
    ];

    sessions[historyKey] = newHistory.slice(-MAX_HISTORY_MESSAGES);

    // ---------- ANALYTICS ENTRY (SUCCESS) ----------
    const durationMs = Date.now() - startTime;

    const analyticsEntry = {
      timestamp: new Date().toISOString(),
      message: userMessage,
      intent: intent.mainIntent,
      orderNumber: intent.orderNumber || "",
      trackingCode: intent.trackingCode || "",
      responseLength: typeof answer === "string" ? answer.length : 0,
      durationMs,
      error: false,
    };

    logAnalytics(clientId, analyticsEntry);

    return res.json({ reply: answer });
  } catch (err) {
    console.error("Error in /chat:", err);

    // ---------- ANALYTICS ENTRY (ERROR) ----------
    const durationMs = Date.now() - startTime;

    try {
      const clientId = req.query.client || "Advantum";

      const analyticsEntry = {
        timestamp: new Date().toISOString(),
        message: userMessage,
        intent: "error",
        orderNumber: "",
        trackingCode: "",
        responseLength: 0,
        durationMs,
        error: true,
      };

      logAnalytics(clientId, analyticsEntry);
    } catch (logErr) {
      console.error("Failed to log analytics for error:", logErr.message);
    }

    return res.status(500).json({
      error: "Something went wrong talking to the AI or loading client data.",
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});





