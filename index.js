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
  apiKey: process.env.OPENAI_API_KEY
});

// ---- Load client files ----
function loadClient(clientId) {
  const basePath = `../Clients/${clientId}`;

  const faq = fs.readFileSync(`${basePath}/FAQ.md`, "utf8");
  const policies = fs.readFileSync(`${basePath}/Policies.md`, "utf8");
  const products = fs.readFileSync(`${basePath}/Product Samples.md`, "utf8`);
  const brandVoice = fs.readFileSync(`${basePath}/Brand voice.md`, "utf8`);
  const clientConfig = JSON.parse(
    fs.readFileSync(`${basePath}/client-config.json`, "utf8")
  );

  return { faq, policies, products, brandVoice, clientConfig };
}

// ---- Routes ----
app.get("/", (req, res) => {
  res.send("AI support backend running.");
});

app.post("/chat", async (req, res) => {
  const message = req.body.message || "";
  const clientId = req.query.client || "Advantum";

  try {
    // Load data
    const data = loadClient(clientId);

    const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName}.
Use the same language as the user.
No emojis.
Keep answers correct and polite.

Client voice:
${data.brandVoice}

FAQ:
${data.faq}

Policies:
${data.policies}

Products:
${data.products}
`;

    const response = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: message }
      ]
    });

    return res.json({
      reply: response.choices[0].message.content
    });

  } catch (err) {
    console.error("Chat error:", err.message);
    return res.status(500).json({ error: "Server error" });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});






