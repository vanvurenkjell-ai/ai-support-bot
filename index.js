const express = require("express");
const cors = require("cors");
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

app.get("/", (req, res) => {
  res.send("AI support backend is running.");
});

app.post("/chat", async (req, res) => {
  const message = req.body.message || "";

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: message }
      ]
    });

    return res.json({
      reply: response.choices[0].message.content
    });

  } catch (err) {
    console.error("OpenAI error:", err.message);
    return res.status(500).json({
      error: "AI request failed"
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});






