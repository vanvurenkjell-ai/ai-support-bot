const express = require("express");
const cors = require("cors");

const app = express();
const port = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Simple health check
app.get("/", (req, res) => {
  res.send("AI support backend is running.");
});

// Very simple test chat route (no OpenAI, no Shopify yet)
app.post("/chat", (req, res) => {
  const message = req.body.message || "";
  return res.json({
    reply: `Test reply. You said: "${message}".`,
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});





