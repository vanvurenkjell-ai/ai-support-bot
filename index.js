const express = require("express");
const cors = require("cors");
const fs = require("fs");
require("dotenv").config();
const OpenAI = require("openai");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3001;

// Optional: set this in Render env vars to know exactly what version is deployed
// Example: BUILD_VERSION=2025-12-16-a
const BUILD_VERSION = process.env.BUILD_VERSION || "dev";

// IMPORTANT on Render/Proxies: this makes req.ip work properly
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

// ---- Process-level safety (log crashes) ----
process.on("unhandledRejection", (reason) => {
  console.error("UNHANDLED_REJECTION:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT_EXCEPTION:", err);
});

// ---- RequestId + structured logging ----
function makeRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function safeLogJson(obj) {
  try {
    console.log(JSON.stringify(obj));
  } catch {
    console.log(String(obj));
  }
}

// attach requestId to every request
app.use((req, res, next) => {
  req.requestId = makeRequestId();
  res.setHeader("X-Request-Id", req.requestId);
  next();
});

// ---- Sanitizing helpers needed early for rate limiting ----
function sanitizeClientId(id) {
  const fallback = "Advantum";
  const raw = String(id || "").trim();
  if (!raw) return fallback;
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) return fallback;
  return raw;
}

function sanitizeSessionId(id) {
  const raw = String(id || "").trim();
  if (!raw) return "";
  return raw.replace(/[^A-Za-z0-9_-]/g, "").slice(0, 80);
}

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

// ---- Abuse protection (IP + Client + Session) ----
const RL_WINDOW_MS = 10 * 1000; // 10 seconds

// IP limits
const RL_IP_MAX_REQUESTS_PER_WINDOW = 12;
const RL_IP_MIN_GAP_MS = 800;

// Client limits
const RL_CLIENT_MAX_REQUESTS_PER_WINDOW = 40;
const RL_CLIENT_MIN_GAP_MS = 200;

// Session limits
const RL_SESSION_MAX_REQUESTS_PER_WINDOW = 10;
const RL_SESSION_MIN_GAP_MS = 700;

// Duplicate message spam limits (per session)
const RL_DUPLICATE_WINDOW_MS = 20 * 1000;
const RL_DUPLICATE_MAX = 3;

// stores
const rateLimitStoreIp = new Map(); // ip -> { windowStart, count, lastAt }
const rateLimitStoreClient = new Map(); // clientId -> { windowStart, count, lastAt }
const rateLimitStoreSession = new Map(); // sessionId -> { windowStart, count, lastAt, lastMsg, lastMsgAt, dupCount }

function getClientIp(req) {
  return req.ip || "unknown";
}

function readClientIdFromReq(req) {
  return sanitizeClientId(req.query && req.query.client ? req.query.client : "Advantum");
}

function readSessionIdFromReq(req) {
  return sanitizeSessionId(req.body && req.body.sessionId ? req.body.sessionId : "");
}

function readMessageFromReq(req) {
  return sanitizeUserMessage(req.body && req.body.message ? req.body.message : "");
}

function rateLimitDecision(store, key, now, maxPerWindow, minGapMs) {
  const entry = store.get(key) || { windowStart: now, count: 0, lastAt: 0 };
  if (now - entry.windowStart > RL_WINDOW_MS) {
    entry.windowStart = now;
    entry.count = 0;
  }
  if (entry.lastAt && now - entry.lastAt < minGapMs) {
    entry.lastAt = now;
    store.set(key, entry);
    return { blocked: true, reason: "min_gap", entry };
  }
  entry.count += 1;
  entry.lastAt = now;
  store.set(key, entry);
  if (entry.count > maxPerWindow) {
    return { blocked: true, reason: "window_count", entry };
  }
  return { blocked: false, reason: "", entry };
}

function shouldBlockDuplicateSessionMessage(sessionEntry, now, message) {
  if (!message || !sessionEntry) return { blocked: false };

  const lastMsg = sessionEntry.lastMsg || "";
  const lastMsgAt = sessionEntry.lastMsgAt || 0;

  if (!lastMsgAt || now - lastMsgAt > RL_DUPLICATE_WINDOW_MS || lastMsg !== message) {
    sessionEntry.lastMsg = message;
    sessionEntry.lastMsgAt = now;
    sessionEntry.dupCount = 0;
    return { blocked: false };
  }

  sessionEntry.dupCount = (sessionEntry.dupCount || 0) + 1;
  if (sessionEntry.dupCount >= RL_DUPLICATE_MAX) {
    return { blocked: true };
  }
  return { blocked: false };
}

function rateLimitChat(req, res, next) {
  if (req.path !== "/chat") return next();

  const now = Date.now();
  const ip = getClientIp(req);
  const clientId = readClientIdFromReq(req);
  const sessionId = readSessionIdFromReq(req);
  const message = readMessageFromReq(req);

  const ipCheck = rateLimitDecision(rateLimitStoreIp, ip, now, RL_IP_MAX_REQUESTS_PER_WINDOW, RL_IP_MIN_GAP_MS);
  if (ipCheck.blocked) {
    safeLogJson({
      type: "rate_limit",
      requestId: req.requestId,
      keyType: "ip",
      key: ip,
      clientId,
      sessionId: sessionId || null,
      rule: ipCheck.reason,
      count: ipCheck.entry.count,
      windowMs: RL_WINDOW_MS,
      at: new Date().toISOString(),
    });
    return res.status(429).json({
      requestId: req.requestId,
      error: "Too many messages too quickly. Please wait a moment and try again.",
    });
  }

  const clientCheck = rateLimitDecision(
    rateLimitStoreClient,
    clientId,
    now,
    RL_CLIENT_MAX_REQUESTS_PER_WINDOW,
    RL_CLIENT_MIN_GAP_MS
  );
  if (clientCheck.blocked) {
    safeLogJson({
      type: "rate_limit",
      requestId: req.requestId,
      keyType: "client",
      key: clientId,
      clientId,
      sessionId: sessionId || null,
      rule: clientCheck.reason,
      count: clientCheck.entry.count,
      windowMs: RL_WINDOW_MS,
      at: new Date().toISOString(),
    });
    return res.status(429).json({
      requestId: req.requestId,
      error: "Too many requests right now for this store. Please wait a few seconds and try again.",
    });
  }

  if (sessionId) {
    const sessionCheck = rateLimitDecision(
      rateLimitStoreSession,
      sessionId,
      now,
      RL_SESSION_MAX_REQUESTS_PER_WINDOW,
      RL_SESSION_MIN_GAP_MS
    );

    const sessionEntry = rateLimitStoreSession.get(sessionId) || sessionCheck.entry;
    const dupCheck = shouldBlockDuplicateSessionMessage(sessionEntry, now, message);
    rateLimitStoreSession.set(sessionId, sessionEntry);

    if (dupCheck.blocked) {
      safeLogJson({
        type: "rate_limit",
        requestId: req.requestId,
        keyType: "session",
        key: sessionId,
        clientId,
        sessionId,
        rule: "duplicate_message",
        dupCount: sessionEntry.dupCount,
        windowMs: RL_DUPLICATE_WINDOW_MS,
        at: new Date().toISOString(),
      });
      return res.status(429).json({
        requestId: req.requestId,
        error: "It looks like the same message was sent repeatedly. Please wait a moment and try again.",
      });
    }

    if (sessionCheck.blocked) {
      safeLogJson({
        type: "rate_limit",
        requestId: req.requestId,
        keyType: "session",
        key: sessionId,
        clientId,
        sessionId,
        rule: sessionCheck.reason,
        count: sessionCheck.entry.count,
        windowMs: RL_WINDOW_MS,
        at: new Date().toISOString(),
      });
      return res.status(429).json({
        requestId: req.requestId,
        error: "Too many messages too quickly. Please wait a moment and try again.",
      });
    }
  }

  return next();
}

// cleanup stores
setInterval(() => {
  const now = Date.now();
  function clean(store) {
    for (const [k, entry] of store.entries()) {
      if (!entry) {
        store.delete(k);
        continue;
      }
      if (now - (entry.lastAt || entry.windowStart || 0) > 60 * 1000) {
        store.delete(k);
      }
    }
  }
  clean(rateLimitStoreIp);
  clean(rateLimitStoreClient);
  clean(rateLimitStoreSession);
}, 60 * 1000);

app.use(rateLimitChat);

// ---- OpenAI ----
if (!process.env.OPENAI_API_KEY) {
  console.error("Missing OPENAI_API_KEY");
  process.exit(1);
}

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

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
} else {
  console.warn("Shopify env vars missing; order lookup will be disabled until they are set.");
}

function sanitizeOrderNumber(orderNumber) {
  if (!orderNumber) return "";
  return String(orderNumber).replace(/[^A-Za-z0-9#\-_ ]/g, "").trim().slice(0, 60);
}

function looksLikeEmail(s) {
  const t = String(s || "").trim();
  if (!t) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t);
}

function looksLikeShopifyOrderName(orderNumberRaw) {
  const t = sanitizeOrderNumber(orderNumberRaw).replace(/\s+/g, "");
  if (!t) return false;
  if (/^#\d{3,12}$/.test(t)) return true;
  if (/^\d{3,12}$/.test(t)) return true;
  return false;
}

function extractOrderNumberFromText(message) {
  const raw = String(message || "");
  if (!raw.trim()) return "";

  const candidates = [];

  const customMatches = raw.match(/\b[A-Za-z]{2,12}[-_]\d{2,8}(?:[-_]\d{1,8})+\b/g) || [];
  for (const m of customMatches) candidates.push(m);

  const customShortMatches = raw.match(/\b[A-Za-z]{2,12}[-_]\d{3,12}\b/g) || [];
  for (const m of customShortMatches) candidates.push(m);

  const numericMatches = raw.match(/#\d{3,12}\b/g) || [];
  for (const m of numericMatches) candidates.push(m);

  const plainDigits = raw.match(/\b\d{3,12}\b/g) || [];
  for (const m of plainDigits) candidates.push(m);

  const splitNumeric = raw.match(/\b\d{2,6}[- ]\d{2,6}\b/g) || [];
  for (const m of splitNumeric) candidates.push(m);

  if (!candidates.length) return "";

  const pickedRaw = candidates[candidates.length - 1];
  let cleaned = sanitizeOrderNumber(pickedRaw);
  cleaned = cleaned.replace(/\s+/g, " ").trim();
  if (!/\d/.test(cleaned)) return "";
  return cleaned;
}

// ---- Session memory + flow state + facts ----
const SESSION_HISTORY_LIMIT = 10;
const SESSION_TTL_MS = 1000 * 60 * 60 * 6;

const sessionStore = new Map();

function getSession(sessionId) {
  if (!sessionId) return null;
  const existing = sessionStore.get(sessionId);
  if (!existing) return null;
  if (Date.now() - existing.updatedAt > SESSION_TTL_MS) {
    sessionStore.delete(sessionId);
    return null;
  }
  return existing;
}

function upsertSession(sessionId, messages, meta) {
  if (!sessionId) return;
  sessionStore.set(sessionId, {
    updatedAt: Date.now(),
    messages,
    meta: meta || {},
  });
}

function appendToHistory(sessionId, role, content) {
  if (!sessionId || !content) return;
  const existing = getSession(sessionId);
  const history = existing ? existing.messages.slice() : [];
  const meta = existing ? { ...(existing.meta || {}) } : {};
  history.push({ role, content });
  const trimmed = history.slice(-SESSION_HISTORY_LIMIT);
  upsertSession(sessionId, trimmed, meta);
}

function getMeta(sessionId) {
  const s = getSession(sessionId);
  return s && s.meta ? s.meta : {};
}

function setMeta(sessionId, patch) {
  if (!sessionId) return;
  const existing = getSession(sessionId);
  const messages = existing ? existing.messages.slice() : [];
  const meta = existing ? { ...(existing.meta || {}) } : {};
  const merged = { ...meta, ...(patch || {}) };
  upsertSession(sessionId, messages, merged);
}

function getFacts(sessionId) {
  const meta = getMeta(sessionId);
  return meta && meta.facts ? meta.facts : {};
}

function setFacts(sessionId, patch) {
  const meta = getMeta(sessionId);
  const facts = meta && meta.facts ? { ...meta.facts } : {};
  const mergedFacts = { ...facts, ...(patch || {}) };
  setMeta(sessionId, { facts: mergedFacts });
}

function clearExpectedSlot(sessionId) {
  setMeta(sessionId, { expectedSlot: "" });
}

function buildHistoryMessages(sessionId) {
  const existing = getSession(sessionId);
  return existing ? existing.messages.slice() : [];
}

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of sessionStore.entries()) {
    if (!val || now - val.updatedAt > SESSION_TTL_MS) sessionStore.delete(key);
  }
}, 1000 * 60 * 15);

// ---- Intent detection ----
function detectIntent(message) {
  const text = message.toLowerCase();
  const shipping = ["verzending", "bezorg", "track", "order", "shipping", "delivery"];
  const returns = ["retour", "refund", "terug", "herroep", "omruil"];
  const usage = ["gebruik", "how", "hoe", "tutorial", "uitleg"];

  const orderNumber = extractOrderNumberFromText(message);

  let mainIntent = "general";
  if (shipping.some((w) => text.includes(w)) || orderNumber) mainIntent = "shipping_or_order";
  if (returns.some((w) => text.includes(w))) mainIntent = "return_or_withdrawal";
  if (usage.some((w) => text.includes(w)) && mainIntent === "general") mainIntent = "product_usage";

  return { mainIntent, orderNumber };
}

// ---- Shopify lookup ----
async function lookupShopifyOrder(orderNumberRaw) {
  if (!shopifyClient) return null;

  const orderNumber = sanitizeOrderNumber(orderNumberRaw);
  if (!orderNumber) return null;

  const compact = orderNumber.replace(/\s+/g, "");
  const nameParam = compact.startsWith("#") ? compact : `#${compact}`;

  try {
    const res = await shopifyClient.get("/orders.json", {
      params: { name: nameParam, status: "any" },
    });

    const orders = res.data && res.data.orders ? res.data.orders : [];
    if (!orders.length) return null;

    const order = orders[0];
    const fulfillment = order.fulfillments && order.fulfillments[0] ? order.fulfillments[0] : null;

    return {
      orderName: order.name || null,
      fulfillmentStatus: order.fulfillment_status || null,
      financialStatus: order.financial_status || null,
      tracking:
        fulfillment && fulfillment.tracking_numbers && fulfillment.tracking_numbers[0]
          ? fulfillment.tracking_numbers[0]
          : null,
      trackingUrl:
        fulfillment && fulfillment.tracking_urls && fulfillment.tracking_urls[0]
          ? fulfillment.tracking_urls[0]
          : null,
      createdAt: order.created_at || null,
    };
  } catch (e) {
    console.error("Shopify lookup error:", e.message);
    return null;
  }
}

// ---- Knowledge loading ----
function readFile(path) {
  try {
    return fs.existsSync(path) ? fs.readFileSync(path, "utf8") : "";
  } catch {
    return "";
  }
}

function safeJsonParse(raw, fallback = {}) {
  try {
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" ? obj : fallback;
  } catch {
    return fallback;
  }
}

function normalizeText(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/[\u2019’]/g, "'")
    .replace(/[^a-z0-9à-ÿ#\-\s]/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const STOPWORDS = new Set([
  "de","het","een","en","of","maar","want","dus","dat","dit","die",
  "ik","jij","je","u","hij","zij","ze","wij","we","jullie","hun","hen","mijn","jouw","uw",
  "is","zijn","was","waren","ben","bent","wordt","worden","kan","kunnen","zal","zullen",
  "met","voor","van","naar","op","in","aan","bij","als","om","uit","tot","over","onder",
  "the","a","an","and","or","but","because","so","that","this","these","those",
  "i","you","he","she","we","they","my","your","our","their",
  "is","are","was","were","be","been","being","can","could","will","would","should",
  "with","for","from","to","on","in","at","as","by","of","about","into","over","under"
]);

function extractKeywords(query) {
  const norm = normalizeText(query);
  const parts = norm.split(" ").filter(Boolean);
  const keywords = [];
  for (const p of parts) {
    if (p.length < 3) continue;
    if (STOPWORDS.has(p)) continue;
    keywords.push(p);
  }
  return [...new Set(keywords)];
}

function chunkMarkdown(source, markdown, maxChunkChars = 900) {
  const lines = String(markdown || "").split("\n");
  let h1 = "", h2 = "", h3 = "";
  const chunks = [];
  let buffer = "";

  function flushBuffer() {
    const text = buffer.trim();
    buffer = "";
    if (!text) return;

    if (text.length <= maxChunkChars) {
      chunks.push({ source, heading: [h1, h2, h3].filter(Boolean).join(" > "), text });
      return;
    }

    const paras = text.split(/\n{2,}/);
    let current = "";
    for (const p of paras) {
      const part = p.trim();
      if (!part) continue;

      if ((current + "\n\n" + part).trim().length > maxChunkChars && current.trim()) {
        chunks.push({ source, heading: [h1, h2, h3].filter(Boolean).join(" > "), text: current.trim() });
        current = part;
      } else {
        current = (current ? current + "\n\n" : "") + part;
      }
    }
    if (current.trim()) chunks.push({ source, heading: [h1, h2, h3].filter(Boolean).join(" > "), text: current.trim() });
  }

  for (const raw of lines) {
    const line = raw || "";
    const h1m = line.match(/^#\s+(.+)/);
    const h2m = line.match(/^##\s+(.+)/);
    const h3m = line.match(/^###\s+(.+)/);

    if (h1m) { flushBuffer(); h1 = h1m[1].trim(); h2 = ""; h3 = ""; continue; }
    if (h2m) { flushBuffer(); h2 = h2m[1].trim(); h3 = ""; continue; }
    if (h3m) { flushBuffer(); h3 = h3m[1].trim(); continue; }

    buffer += line + "\n";
  }

  flushBuffer();
  return chunks.filter((c) => c.text && c.text.trim().length >= 80);
}

const SOURCE_WEIGHT = {
  "Policies.md": 3,
  "Shipping matrix.md": 3,
  "Customer support rules.md": 3,
  "Promotions & discounts.md": 2,
  "FAQ.md": 2,
  "Troubleshooting.md": 2,
  "Products.md": 1,
  "Product tutorials.md": 1,
  "Company overview.md": 1,
  "Legal.md": 1,
};

function loadClient(clientIdRaw) {
  const clientId = sanitizeClientId(clientIdRaw);
  const base = `./Clients/${clientId}`;

  if (!fs.existsSync(base)) {
    throw new Error(`Client folder not found: ${base}`);
  }

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

  const allChunks = [];
  for (const file of files) {
    const content = readFile(`${base}/${file}`);
    if (!content || !content.trim()) continue;
    const chunks = chunkMarkdown(file, content, 900);
    for (const c of chunks) allChunks.push({ source: file, heading: c.heading || "", text: c.text });
  }

  const clientConfigRaw = readFile(`${base}/client-config.json`) || "{}";
  const clientConfig = safeJsonParse(clientConfigRaw, {});

  return { clientId, brandVoice, supportRules, chunks: allChunks, clientConfig };
}

function countHits(textNorm, keyword) {
  const k = keyword.trim();
  if (!k) return 0;
  let count = 0;
  let idx = 0;
  while (true) {
    idx = textNorm.indexOf(k, idx);
    if (idx === -1) break;
    count++;
    idx += k.length;
  }
  return count;
}

function scoreChunk(chunk, queryKeywords) {
  const textNorm = normalizeText(chunk.text);
  const headingNorm = normalizeText(chunk.heading || "");
  let score = 0;
  for (const kw of queryKeywords) {
    score += countHits(textNorm, kw) * 2 + (headingNorm ? countHits(headingNorm, kw) * 4 : 0);
  }
  return score * (SOURCE_WEIGHT[chunk.source] || 1);
}

function isPolicyLikeQuestion(msgNorm) {
  const keys = ["verzend","shipping","bezorg","delivery","retour","refund","garantie","warranty","korting","discount","promot","actie","kosten","price","betaling","payment"];
  return keys.some((k) => msgNorm.includes(k));
}

function selectTopChunks(chunks, message, limit = 8, maxTotalChars = 4500) {
  const msgNorm = normalizeText(message);
  const keywords = extractKeywords(message);

  const scored = chunks
    .map((c) => ({ ...c, score: scoreChunk(c, keywords) }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score);

  if (!scored.length && isPolicyLikeQuestion(msgNorm)) {
    return chunks
      .filter((c) => c.source === "Policies.md" || c.source === "Shipping matrix.md")
      .slice(0, limit)
      .map((c) => ({ ...c, score: 1 }));
  }

  const selected = [];
  let total = 0;

  for (const c of scored) {
    const block = `### ${c.source}${c.heading ? " — " + c.heading : ""}\n${c.text}\n`;
    if (total + block.length > maxTotalChars) continue;
    selected.push(c);
    total += block.length;
    if (selected.length >= limit) break;
  }

  return selected;
}

// ---- Widget config endpoint ----
function buildWidgetConfig(clientConfig, clientId) {
  const brandName = clientConfig.brandName || clientId;

  const widgetTitle =
    (clientConfig.widget && clientConfig.widget.title) ||
    clientConfig.widgetTitle ||
    clientConfig.assistantName ||
    brandName;

  const widgetGreeting =
    (clientConfig.widget && clientConfig.widget.greeting) ||
    clientConfig.widgetGreeting ||
    `Hallo! Ik ben de ${brandName} klantenservice assistent. Waar kan ik je mee helpen?`;

  const logoUrl = clientConfig.logoUrl || null;

  const colors = clientConfig.colors
    ? {
        primary: clientConfig.colors.primary || clientConfig.primaryColor || "#000000",
        accent: clientConfig.colors.accent || clientConfig.accentColor || "#2563eb",
        background: clientConfig.colors.background || "#ffffff",
        userBubble:
          clientConfig.colors.userBubble ||
          clientConfig.colors.primary ||
          clientConfig.primaryColor ||
          "#000000",
        botBubble: clientConfig.colors.botBubble || "#ffffff",
      }
    : {
        primary: clientConfig.primaryColor || "#000000",
        accent: clientConfig.accentColor || "#2563eb",
        background: "#ffffff",
        userBubble: clientConfig.primaryColor || "#000000",
        botBubble: "#ffffff",
      };

  return {
    brandName,
    assistantName: clientConfig.assistantName || widgetTitle,
    language: clientConfig.language || "nl",
    noEmojis: clientConfig.noEmojis !== false,
    logoUrl,
    widget: { title: widgetTitle, greeting: widgetGreeting },
    colors,
    support: {
      email: clientConfig.supportEmail || null,
      contactFormUrl: clientConfig.contactFormUrl || null,
    },
    version: clientConfig.version || null,
  };
}

// ---- Troubleshooting + follow-up router + fact capture ----
function isTroubleshootingLike(message) {
  const t = normalizeText(message);
  const keys = ["werkt niet","doet het niet","kapot","probleem","storing","error","fout","broken","doesnt work","doesn't work"];
  return keys.some((k) => t.includes(k));
}

function buildFollowUpQuestion(language, intent, slot) {
  const nl = {
    orderNumber: "Wat is je bestelnummer? Bijvoorbeeld #1055.",
    emailOrOrder: "Wat is je bestelnummer? Als je die niet hebt: met welk e-mailadres heb je besteld?",
    productName: "Welk product bedoel je precies?",
    problemDetails: "Wat gaat er precies mis, en wat heb je al geprobeerd?",
  };
  const en = {
    orderNumber: "What is your order number? For example #1055.",
    emailOrOrder: "What is your order number? If you don’t have it: what email address did you order with?",
    productName: "Which product is it exactly?",
    problemDetails: "What exactly is going wrong, and what have you tried already?",
  };

  const dict = String(language || "nl").toLowerCase().startsWith("en") ? en : nl;
  if (slot && dict[slot]) return dict[slot];
  if (intent === "shipping_or_order") return dict.orderNumber;
  if (intent === "return_or_withdrawal") return dict.emailOrOrder;
  return dict.problemDetails;
}

function captureFactsFromExpectedSlot(sessionId, expectedSlot, userMessage) {
  const msg = String(userMessage || "").trim();
  if (!expectedSlot) return;

  if (expectedSlot === "orderNumber") {
    const order = extractOrderNumberFromText(msg);
    if (order) setFacts(sessionId, { orderNumber: order });
    return;
  }

  if (expectedSlot === "emailOrOrder") {
    const order = extractOrderNumberFromText(msg);
    if (order) {
      setFacts(sessionId, { orderNumber: order });
      return;
    }
    if (looksLikeEmail(msg)) setFacts(sessionId, { email: msg });
    return;
  }

  if (expectedSlot === "productName") {
    const cleaned = msg.slice(0, 80);
    if (cleaned) setFacts(sessionId, { productName: cleaned });
    return;
  }

  if (expectedSlot === "problemDetails") {
    const cleaned = msg.slice(0, 200);
    if (cleaned) setFacts(sessionId, { problemDetails: cleaned });
    return;
  }
}

function maybeHandleWithRouter({ sessionId, message, intent, clientConfig }) {
  const lang = clientConfig.language || "nl";
  const meta = getMeta(sessionId);
  const facts = getFacts(sessionId);
  const expected = meta.expectedSlot || "";

  if (expected) {
    captureFactsFromExpectedSlot(sessionId, expected, message);
    clearExpectedSlot(sessionId);
    return { handled: false };
  }

  if (intent.orderNumber) setFacts(sessionId, { orderNumber: intent.orderNumber });

  if (intent.mainIntent === "shipping_or_order") {
    const orderKnown = intent.orderNumber || facts.orderNumber;
    if (!orderKnown) {
      setMeta(sessionId, { expectedSlot: "orderNumber", lastIntent: intent.mainIntent });
      return { handled: true, reply: buildFollowUpQuestion(lang, intent.mainIntent, "orderNumber") };
    }
  }

  if (intent.mainIntent === "return_or_withdrawal") {
    const orderKnown = intent.orderNumber || facts.orderNumber;
    const emailKnown = facts.email;
    if (!orderKnown && !emailKnown) {
      setMeta(sessionId, { expectedSlot: "emailOrOrder", lastIntent: intent.mainIntent });
      return { handled: true, reply: buildFollowUpQuestion(lang, intent.mainIntent, "emailOrOrder") };
    }
  }

  if ((intent.mainIntent === "product_usage" || intent.mainIntent === "general") && isTroubleshootingLike(message)) {
    if (!facts.productName) {
      setMeta(sessionId, { expectedSlot: "productName", lastIntent: "product_troubleshooting" });
      return { handled: true, reply: buildFollowUpQuestion(lang, "product_usage", "productName") };
    }
    if (!facts.problemDetails) {
      setMeta(sessionId, { expectedSlot: "problemDetails", lastIntent: "product_troubleshooting" });
      return { handled: true, reply: buildFollowUpQuestion(lang, "product_usage", "problemDetails") };
    }
  }

  return { handled: false };
}

// ---- Angry / urgent detection ----
function detectAngryOrUrgent(message) {
  const t = normalizeText(message);
  const urgent = ["urgent","met spoed","direct","nu hulp","nu meteen","asap","immediately"];
  const angry = ["boos","woest","geïrriteerd","geirriteerd","belachelijk","ridiculous","waardeloos","oplichter","scam","fraude","ik ben er klaar mee","this is unacceptable","i am angry","i'm angry"];
  const hasUrgent = urgent.some((k) => t.includes(k));
  const hasAngry = angry.some((k) => t.includes(k));
  return { hasUrgent, hasAngry, shouldEscalate: hasUrgent || hasAngry };
}

function buildEscalationReply(clientConfig, clientId) {
  const lang = clientConfig.language || "nl";
  const brandName = clientConfig.brandName || clientId;

  const email = (clientConfig.support && clientConfig.support.email) || clientConfig.supportEmail || "";
  const contactUrl = (clientConfig.support && clientConfig.support.contactFormUrl) || clientConfig.contactFormUrl || "";
  const custom = (clientConfig.support && clientConfig.support.escalationMessage) || "";

  if (custom && String(custom).trim()) {
    let msg = String(custom).trim();
    if (email && !msg.includes(email)) msg += `\n\nE-mail: ${email}`;
    if (contactUrl && !msg.includes(contactUrl)) msg += `\nContact: ${contactUrl}`;
    return msg;
  }

  if (String(lang).toLowerCase().startsWith("en")) {
    let msg = `I’m sorry this has been frustrating. For urgent help, please contact ${brandName} support.`;
    if (email) msg += `\n\nEmail: ${email}`;
    if (contactUrl) msg += `\nContact form: ${contactUrl}`;
    return msg;
  }

  let msg = `Het spijt me dat dit frustrerend is. Voor snelle hulp kun je direct contact opnemen met ${brandName} support.`;
  if (email) msg += `\n\nE-mail: ${email}`;
  if (contactUrl) msg += `\nContactformulier: ${contactUrl}`;
  return msg;
}

// NEW: structured handoff payload for the frontend
function buildHandoffPayload({ clientConfig, clientId, sessionId, reason, lastUserMessage }) {
  const lang = (clientConfig && clientConfig.language) || "nl";
  const brandName = (clientConfig && clientConfig.brandName) || clientId;

  const email =
    (clientConfig && clientConfig.support && clientConfig.support.email) ||
    (clientConfig && clientConfig.supportEmail) ||
    null;

  const contactFormUrl =
    (clientConfig && clientConfig.support && clientConfig.support.contactFormUrl) ||
    (clientConfig && clientConfig.contactFormUrl) ||
    null;

  const facts = getFacts(sessionId);

  const parts = [];
  parts.push(`${brandName} support handoff`);
  parts.push(`Reason: ${reason || "unknown"}`);

  if (facts.orderNumber) parts.push(`Order number: ${facts.orderNumber}`);
  if (facts.email) parts.push(`Customer email: ${facts.email}`);
  if (facts.productName) parts.push(`Product: ${facts.productName}`);
  if (facts.problemDetails) parts.push(`Problem details: ${facts.problemDetails}`);

  if (lastUserMessage) parts.push(`Last message: ${String(lastUserMessage).slice(0, 300)}`);

  const summary = parts.join("\n");

  return {
    reason: reason || "unknown",
    email,
    contactFormUrl,
    summary,
    language: String(lang).toLowerCase().startsWith("en") ? "en" : "nl",
  };
}

// ---- Deterministic reply for "order number not found" ----
function buildOrderNotFoundReply(clientConfig, clientId, orderNumber) {
  const lang = (clientConfig && clientConfig.language) || "nl";
  const n = sanitizeOrderNumber(orderNumber).replace(/\s+/g, " ").trim();

  if (String(lang).toLowerCase().startsWith("en")) {
    return `I can’t find an order with order number "${n}". Please send the correct Shopify order number (for example #1055). If you don’t have it, share the email address used for the order.`;
  }

  return `Ik kan geen bestelling vinden met bestelnummer "${n}". Stuur het juiste Shopify bestelnummer (bijvoorbeeld #1055). Als je die niet hebt: met welk e-mailadres heb je besteld?`;
}

// ---- Routes ----
app.get("/", (req, res) => {
  return res.json({ ok: true, message: "AI support backend running.", requestId: req.requestId });
});

app.get("/health", (req, res) => {
  return res.json({
    ok: true,
    requestId: req.requestId,
    version: BUILD_VERSION,
    uptimeSec: Math.round(process.uptime()),
    node: process.version,
    shopifyEnabled: Boolean(shopifyClient),
    time: new Date().toISOString(),
  });
});

app.get("/widget-config", (req, res) => {
  const clientId = sanitizeClientId(req.query.client || "Advantum");
  const t0 = Date.now();

  try {
    const data = loadClient(clientId);
    const widgetConfig = buildWidgetConfig(data.clientConfig || {}, data.clientId);
    res.setHeader("Cache-Control", "public, max-age=300");

    safeLogJson({
      type: "widget_config",
      requestId: req.requestId,
      clientId: data.clientId,
      ip: getClientIp(req),
      ms: Date.now() - t0,
      at: new Date().toISOString(),
    });

    return res.json({ requestId: req.requestId, ...widgetConfig });
  } catch (e) {
    console.error("widget-config error:", e.message);

    safeLogJson({
      type: "widget_config_error",
      requestId: req.requestId,
      clientId,
      ip: getClientIp(req),
      error: e && e.message ? e.message : String(e),
      ms: Date.now() - t0,
      at: new Date().toISOString(),
    });

    return res.status(500).json({ requestId: req.requestId, error: "Server error" });
  }
});

app.post("/chat", async (req, res) => {
  const tAll0 = Date.now();
  const ip = getClientIp(req);

  let clientId = "Advantum";
  let sessionId = "";
  let effectiveIntent = null;

  let shopifyAttempted = false;
  let shopifyFound = false;
  let shopifyMs = 0;
  let openaiMs = 0;
  let openaiUsage = null;

  try {
    const message = sanitizeUserMessage(req.body.message);
    if (!message) return res.status(400).json({ requestId: req.requestId, error: "Invalid message" });

    clientId = sanitizeClientId(req.query.client || "Advantum");
    sessionId = sanitizeSessionId(req.body.sessionId);

    const data = loadClient(clientId);
    const intentRaw = detectIntent(message);

    if (intentRaw.orderNumber) setFacts(sessionId, { orderNumber: intentRaw.orderNumber });
    setMeta(sessionId, { lastIntent: intentRaw.mainIntent });

    appendToHistory(sessionId, "user", message);

    const escalation = detectAngryOrUrgent(message);
    if (escalation.shouldEscalate) {
      const reply = buildEscalationReply(data.clientConfig || {}, data.clientId);

      const handoff = buildHandoffPayload({
        clientConfig: data.clientConfig || {},
        clientId: data.clientId,
        sessionId,
        reason: escalation.hasUrgent ? "urgent" : "angry",
        lastUserMessage: message,
      });

      appendToHistory(sessionId, "assistant", reply);

      safeLogJson({
        type: "chat_done",
        requestId: req.requestId,
        clientId: data.clientId,
        sessionId: sessionId || null,
        ip,
        intent: { ...intentRaw, mainIntent: "support_escalation" },
        routed: true,
        escalated: true,
        handoffReason: handoff.reason,
        shopifyAttempted: false,
        shopifyFound: false,
        openaiMs: 0,
        totalMs: Date.now() - tAll0,
        at: new Date().toISOString(),
      });

      return res.json({
        requestId: req.requestId,
        reply,
        intent: { ...intentRaw, mainIntent: "support_escalation" },
        shopify: null,
        routed: true,
        escalated: true,
        handoff,
        facts: getFacts(sessionId),
      });
    }

    const router = maybeHandleWithRouter({
      sessionId,
      message,
      intent: intentRaw,
      clientConfig: data.clientConfig || {},
    });

    if (router.handled) {
      appendToHistory(sessionId, "assistant", router.reply);

      safeLogJson({
        type: "chat_done",
        requestId: req.requestId,
        clientId: data.clientId,
        sessionId: sessionId || null,
        ip,
        intent: intentRaw,
        routed: true,
        escalated: false,
        shopifyAttempted: false,
        shopifyFound: false,
        openaiMs: 0,
        totalMs: Date.now() - tAll0,
        at: new Date().toISOString(),
      });

      return res.json({
        requestId: req.requestId,
        reply: router.reply,
        intent: intentRaw,
        shopify: null,
        routed: true,
        escalated: false,
        facts: getFacts(sessionId),
      });
    }

    const facts = getFacts(sessionId);
    effectiveIntent = {
      ...intentRaw,
      orderNumber: intentRaw.orderNumber || facts.orderNumber || "",
    };

    if (
      effectiveIntent.mainIntent === "shipping_or_order" &&
      effectiveIntent.orderNumber &&
      !looksLikeShopifyOrderName(effectiveIntent.orderNumber)
    ) {
      const reply = buildOrderNotFoundReply(data.clientConfig || {}, data.clientId, effectiveIntent.orderNumber);
      appendToHistory(sessionId, "assistant", reply);

      safeLogJson({
        type: "chat_done",
        requestId: req.requestId,
        clientId: data.clientId,
        sessionId: sessionId || null,
        ip,
        intent: effectiveIntent,
        routed: true,
        escalated: false,
        shopifyAttempted: false,
        shopifyFound: false,
        openaiMs: 0,
        totalMs: Date.now() - tAll0,
        at: new Date().toISOString(),
      });

      return res.json({
        requestId: req.requestId,
        reply,
        intent: effectiveIntent,
        shopify: null,
        routed: true,
        escalated: false,
        facts: getFacts(sessionId),
      });
    }

    let shopify = null;
    if (effectiveIntent.mainIntent === "shipping_or_order" && effectiveIntent.orderNumber && looksLikeShopifyOrderName(effectiveIntent.orderNumber)) {
      shopifyAttempted = true;
      const tShop0 = Date.now();
      shopify = await lookupShopifyOrder(effectiveIntent.orderNumber);
      shopifyMs = Date.now() - tShop0;
      shopifyFound = Boolean(shopify);

      if (!shopify) {
        const reply = buildOrderNotFoundReply(data.clientConfig || {}, data.clientId, effectiveIntent.orderNumber);
        appendToHistory(sessionId, "assistant", reply);

        safeLogJson({
          type: "chat_done",
          requestId: req.requestId,
          clientId: data.clientId,
          sessionId: sessionId || null,
          ip,
          intent: effectiveIntent,
          routed: true,
          escalated: false,
          shopifyAttempted: true,
          shopifyFound: false,
          shopifyMs,
          openaiMs: 0,
          totalMs: Date.now() - tAll0,
          at: new Date().toISOString(),
        });

        return res.json({
          requestId: req.requestId,
          reply,
          intent: effectiveIntent,
          shopify: null,
          routed: true,
          escalated: false,
          facts: getFacts(sessionId),
        });
      }
    }

    const retrievalQuery = message.length < 30 && facts.productName ? `${message} ${facts.productName}` : message;

    const topChunks = selectTopChunks(data.chunks, retrievalQuery, 8, 4500);
    const context = topChunks
      .map((c) => `### ${c.source}${c.heading ? " — " + c.heading : ""}\n${c.text}`)
      .join("\n\n");

    const historyMessages = buildHistoryMessages(sessionId);
    const meta = getMeta(sessionId);

    const flowHint = meta.expectedSlot
      ? `EXPECTED_USER_INPUT: The user is answering the bot's question. Slot expected: ${meta.expectedSlot}.`
      : "EXPECTED_USER_INPUT: none";

    const factsBlock = `
FACTS WE ALREADY KNOW (persisted from earlier messages):
- productName: ${facts.productName || "unknown"}
- orderNumber: ${facts.orderNumber || "unknown"}
- email: ${facts.email || "unknown"}
- problemDetails: ${facts.problemDetails || "unknown"}
`.trim();

    const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName || data.clientId}.
Use the same language as the user. No emojis.
Never guess policies, prices, or shipping rules.
Only answer using the provided context.

Conversation handling rules:
- Use the chat history and FACTS WE ALREADY KNOW to understand what the user is answering.
- If the user is answering a clarification question (e.g., product name, order number), treat it as an answer and continue.
- Ask only 1 short follow-up question at a time when needed.
- Do NOT respond with a full product description unless the user explicitly asks for product info.

${flowHint}

${factsBlock}

BRAND VOICE:
${data.brandVoice || ""}

CUSTOMER SUPPORT RULES:
${data.supportRules || ""}

SHOPIFY ORDER DATA:
${shopify ? JSON.stringify(shopify, null, 2) : "none"}

RELEVANT KNOWLEDGE (selected excerpts):
${context || "No relevant knowledge matched."}
`;

    const tAi0 = Date.now();
    const response = await openai.chat.completions.create({
      model: "gpt-4.1-mini",
      messages: [
        { role: "system", content: systemPrompt },
        ...historyMessages,
        { role: "user", content: message },
      ],
    });
    openaiMs = Date.now() - tAi0;
    openaiUsage = response && response.usage ? response.usage : null;

    const reply = response.choices[0].message.content;
    appendToHistory(sessionId, "assistant", reply);

    safeLogJson({
      type: "chat_done",
      requestId: req.requestId,
      clientId: data.clientId,
      sessionId: sessionId || null,
      ip,
      intent: effectiveIntent,
      routed: false,
      escalated: false,
      shopifyAttempted,
      shopifyFound,
      shopifyMs,
      openaiMs,
      openaiUsage,
      totalMs: Date.now() - tAll0,
      at: new Date().toISOString(),
    });

    return res.json({
      requestId: req.requestId,
      reply,
      intent: effectiveIntent,
      shopify,
      routed: false,
      escalated: false,
      facts: getFacts(sessionId),
    });
  } catch (e) {
    console.error("CHAT_ROUTE_ERROR:", e);

    safeLogJson({
      type: "chat_error",
      requestId: req.requestId,
      clientId,
      sessionId: sessionId || null,
      ip,
      intent: effectiveIntent,
      shopifyAttempted,
      shopifyFound,
      shopifyMs,
      openaiMs,
      totalMs: Date.now() - tAll0,
      error: e && e.message ? e.message : String(e),
      at: new Date().toISOString(),
    });

    return res.status(500).json({ requestId: req.requestId, error: "Server error" });
  }
});

app.use((req, res) => {
  res.status(404).send("Not Found");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  safeLogJson({
    type: "boot",
    version: BUILD_VERSION,
    port,
    shopifyEnabled: Boolean(shopifyClient),
    at: new Date().toISOString(),
  });
});

