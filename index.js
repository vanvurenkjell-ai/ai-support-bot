const express = require("express");
const cors = require("cors");
const fs = require("fs");
const crypto = require("crypto");
const https = require("https");
const { URL } = require("url");
require("dotenv").config();
const OpenAI = require("openai");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3001;

// Optional: set this in Render env vars to know exactly what version is deployed
const BUILD_VERSION = process.env.BUILD_VERSION || "dev";

// ---- Axiom log ingestion config ----
const AXIOM_TOKEN = process.env.AXIOM_TOKEN;
const AXIOM_DATASET = process.env.AXIOM_DATASET;
const AXIOM_URL = process.env.AXIOM_URL || "https://api.axiom.co";
const AXIOM_ENABLED = Boolean(AXIOM_TOKEN && AXIOM_DATASET);

// IMPORTANT on Render/Proxies: this makes req.ip work properly
app.set("trust proxy", 1);

app.use(cors());
app.use(express.json());

// ---- RequestId + structured logging helpers ----
function makeRequestId() {
  try {
    if (typeof crypto !== "undefined" && crypto.randomUUID) {
      return crypto.randomUUID();
    }
  } catch (e) {}
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function nowIso() {
  return new Date().toISOString();
}

function sendEventToAxiom(eventObj) {
  if (!AXIOM_ENABLED) return;

  try {
    const ingestUrl = `${AXIOM_URL}/v1/datasets/${encodeURIComponent(AXIOM_DATASET)}/ingest`;
    const urlObj = new URL(ingestUrl);
    const payload = JSON.stringify([eventObj]);

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: "POST",
      headers: {
        "Authorization": `Bearer ${AXIOM_TOKEN}`,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
      timeout: 1500,
    };

    const req = https.request(options, (res) => {
      // Consume response to prevent memory leaks, but ignore result
      res.on("data", () => {});
      res.on("end", () => {});
    });

    req.on("error", () => {
      // Silently ignore errors - don't log sensitive data
    });

    req.on("timeout", () => {
      req.destroy();
    });

    req.write(payload);
    req.end();
  } catch (e) {
    // Silently ignore all errors
  }
}

function logJson(level, event, fields) {
  try {
    const logObj = {
      timestamp: nowIso(),
      level: level || "info",
      event: event || "log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));

    // Send to Axiom for request_end, conversation_end, knowledge_gap, and error events
    if (event === "request_end" || event === "conversation_end" || event === "knowledge_gap" || level === "error") {
      sendEventToAxiom(logObj);
    }
  } catch {
    console.log(String(fields));
  }
}

// ---- Process-level safety (log crashes) ----
process.on("unhandledRejection", (reason) => {
  logJson("error", "unhandled_rejection", {
    error: reason && typeof reason === "object" && reason.message ? reason.message : String(reason),
    errorStack: reason && typeof reason === "object" && reason.stack ? String(reason.stack).slice(0, 500) : null,
  });
});
process.on("uncaughtException", (err) => {
  logJson("error", "uncaught_exception", {
    error: err && err.message ? err.message : String(err),
    errorStack: err && err.stack ? String(err.stack).slice(0, 500) : null,
  });
});

function safeLogJson(obj) {
  try {
    console.log(JSON.stringify(obj));
  } catch {
    console.log(String(obj));
  }
}

app.use((req, res, next) => {
  req.requestId = makeRequestId();
  req.requestStartTime = Date.now();
  res.setHeader("X-Request-Id", req.requestId);

  const clientId = sanitizeClientId(req.query && req.query.client ? req.query.client : (req.body && req.body.client ? req.body.client : null));
  const sessionId = req.body && req.body.sessionId ? sanitizeSessionId(req.body.sessionId) : null;

  logJson("info", "request_start", {
    requestId: req.requestId,
    route: req.path,
    method: req.method,
    clientId: clientId || null,
    sessionId: sessionId || null,
    messageLength: req.body && req.body.message ? String(req.body.message).length : null,
  });

  let responseLogged = false;
  const originalJson = res.json.bind(res);
  res.json = function (data) {
    if (!responseLogged) {
      responseLogged = true;
      const latencyMs = Date.now() - req.requestStartTime;
      const logData = {
        requestId: req.requestId,
        route: req.path,
        method: req.method,
        statusCode: res.statusCode || 200,
        latencyMs: latencyMs,
        clientId: clientId || null,
        sessionId: sessionId || null,
      };

      if (req.path === "/chat" && res.locals.chatMetrics) {
        Object.assign(logData, res.locals.chatMetrics);
      }

      logJson("info", "request_end", logData);
    }
    return originalJson(data);
  };

  res.on("finish", function () {
    if (!responseLogged) {
      const latencyMs = Date.now() - req.requestStartTime;
      const logData = {
        requestId: req.requestId,
        route: req.path,
        method: req.method,
        statusCode: res.statusCode || 200,
        latencyMs: latencyMs,
        clientId: clientId || null,
        sessionId: sessionId || null,
      };

      if (req.path === "/chat" && res.locals.chatMetrics) {
        Object.assign(logData, res.locals.chatMetrics);
      }

      logJson("info", "request_end", logData);
    }
  });

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

const RL_IP_MAX_REQUESTS_PER_WINDOW = 12;
const RL_IP_MIN_GAP_MS = 800;

const RL_CLIENT_MAX_REQUESTS_PER_WINDOW = 40;
const RL_CLIENT_MIN_GAP_MS = 200;

const RL_SESSION_MAX_REQUESTS_PER_WINDOW = 10;
const RL_SESSION_MIN_GAP_MS = 700;

const RL_DUPLICATE_WINDOW_MS = 20 * 1000;
const RL_DUPLICATE_MAX = 3;

const rateLimitStoreIp = new Map();
const rateLimitStoreClient = new Map();
const rateLimitStoreSession = new Map();

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

  const clientCheck = rateLimitDecision(rateLimitStoreClient, clientId, now, RL_CLIENT_MAX_REQUESTS_PER_WINDOW, RL_CLIENT_MIN_GAP_MS);
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
    const sessionCheck = rateLimitDecision(rateLimitStoreSession, sessionId, now, RL_SESSION_MAX_REQUESTS_PER_WINDOW, RL_SESSION_MIN_GAP_MS);

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
  setMeta(sessionId, { expectedSlot: "", clarificationType: null, clarificationAttemptCount: 0 });
}

function buildHistoryMessages(sessionId) {
  const existing = getSession(sessionId);
  return existing ? existing.messages.slice() : [];
}

// ---- Conversation state tracking ----
const conversationStateMap = new Map();
const ABANDON_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

function getOrCreateConversation(sessionId, clientId) {
  if (!sessionId) return null;
  
  let state = conversationStateMap.get(sessionId);
  if (!state) {
    state = {
      conversationId: sessionId, // Use sessionId as conversationId
      clientId: clientId,
      sessionId: sessionId,
      startedAt: Date.now(),
      lastActivityAt: Date.now(),
      ended: false,
      outcome: null,
      messageCount: 0,
    };
    conversationStateMap.set(sessionId, state);
  }
  
  return state;
}

function updateConversationActivity(sessionId) {
  if (!sessionId) return;
  const state = conversationStateMap.get(sessionId);
  if (state && !state.ended) {
    state.lastActivityAt = Date.now();
    state.messageCount = (state.messageCount || 0) + 1;
  }
}

function endConversation(sessionId, outcome) {
  if (!sessionId) return false;
  const state = conversationStateMap.get(sessionId);
  if (!state || state.ended) return false;
  
  state.ended = true;
  state.outcome = outcome;
  const durationMs = Date.now() - state.startedAt;
  
  // Get escalateReason from session meta if available
  const session = getSession(sessionId);
  const meta = session && session.meta ? session.meta : {};
  const escalateReason = meta.escalateReason || null;
  
  // logJson will send to Axiom for conversation_end events
  logJson("info", "conversation_end", {
    conversationId: state.conversationId,
    clientId: state.clientId,
    sessionId: state.sessionId,
    conversationOutcome: outcome,
    escalateReason: escalateReason,
    durationMs: durationMs,
    messageCount: state.messageCount || 0,
  });
  
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, val] of sessionStore.entries()) {
    if (!val || now - val.updatedAt > SESSION_TTL_MS) sessionStore.delete(key);
  }
}, 1000 * 60 * 15);

// Background timer for abandonment detection
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, state] of conversationStateMap.entries()) {
    if (!state.ended && (now - state.lastActivityAt) > ABANDON_TIMEOUT_MS) {
      endConversation(sessionId, "abandoned");
    }
  }
}, 60 * 1000); // Check every 60 seconds

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

// ---- Tracking URL normalization ----
function normalizeTrackingLink(trackingUrl, carrier, trackingNumber) {
  // If trackingUrl exists, normalize it
  if (trackingUrl) {
    const trimmed = String(trackingUrl).trim();
    if (!trimmed) {
      // Empty string, fall through to carrier logic
    } else if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      return trimmed;
    } else if (trimmed.startsWith("www.")) {
      return "https://" + trimmed;
    } else if (trimmed.includes(".") && !trimmed.includes(" ")) {
      // Looks like a domain/path (contains a dot and no spaces)
      return "https://" + trimmed;
    }
    // If trackingUrl exists but doesn't match patterns, fall through to carrier logic
  }
  
  // If carrier + trackingNumber exist, build carrier-specific URL
  if (carrier && trackingNumber) {
    const carrierLower = String(carrier).toLowerCase();
    const tracking = String(trackingNumber).trim();
    if (!tracking) return null;
    
    // Carrier matching (case-insensitive, tolerant)
    if (carrierLower.includes("postnl")) {
      return `https://www.postnl.nl/tracktrace/?B=${encodeURIComponent(tracking)}`;
    }
    if (carrierLower.includes("dhl")) {
      return `https://www.dhl.com/nl-nl/home/tracking.html?tracking-id=${encodeURIComponent(tracking)}`;
    }
    if (carrierLower.includes("dpd")) {
      return `https://www.dpd.com/nl/nl/ontvangen/track-en-trace/?shipmentNumber=${encodeURIComponent(tracking)}`;
    }
    if (carrierLower.includes("ups")) {
      return `https://wwwapps.ups.com/WebTracking/track?track=yes&trackNums=${encodeURIComponent(tracking)}`;
    }
    if (carrierLower.includes("gls")) {
      return `https://gls-group.com/NL/nl/pakket-volgen/?match=${encodeURIComponent(tracking)}`;
    }
    
    // Unknown carrier: fall back to neutral tracking page
    return `https://www.17track.net/en#nums=${encodeURIComponent(tracking)}`;
  }
  
  return null;
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

    const trackingNumber =
      fulfillment && fulfillment.tracking_numbers && fulfillment.tracking_numbers[0]
        ? fulfillment.tracking_numbers[0]
        : null;
    const trackingUrlRaw =
      fulfillment && fulfillment.tracking_urls && fulfillment.tracking_urls[0]
        ? fulfillment.tracking_urls[0]
        : null;
    const carrier =
      fulfillment && fulfillment.tracking_company
        ? fulfillment.tracking_company
        : null;

    const trackingUrlNormalized = normalizeTrackingLink(trackingUrlRaw, carrier, trackingNumber);

    return {
      orderName: order.name || null,
      fulfillmentStatus: order.fulfillment_status || null,
      financialStatus: order.financial_status || null,
      tracking: trackingNumber,
      trackingUrl: trackingUrlNormalized,
      carrier: carrier,
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

// ---- Client Registry & Validation ----
const clientRegistry = new Map();

const REQUIRED_CLIENT_FILES = [
  "Brand voice.md",
  "Customer support rules.md",
  "client-config.json",
];

const OPTIONAL_CLIENT_FILES = [
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

function normalizeClientConfig(rawCfg, clientId) {
  const normalized = {
    brandName: String(rawCfg.brandName || clientId || "Support").trim(),
    assistantName: String(rawCfg.assistantName || rawCfg.brandName || clientId || "Support").trim(),
    logoUrl: rawCfg.logoUrl ? String(rawCfg.logoUrl).trim() : null,
    language: String(rawCfg.language || "nl").trim(),
    noEmojis: rawCfg.noEmojis !== false,
    version: rawCfg.version ? String(rawCfg.version).trim() : null,
    supportEmail: rawCfg.supportEmail ? String(rawCfg.supportEmail).trim() : null,
    contactFormUrl: rawCfg.contactFormUrl ? String(rawCfg.contactFormUrl).trim() : null,
    features: rawCfg.features && typeof rawCfg.features === "object" ? rawCfg.features : {},
  };

  // Widget config with defaults
  const widgetTitle = rawCfg.widget && rawCfg.widget.title
    ? String(rawCfg.widget.title).trim()
    : (rawCfg.widgetTitle ? String(rawCfg.widgetTitle).trim() : normalized.brandName);
  const widgetGreeting = rawCfg.widget && rawCfg.widget.greeting
    ? String(rawCfg.widget.greeting).trim()
    : (rawCfg.widgetGreeting ? String(rawCfg.widgetGreeting).trim() : `Hallo! Waar kan ik je mee helpen?`);

  normalized.widget = {
    title: widgetTitle,
    greeting: widgetGreeting,
  };

  // Colors with defaults
  normalized.colors = {
    primary: String(rawCfg.colors && rawCfg.colors.primary ? rawCfg.colors.primary : (rawCfg.primaryColor || "#000000")).trim(),
    accent: String(rawCfg.colors && rawCfg.colors.accent ? rawCfg.colors.accent : (rawCfg.accentColor || "#2563eb")).trim(),
    background: String(rawCfg.colors && rawCfg.colors.background ? rawCfg.colors.background : "#ffffff").trim(),
    userBubble: String(rawCfg.colors && rawCfg.colors.userBubble ? rawCfg.colors.userBubble : (rawCfg.colors && rawCfg.colors.primary ? rawCfg.colors.primary : (rawCfg.primaryColor || "#000000"))).trim(),
    botBubble: String(rawCfg.colors && rawCfg.colors.botBubble ? rawCfg.colors.botBubble : "#ffffff").trim(),
  };

  // Entry screen with defaults
  if (rawCfg.entryScreen && typeof rawCfg.entryScreen === "object") {
    normalized.entryScreen = {
      enabled: rawCfg.entryScreen.enabled === true,
      title: rawCfg.entryScreen.title ? String(rawCfg.entryScreen.title).trim() : null,
      disclaimer: rawCfg.entryScreen.disclaimer ? String(rawCfg.entryScreen.disclaimer).trim() : null,
      primaryButton: rawCfg.entryScreen.primaryButton && typeof rawCfg.entryScreen.primaryButton === "object"
        ? {
            label: rawCfg.entryScreen.primaryButton.label ? String(rawCfg.entryScreen.primaryButton.label).trim() : "Start chat",
            action: rawCfg.entryScreen.primaryButton.action ? String(rawCfg.entryScreen.primaryButton.action).trim() : "openChat",
          }
        : null,
      secondaryButtons: Array.isArray(rawCfg.entryScreen.secondaryButtons)
        ? rawCfg.entryScreen.secondaryButtons.slice(0, 2).map(btn => ({
            label: btn.label ? String(btn.label).trim() : "",
            action: btn.action ? String(btn.action).trim() : "",
            url: btn.url ? String(btn.url).trim() : "",
          })).filter(btn => btn.label && btn.action)
        : [],
    };
  } else {
    normalized.entryScreen = { enabled: false };
  }

  return normalized;
}

function validateClientFolder(clientId) {
  const base = `./Clients/${clientId}`;
  const missingFiles = [];
  const errors = [];

  if (!fs.existsSync(base)) {
    return { valid: false, missingFiles: ["folder"], errors: [`Client folder not found: ${clientId}`] };
  }

  if (!fs.statSync(base).isDirectory()) {
    return { valid: false, missingFiles: [], errors: [`Path exists but is not a directory: ${clientId}`] };
  }

  for (const file of REQUIRED_CLIENT_FILES) {
    const filePath = `${base}/${file}`;
    if (!fs.existsSync(filePath)) {
      missingFiles.push(file);
    }
  }

  if (missingFiles.length > 0) {
    errors.push(`Missing required files: ${missingFiles.join(", ")}`);
  }

  const clientConfigPath = `${base}/client-config.json`;
  if (fs.existsSync(clientConfigPath)) {
    try {
      const configRaw = readFile(clientConfigPath);
      const config = safeJsonParse(configRaw, null);
      if (!config || typeof config !== "object") {
        errors.push("client-config.json is not valid JSON");
      }
    } catch (e) {
      errors.push(`client-config.json parse error: ${e && e.message ? e.message : String(e)}`);
    }
  }

  return {
    valid: missingFiles.length === 0 && errors.length === 0,
    missingFiles,
    errors,
  };
}

function initializeClientRegistry() {
  const clientsDir = "./Clients";
  if (!fs.existsSync(clientsDir)) {
    logJson("warn", "client_registry_init", { error: "Clients directory not found" });
    return;
  }

  try {
    const entries = fs.readdirSync(clientsDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (entry.name.startsWith(".")) continue;

      const clientId = entry.name;
      const validation = validateClientFolder(clientId);

      if (!validation.valid) {
        logJson("warn", "client_validation_failed", {
          clientId: clientId,
          missingFiles: validation.missingFiles,
          errors: validation.errors,
        });
        clientRegistry.set(clientId, {
          status: "invalid",
          missingFiles: validation.missingFiles,
          validationErrors: validation.errors,
        });
        continue;
      }

      try {
        const base = `./Clients/${clientId}`;
        const configRaw = readFile(`${base}/client-config.json`);
        const config = safeJsonParse(configRaw, {});
        const normalizedConfig = normalizeClientConfig(config, clientId);

        clientRegistry.set(clientId, {
          status: "ok",
          config: normalizedConfig,
        });
      } catch (e) {
        logJson("warn", "client_config_normalize_failed", {
          clientId: clientId,
          error: e && e.message ? e.message : String(e),
        });
        clientRegistry.set(clientId, {
          status: "invalid",
          validationErrors: [e && e.message ? e.message : "Config normalization failed"],
        });
      }
    }

    const validCount = Array.from(clientRegistry.values()).filter(c => c.status === "ok").length;
    logJson("info", "client_registry_initialized", {
      totalClients: clientRegistry.size,
      validClients: validCount,
    });
  } catch (e) {
    logJson("error", "client_registry_init_error", {
      error: e && e.message ? e.message : String(e),
    });
  }
}

function getClientOrNull(clientIdRaw) {
  const clientId = sanitizeClientId(clientIdRaw);
  const entry = clientRegistry.get(clientId);
  if (!entry) return null;
  if (entry.status !== "ok") return null;
  return { clientId, config: entry.config };
}

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

// ---- Canonical support settings (single source of truth) ----
function getSupportSettings(clientConfig) {
  const email =
    (clientConfig && clientConfig.supportEmail) ||
    (clientConfig && clientConfig.support && clientConfig.support.email) ||
    null;

  const contactFormUrl =
    (clientConfig && clientConfig.contactFormUrl) ||
    (clientConfig && clientConfig.support && clientConfig.support.contactFormUrl) ||
    null;

  const escalationMessage =
    (clientConfig && clientConfig.support && clientConfig.support.escalationMessage) ||
    (clientConfig && clientConfig.escalationMessage) ||
    "";

  return {
    email: email ? String(email).trim() : null,
    contactFormUrl: contactFormUrl ? String(contactFormUrl).trim() : null,
    escalationMessage: escalationMessage ? String(escalationMessage).trim() : "",
  };
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

  const support = getSupportSettings(clientConfig);

  const entryScreen = clientConfig.entryScreen || null;

  return {
    brandName,
    assistantName: clientConfig.assistantName || widgetTitle,
    language: clientConfig.language || "nl",
    noEmojis: clientConfig.noEmojis !== false,
    logoUrl,
    widget: { title: widgetTitle, greeting: widgetGreeting },
    colors,
    entryScreen,
    support: {
      email: support.email,
      contactFormUrl: support.contactFormUrl,
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

  const isEn = String(language || "nl").toLowerCase().startsWith("en");
  const attempt = attemptNumber || 1;
  
  if (attempt >= 2) {
    // Second attempt: shorter and more explicit
    const nl2 = {
      orderNumber: "Ik heb je bestelnummer echt nodig om je te helpen. Wat is je bestelnummer?",
      emailOrOrder: "Ik heb je bestelnummer of e-mailadres nodig om je te helpen. Wat is je bestelnummer of e-mailadres?",
      productName: "Ik heb echt nodig te weten welk product je bedoelt. Welk product is het?",
      problemDetails: "Ik heb meer details nodig om je te helpen. Wat gaat er precies mis?",
    };
    const en2 = {
      orderNumber: "I really need your order number to help you. What is your order number?",
      emailOrOrder: "I need your order number or email address to help you. What is your order number or email address?",
      productName: "I really need to know which product you mean. Which product is it?",
      problemDetails: "I need more details to help you. What exactly is going wrong?",
    };
    const dict2 = isEn ? en2 : nl2;
    if (slot && dict2[slot]) return dict2[slot];
    if (intent === "shipping_or_order") return dict2.orderNumber;
    if (intent === "return_or_withdrawal") return dict2.emailOrOrder;
    return dict2.problemDetails;
  }
  
  // First attempt: normal clarification question
  const dict = isEn ? en : nl;
  if (slot && dict[slot]) return dict[slot];
  if (intent === "shipping_or_order") return dict.orderNumber;
  if (intent === "return_or_withdrawal") return dict.emailOrOrder;
  return dict.problemDetails;
}

function buildFollowUpQuestion(language, intent, slot, attemptNumber) {
  const isEn = String(language || "nl").toLowerCase().startsWith("en");
  const attempt = attemptNumber || 1;
  
  const nl = {
    orderNumber: "Wat is je bestelnummer? Bijvoorbeeld #1055.",
    emailOrOrder: "Wat is je bestelnummer? Als je die niet hebt: met welk e-mailadres heb je besteld?",
    productName: "Welk product bedoel je precies?",
    problemDetails: "Wat gaat er precies mis, en wat heb je al geprobeerd?",
  };
  const en = {
    orderNumber: "What is your order number? For example #1055.",
    emailOrOrder: "What is your order number? If you don't have it: what email address did you order with?",
    productName: "Which product is it exactly?",
    problemDetails: "What exactly is going wrong, and what have you tried already?",
  };
  
  if (attempt >= 2) {
    // Second attempt: shorter and more explicit
    const nl2 = {
      orderNumber: "Ik heb je bestelnummer echt nodig om je te helpen. Wat is je bestelnummer?",
      emailOrOrder: "Ik heb je bestelnummer of e-mailadres nodig om je te helpen. Wat is je bestelnummer of e-mailadres?",
      productName: "Ik heb echt nodig te weten welk product je bedoelt. Welk product is het?",
      problemDetails: "Ik heb meer details nodig om je te helpen. Wat gaat er precies mis?",
    };
    const en2 = {
      orderNumber: "I really need your order number to help you. What is your order number?",
      emailOrOrder: "I need your order number or email address to help you. What is your order number or email address?",
      productName: "I really need to know which product you mean. Which product is it?",
      problemDetails: "I need more details to help you. What exactly is going wrong?",
    };
    const dict2 = isEn ? en2 : nl2;
    if (slot && dict2[slot]) return dict2[slot];
    if (intent === "shipping_or_order") return dict2.orderNumber;
    if (intent === "return_or_withdrawal") return dict2.emailOrOrder;
    return dict2.problemDetails;
  }
  
  // First attempt: normal clarification question
  const dict = isEn ? en : nl;
  if (slot && dict[slot]) return dict[slot];
  if (intent === "shipping_or_order") return dict.orderNumber;
  if (intent === "return_or_withdrawal") return dict.emailOrOrder;
  return dict.problemDetails;
}

function buildMissingInfoEscalationReply(clientConfig, clientId) {
  const lang = clientConfig.language || "nl";
  const support = getSupportSettings(clientConfig);
  const email = support.email || "";
  const contactUrl = support.contactFormUrl || "";
  
  if (String(lang).toLowerCase().startsWith("en")) {
    let msg = "I'd like to help you, but I'm missing important information to resolve this properly. I'm transferring you to our support team so you can get help quickly.";
    if (email) msg += `\n\nEmail: ${email}`;
    if (contactUrl) msg += `\nContact form: ${contactUrl}`;
    return msg;
  }
  
  let msg = "Ik wil je graag helpen, maar ik mis belangrijke informatie om dit goed op te lossen. Ik zet je door naar onze support zodat je snel geholpen wordt.";
  if (email) msg += `\n\nE-mail: ${email}`;
  if (contactUrl) msg += `\nContactformulier: ${contactUrl}`;
  return msg;
}

function isKnowledgeInsufficient(contextString, topChunks) {
  // Check if context is empty or indicates no knowledge
  if (!contextString || !contextString.trim()) return true;
  if (contextString.trim() === "No relevant knowledge matched.") return true;
  
  // Check if very short (below minimal threshold for meaningful content)
  // Threshold: less than 100 characters likely indicates insufficient knowledge
  if (contextString.trim().length < 100) return true;
  
  // Check if topChunks is empty or very few chunks with low scores
  if (!topChunks || topChunks.length === 0) return true;
  
  return false;
}

function buildKnowledgeGapClarificationReply(language) {
  const isEn = String(language || "nl").toLowerCase().startsWith("en");
  if (isEn) {
    return "I want to help you well, but I'm missing some context. What product/topic is your question about exactly?";
  }
  return "Ik wil je goed helpen, maar ik mis nog wat context. Over welk product/onderwerp gaat je vraag precies?";
}

function buildKnowledgeGapEscalationReply(clientConfig, clientId) {
  const lang = clientConfig.language || "nl";
  const support = getSupportSettings(clientConfig);
  const email = support.email || "";
  const contactUrl = support.contactFormUrl || "";
  
  if (String(lang).toLowerCase().startsWith("en")) {
    let msg = "I'd like to help you properly, but I don't have the right information in my knowledge base to resolve this reliably. I'm transferring you to our support so you can get the right help directly.";
    if (email) msg += `\n\nEmail: ${email}`;
    if (contactUrl) msg += `\nContact form: ${contactUrl}`;
    return msg;
  }
  
  let msg = "Ik wil je graag goed helpen, maar ik heb niet de juiste informatie in mijn kennisbank om dit betrouwbaar op te lossen. Ik zet je door naar onze support zodat je direct de juiste hulp krijgt.";
  if (email) msg += `\n\nE-mail: ${email}`;
  if (contactUrl) msg += `\nContactformulier: ${contactUrl}`;
  return msg;
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

function maybeHandleWithRouter({ sessionId, message, intent, clientConfig, clientId }) {
  const lang = clientConfig.language || "nl";
  const meta = getMeta(sessionId);
  const facts = getFacts(sessionId);
  const expected = meta.expectedSlot || "";
  const clarificationType = meta.clarificationType || null;
  const clarificationAttemptCount = meta.clarificationAttemptCount || 0;

  // If we're awaiting clarification, try to capture the info
  if (expected) {
    const beforeCapture = {
      orderNumber: facts.orderNumber || null,
      email: facts.email || null,
      productName: facts.productName || null,
      problemDetails: facts.problemDetails || null,
    };
    
    captureFactsFromExpectedSlot(sessionId, expected, message);
    
    // Check if we successfully captured the info
    const afterCapture = {
      orderNumber: getFacts(sessionId).orderNumber || null,
      email: getFacts(sessionId).email || null,
      productName: getFacts(sessionId).productName || null,
      problemDetails: getFacts(sessionId).problemDetails || null,
    };
    
    const infoCaptured = (
      (expected === "orderNumber" && afterCapture.orderNumber && !beforeCapture.orderNumber) ||
      (expected === "emailOrOrder" && ((afterCapture.orderNumber && !beforeCapture.orderNumber) || (afterCapture.email && !beforeCapture.email))) ||
      (expected === "productName" && afterCapture.productName && !beforeCapture.productName) ||
      (expected === "problemDetails" && afterCapture.problemDetails && !beforeCapture.problemDetails)
    );
    
    if (infoCaptured) {
      // Successfully captured the info, reset clarification state
      clearExpectedSlot(sessionId);
      setMeta(sessionId, { clarificationType: null, clarificationAttemptCount: 0 });
      return { handled: false, clarificationResolved: true };
    } else {
      // Info still missing, increment attempt count
      const newAttemptCount = clarificationAttemptCount + 1;
      setMeta(sessionId, { clarificationAttemptCount: newAttemptCount });
      
      // Check if we've exceeded max attempts
      if (newAttemptCount >= 2) {
        // Escalate to human support
        clearExpectedSlot(sessionId);
        setMeta(sessionId, { clarificationType: null, clarificationAttemptCount: 0 });
        return {
          handled: true,
          reply: buildMissingInfoEscalationReply(clientConfig, clientId),
          escalateReason: "missing_required_info",
        };
      }
      
      // Ask clarification again (second attempt with shorter message)
      return {
        handled: true,
        reply: buildFollowUpQuestion(lang, meta.lastIntent || intent.mainIntent, expected, newAttemptCount),
        clarificationRequired: true,
        clarificationType: expected,
        clarificationAttemptCount: newAttemptCount,
      };
    }
  }

  // Check for catastrophic physical damage/defect before other routing
  if (isCatastrophicIssue(message)) {
    const reply = buildCatastrophicIssueReply(clientConfig, clientId);
    return { handled: true, reply };
  }

  if (intent.orderNumber) setFacts(sessionId, { orderNumber: intent.orderNumber });

  if (intent.mainIntent === "shipping_or_order") {
    const orderKnown = intent.orderNumber || facts.orderNumber;
    if (!orderKnown) {
      const newAttemptCount = (clarificationType === "orderNumber" ? clarificationAttemptCount : 0) + 1;
      setMeta(sessionId, {
        expectedSlot: "orderNumber",
        lastIntent: intent.mainIntent,
        clarificationType: "orderNumber",
        clarificationAttemptCount: newAttemptCount,
      });
      return {
        handled: true,
        reply: buildFollowUpQuestion(lang, intent.mainIntent, "orderNumber", newAttemptCount),
        clarificationRequired: true,
        clarificationType: "orderNumber",
        clarificationAttemptCount: newAttemptCount,
      };
    }
  }

  if (intent.mainIntent === "return_or_withdrawal") {
    const orderKnown = intent.orderNumber || facts.orderNumber;
    const emailKnown = facts.email;
    if (!orderKnown && !emailKnown) {
      const newAttemptCount = (clarificationType === "emailOrOrder" ? clarificationAttemptCount : 0) + 1;
      setMeta(sessionId, {
        expectedSlot: "emailOrOrder",
        lastIntent: intent.mainIntent,
        clarificationType: "emailOrOrder",
        clarificationAttemptCount: newAttemptCount,
      });
      return {
        handled: true,
        reply: buildFollowUpQuestion(lang, intent.mainIntent, "emailOrOrder", newAttemptCount),
        clarificationRequired: true,
        clarificationType: "emailOrOrder",
        clarificationAttemptCount: newAttemptCount,
      };
    }
  }

  if ((intent.mainIntent === "product_usage" || intent.mainIntent === "general") && isTroubleshootingLike(message)) {
    if (!facts.productName) {
      const newAttemptCount = (clarificationType === "productName" ? clarificationAttemptCount : 0) + 1;
      setMeta(sessionId, {
        expectedSlot: "productName",
        lastIntent: "product_troubleshooting",
        clarificationType: "productName",
        clarificationAttemptCount: newAttemptCount,
      });
      return {
        handled: true,
        reply: buildFollowUpQuestion(lang, "product_usage", "productName", newAttemptCount),
        clarificationRequired: true,
        clarificationType: "productName",
        clarificationAttemptCount: newAttemptCount,
      };
    }
    if (!facts.problemDetails) {
      const newAttemptCount = (clarificationType === "problemDetails" ? clarificationAttemptCount : 0) + 1;
      setMeta(sessionId, {
        expectedSlot: "problemDetails",
        lastIntent: "product_troubleshooting",
        clarificationType: "problemDetails",
        clarificationAttemptCount: newAttemptCount,
      });
      return {
        handled: true,
        reply: buildFollowUpQuestion(lang, "product_usage", "problemDetails", newAttemptCount),
        clarificationRequired: true,
        clarificationType: "problemDetails",
        clarificationAttemptCount: newAttemptCount,
      };
    }
  }

  // Reset clarification state if we're not asking for clarification
  if (clarificationType || clarificationAttemptCount > 0) {
    setMeta(sessionId, { clarificationType: null, clarificationAttemptCount: 0 });
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

// ---- Catastrophic physical damage detection ----
function isCatastrophicIssue(message) {
  const t = normalizeText(message);
  
  // Dutch catastrophic keywords/phrases (specific damage indicators, not vague "kapot" alone)
  const dutchCatastrophic = [
    "afgebroken",
    "gebroken",
    "gescheurd",
    "gekraakt",
    "gebarsten",
    "lekkage",
    "onderdeel ontbreekt",
    "valt uit elkaar",
    "ring is afgebroken",
    "is gebarsten",
    "is gescheurd",
    "is kapot gegaan",
    "stuk",
  ];
  
  // English catastrophic keywords/phrases
  const englishCatastrophic = [
    "snapped",
    "cracked",
    "torn",
    "leaking",
    "missing part",
    "fell apart",
    "defective out of the box",
    "broken part",
  ];
  
  // Check for catastrophic keywords - require explicit physical damage language
  const hasDutchCatastrophic = dutchCatastrophic.some((k) => t.includes(k));
  const hasEnglishCatastrophic = englishCatastrophic.some((k) => t.includes(k));
  
  // Conservative: only escalate if explicit physical damage indicators are present
  // Note: "kapot" alone is excluded as it can mean "not working" (troubleshootable)
  return hasDutchCatastrophic || hasEnglishCatastrophic;
}

function buildCatastrophicIssueReply(clientConfig, clientId) {
  const lang = clientConfig.language || "nl";
  const support = getSupportSettings(clientConfig);
  const email = support.email || "";
  const contactUrl = support.contactFormUrl || "";
  
  if (String(lang).toLowerCase().startsWith("en")) {
    let msg = "That sounds like physical damage or a defect. Unfortunately, I can't resolve this directly via chat. Please contact our support team, and they'll help you further.";
    if (email) msg += `\n\nEmail: ${email}`;
    if (contactUrl) msg += `\nContact form: ${contactUrl}`;
    return msg;
  }
  
  let msg = "Dat klinkt als fysieke schade/defect. Dit kan ik helaas niet direct voor je oplossen via de chat. Neem contact op met onze support, dan helpen zij je verder.";
  if (email) msg += `\n\nE-mail: ${email}`;
  if (contactUrl) msg += `\nContactformulier: ${contactUrl}`;
  return msg;
}

function buildEscalationReply(clientConfig, clientId) {
  const lang = clientConfig.language || "nl";
  const brandName = clientConfig.brandName || clientId;

  const support = getSupportSettings(clientConfig);
  const email = support.email || "";
  const contactUrl = support.contactFormUrl || "";
  const custom = support.escalationMessage || "";

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

  const support = getSupportSettings(clientConfig);

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
    email: support.email,
    contactFormUrl: support.contactFormUrl,
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
  return res.json({ ok: true, message: "AI support backend running.", requestId: req.requestId, status: "ok" });
});

app.get("/health", (req, res) => {
  const version = process.env.VERSION || process.env.RENDER_GIT_COMMIT || BUILD_VERSION || "unknown";
  return res.json({
    status: "ok",
    requestId: req.requestId,
    uptimeSec: Math.round(process.uptime()),
    version: version,
    timestamp: nowIso(),
  });
});

app.get("/widget-config", (req, res) => {
  const clientIdRaw = req.query.client;
  
  if (!clientIdRaw || !String(clientIdRaw).trim()) {
    res.status(400);
    return res.json({
      requestId: req.requestId,
      error: "missing_client",
      message: "Client parameter is required",
    });
  }

  const clientId = sanitizeClientId(clientIdRaw);
  const clientEntry = getClientOrNull(clientId);

  if (!clientEntry) {
    res.status(404);
    return res.json({
      requestId: req.requestId,
      error: "invalid_client",
      message: "Deze chat is niet juist geconfigureerd. Neem contact op met support.",
    });
  }

  try {
    const widgetConfig = buildWidgetConfig(clientEntry.config, clientEntry.clientId);
    res.setHeader("Cache-Control", "public, max-age=300");

    return res.json({ requestId: req.requestId, ...widgetConfig });
  } catch (e) {
    logJson("error", "widget_config_error", {
      requestId: req.requestId,
      route: "/widget-config",
      method: "GET",
      clientId: clientId,
      error: e && e.message ? e.message : String(e),
      errorStack: e && e.stack ? String(e.stack).slice(0, 500) : null,
    });

    res.status(500);
    return res.json({ requestId: req.requestId, error: "Server error" });
  }
});

app.post("/chat", async (req, res) => {
  const ip = getClientIp(req);

  let clientId = "Advantum";
  let sessionId = "";
  let effectiveIntent = null;

  let shopifyLookupAttempted = false;
  let shopifyFound = null;
  let shopifyError = null;
  let shopifyMs = 0;
  let llmLatencyMs = 0;
  let tokenUsage = null;
  let llmModel = null;
  let routedTo = "bot";
  let escalateReason = null;

  // Initialize metrics object
  res.locals.chatMetrics = {
    intent: null,
    routedTo: "bot",
    escalateReason: null,
    conversationId: null,
    clarificationRequired: false,
    clarificationType: null,
    clarificationAttemptCount: null,
    knowledgeGapDetected: false,
    knowledgeGapTopic: null,
    knowledgeGapClarificationAsked: false,
    knowledgeGapClarificationCount: 0,
    shopifyLookupAttempted: false,
    shopifyFound: null,
    shopifyError: null,
    llmProvider: "openai",
    llmModel: null,
    llmLatencyMs: 0,
    tokenUsage: null,
  };

  try {
    const message = sanitizeUserMessage(req.body.message);
    if (!message) {
      res.status(400);
      return res.json({ requestId: req.requestId, error: "Invalid message" });
    }

    const clientIdRaw = req.query.client;
    if (!clientIdRaw || !String(clientIdRaw).trim()) {
      res.status(400);
      return res.json({
        requestId: req.requestId,
        reply: "Deze chat is niet juist geconfigureerd. Neem contact op met support.",
        error: "missing_client",
      });
    }

    clientId = sanitizeClientId(clientIdRaw);
    sessionId = sanitizeSessionId(req.body.sessionId);

    // Get or create conversation state
    const convState = getOrCreateConversation(sessionId, clientId);
    const conversationId = convState ? convState.conversationId : sessionId;
    updateConversationActivity(sessionId);

    const clientEntry = getClientOrNull(clientId);
    if (!clientEntry) {
      res.status(404);
      return res.json({
        requestId: req.requestId,
        reply: "Deze chat is niet juist geconfigureerd. Neem contact op met support.",
        error: "invalid_client",
      });
    }

    let data;
    try {
      data = loadClient(clientId);
    } catch (e) {
      logJson("error", "load_client_failed", {
        requestId: req.requestId,
        clientId: clientId,
        error: e && e.message ? e.message : String(e),
      });
      res.status(404);
      return res.json({
        requestId: req.requestId,
        reply: "Deze chat is niet juist geconfigureerd. Neem contact op met support.",
        error: "invalid_client",
      });
    }

    // Use normalized config from registry
    data.clientConfig = clientEntry.config;

    const intentRaw = detectIntent(message);
    effectiveIntent = intentRaw;

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

      routedTo = "human";
      escalateReason = escalation.hasUrgent ? "urgent" : "angry";
      // Store escalateReason in meta for conversation_end log
      setMeta(sessionId, { escalateReason: escalateReason });
      // End conversation with escalation outcome
      endConversation(sessionId, "escalated_to_human");
      
      res.locals.chatMetrics = {
        intent: { ...intentRaw, mainIntent: "support_escalation" },
        routedTo: "human",
        escalateReason: escalateReason,
        conversationId: conversationId,
        clarificationRequired: false,
        clarificationType: null,
        clarificationAttemptCount: null,
        knowledgeGapDetected: false,
        knowledgeGapTopic: null,
        knowledgeGapClarificationAsked: false,
        knowledgeGapClarificationCount: 0,
        shopifyLookupAttempted: false,
        shopifyFound: null,
        shopifyError: null,
        llmProvider: "openai",
        llmModel: null,
        llmLatencyMs: 0,
        tokenUsage: null,
      };

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
      clientId: data.clientId,
    });

    if (router.handled) {
      appendToHistory(sessionId, "assistant", router.reply);

      // Check if catastrophic issue (router may have handled it)
      if (isCatastrophicIssue(message)) {
        routedTo = "human";
        escalateReason = "catastrophic";
        // Store escalateReason in meta for conversation_end log
        setMeta(sessionId, { escalateReason: "catastrophic" });
        // End conversation with escalation outcome
        endConversation(sessionId, "escalated_to_human");
      }
      
      // Check if escalation due to missing required info
      if (router.escalateReason === "missing_required_info") {
        routedTo = "human";
        escalateReason = "missing_required_info";
        // Store escalateReason in meta for conversation_end log
        setMeta(sessionId, { escalateReason: "missing_required_info" });
        // End conversation with escalation outcome
        endConversation(sessionId, "escalated_to_human");
      }

      res.locals.chatMetrics = {
        intent: intentRaw,
        routedTo: router.escalateReason ? "human" : routedTo,
        escalateReason: router.escalateReason || escalateReason,
        conversationId: conversationId,
        clarificationRequired: router.clarificationRequired || false,
        clarificationType: router.clarificationType || null,
        clarificationAttemptCount: router.clarificationAttemptCount || null,
        knowledgeGapDetected: false,
        knowledgeGapTopic: null,
        knowledgeGapClarificationAsked: false,
        knowledgeGapClarificationCount: 0,
        shopifyLookupAttempted: false,
        shopifyFound: null,
        shopifyError: null,
        llmProvider: "openai",
        llmModel: null,
        llmLatencyMs: 0,
        tokenUsage: null,
      };

      return res.json({
        requestId: req.requestId,
        reply: router.reply,
        intent: intentRaw,
        shopify: null,
        routed: true,
        escalated: (router.escalateReason || escalateReason) !== null,
        facts: getFacts(sessionId),
      });
    }

    const facts = getFacts(sessionId);
    effectiveIntent = {
      ...intentRaw,
      orderNumber: intentRaw.orderNumber || facts.orderNumber || "",
    };

    if (effectiveIntent.mainIntent === "shipping_or_order" && effectiveIntent.orderNumber && !looksLikeShopifyOrderName(effectiveIntent.orderNumber)) {
      const reply = buildOrderNotFoundReply(data.clientConfig || {}, data.clientId, effectiveIntent.orderNumber);
      appendToHistory(sessionId, "assistant", reply);

      res.locals.chatMetrics = {
        intent: effectiveIntent,
        routedTo: "bot",
        escalateReason: null,
        conversationId: conversationId,
        clarificationRequired: false,
        clarificationType: null,
        clarificationAttemptCount: null,
        knowledgeGapDetected: false,
        knowledgeGapTopic: null,
        knowledgeGapClarificationAsked: false,
        knowledgeGapClarificationCount: 0,
        shopifyLookupAttempted: false,
        shopifyFound: null,
        shopifyError: null,
        llmProvider: "openai",
        llmModel: null,
        llmLatencyMs: 0,
        tokenUsage: null,
      };

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
      shopifyLookupAttempted = true;
      const tShop0 = Date.now();
      try {
        shopify = await lookupShopifyOrder(effectiveIntent.orderNumber);
        shopifyMs = Date.now() - tShop0;
        shopifyFound = shopify !== null;
      } catch (e) {
        shopifyMs = Date.now() - tShop0;
        shopifyFound = null;
        shopifyError = e && e.message ? e.message : String(e);
      }

      if (!shopify) {
        const reply = buildOrderNotFoundReply(data.clientConfig || {}, data.clientId, effectiveIntent.orderNumber);
        appendToHistory(sessionId, "assistant", reply);

        res.locals.chatMetrics = {
          intent: effectiveIntent,
          routedTo: "bot",
          escalateReason: null,
          conversationId: conversationId,
          clarificationRequired: false,
          clarificationType: null,
          clarificationAttemptCount: null,
          knowledgeGapDetected: false,
          knowledgeGapTopic: null,
          knowledgeGapClarificationAsked: false,
          knowledgeGapClarificationCount: 0,
          shopifyLookupAttempted: true,
          shopifyFound: false,
          shopifyError: shopifyError,
          llmProvider: "openai",
          llmModel: null,
          llmLatencyMs: 0,
          tokenUsage: null,
        };

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
    const currentMeta = getMeta(sessionId);
    
    // Knowledge gap detection (only if not already handling missing info clarification)
    const knowledgeGapClarificationAsked = currentMeta.knowledgeGapClarificationAsked || false;
    const knowledgeInsufficient = isKnowledgeInsufficient(context, topChunks);
    
    if (knowledgeInsufficient && !currentMeta.expectedSlot) {
      // Only check knowledge gap if we're not already asking for missing info clarification
      if (!knowledgeGapClarificationAsked) {
        // First time detecting knowledge gap: ask one clarification
        const knowledgeGapTopic = effectiveIntent.mainIntent || "unknown";
        setMeta(sessionId, {
          knowledgeGapClarificationAsked: true,
          knowledgeGapTopic: knowledgeGapTopic,
          knowledgeGapDetectedCount: (currentMeta.knowledgeGapDetectedCount || 0) + 1,
          lastKnowledgeGapAt: Date.now(),
        });
        
        const reply = buildKnowledgeGapClarificationReply(data.clientConfig.language || "nl");
        appendToHistory(sessionId, "assistant", reply);
        
        logJson("info", "knowledge_gap", {
          requestId: req.requestId,
          conversationId: conversationId,
          clientId: clientId,
          sessionId: sessionId,
          knowledgeGapTopic: knowledgeGapTopic,
        });
        
        res.locals.chatMetrics = {
          intent: effectiveIntent,
          routedTo: "bot",
          escalateReason: null,
          conversationId: conversationId,
          clarificationRequired: false,
          clarificationType: null,
          clarificationAttemptCount: null,
          knowledgeGapDetected: true,
          knowledgeGapTopic: knowledgeGapTopic,
          knowledgeGapClarificationAsked: true,
          knowledgeGapClarificationCount: 1,
          shopifyLookupAttempted: shopifyLookupAttempted,
          shopifyFound: shopifyFound,
          shopifyError: shopifyError,
          llmProvider: "openai",
          llmModel: null,
          llmLatencyMs: 0,
          tokenUsage: null,
        };
        
        return res.json({
          requestId: req.requestId,
          reply,
          intent: effectiveIntent,
          shopify,
          routed: true,
          escalated: false,
          facts: getFacts(sessionId),
        });
      } else {
        // Already asked clarification once, now escalate
        const knowledgeGapTopic = currentMeta.knowledgeGapTopic || effectiveIntent.mainIntent || "unknown";
        const reply = buildKnowledgeGapEscalationReply(data.clientConfig || {}, data.clientId);
        appendToHistory(sessionId, "assistant", reply);
        
        // Store escalateReason in meta for conversation_end log
        setMeta(sessionId, { escalateReason: "knowledge_gap" });
        // End conversation with escalation outcome
        endConversation(sessionId, "escalated_to_human");
        
        res.locals.chatMetrics = {
          intent: effectiveIntent,
          routedTo: "human",
          escalateReason: "knowledge_gap",
          conversationId: conversationId,
          clarificationRequired: false,
          clarificationType: null,
          clarificationAttemptCount: null,
          knowledgeGapDetected: true,
          knowledgeGapTopic: knowledgeGapTopic,
          knowledgeGapClarificationAsked: true,
          knowledgeGapClarificationCount: 1,
          shopifyLookupAttempted: shopifyLookupAttempted,
          shopifyFound: shopifyFound,
          shopifyError: shopifyError,
          llmProvider: "openai",
          llmModel: null,
          llmLatencyMs: 0,
          tokenUsage: null,
        };
        
        return res.json({
          requestId: req.requestId,
          reply,
          intent: effectiveIntent,
          shopify,
          routed: true,
          escalated: true,
          facts: getFacts(sessionId),
        });
      }
    }
    
    // Reset knowledge gap state if knowledge is now sufficient
    if (!knowledgeInsufficient && knowledgeGapClarificationAsked) {
      setMeta(sessionId, {
        knowledgeGapClarificationAsked: false,
        knowledgeGapTopic: null,
      });
    }

    const flowMeta = getMeta(sessionId);
    const flowHint = flowMeta.expectedSlot
      ? `EXPECTED_USER_INPUT: The user is answering the bot's question. Slot expected: ${flowMeta.expectedSlot}.`
      : "EXPECTED_USER_INPUT: none";

    const factsBlock = `
FACTS WE ALREADY KNOW (persisted from earlier messages):
- productName: ${facts.productName || "unknown"}
- orderNumber: ${facts.orderNumber || "unknown"}
- email: ${facts.email || "unknown"}
- problemDetails: ${facts.problemDetails || "unknown"}
`.trim();

    // IMPORTANT: Force correct support contact details so the model does not invent support@...
    const support = getSupportSettings(data.clientConfig || {});
    const supportBlock = `
OFFICIAL SUPPORT CONTACT DETAILS (must be used exactly; never invent others):
- Support email: ${support.email || "unknown"}
- Contact form URL: ${support.contactFormUrl || "unknown"}
If an email address is needed, ONLY use the Support email above.
If a contact form exists (URL is not "unknown"), do NOT say "no contact form".
`.trim();

    const brandLanguage = (data.clientConfig && data.clientConfig.language) || "nl";

    const systemPrompt = `
You are the AI support bot for ${data.clientConfig.brandName || data.clientId}.
The brand's default support language is "${brandLanguage}".
At the start of the conversation, or whenever the user's language is unclear or ambiguous, respond in this default language.
If the user clearly writes in another language or explicitly asks for a different language, you may switch to that language for your replies.
No emojis.
Never guess policies, prices, or shipping rules.
Only answer using the provided context.

Conversation handling rules:
- Use the chat history and FACTS WE ALREADY KNOW to understand what the user is answering.
- If the user is answering a clarification question (e.g., product name, order number), treat it as an answer and continue.
- Ask only 1 short follow-up question at a time when needed.
- Do NOT respond with a full product description unless the user explicitly asks for product info.

${flowHint}

${factsBlock}

${supportBlock}

BRAND VOICE:
${data.brandVoice || ""}

CUSTOMER SUPPORT RULES:
${data.supportRules || ""}

SHOPIFY ORDER DATA:
${shopify ? JSON.stringify(shopify, null, 2) : "none"}

TRACKING LINK RULES (CRITICAL):
- When mentioning track & trace / tracking information:
  - If the trackingUrl field in SHOPIFY ORDER DATA is a URL (starts with https://), ALWAYS format it as a Markdown link.
  - Format: Use Markdown link syntax [Track & Trace](trackingUrl) where the link text is exactly "Track & Trace" (capitalization preserved).
  - Example required format: "Je kunt de status van je bestelling bekijken via deze [Track & Trace](https://tracking-url-here)." (Dutch) or "You can check your order status via this [Track & Trace](https://tracking-url-here)." (English)
  - Do NOT output the raw tracking URL alone anywhere in the message.
  - Do NOT output only a tracking code. Always use the trackingUrl from SHOPIFY ORDER DATA.
  - Do NOT output HTML. Use Markdown link syntax only.
  - If trackingUrl is null or missing, say: "Track & trace is nog niet beschikbaar." (Dutch) or "Track & trace is not yet available." (English).

SOCIAL MEDIA LINK RULES (CRITICAL):
- When mentioning Instagram links or other social media links:
  - ALWAYS format them as Markdown links using the syntax: [text](url)
  - For Instagram links in Dutch, use natural phrasing like: "voor haar Instagram, [klik hier](https://www.instagram.com/username/)" or "Je kunt haar volgen op Instagram: [klik hier](https://www.instagram.com/username/)"
  - For Instagram links in English, use: "for her Instagram, [click here](https://www.instagram.com/username/)" or "You can follow her on Instagram: [click here](https://www.instagram.com/username/)"
  - Do NOT output raw URLs like "https://www.instagram.com/username/"
  - The label text in the Markdown link should be natural (e.g., "klik hier", "click here", "hier", "here")
  - This applies to all Instagram, Facebook, Twitter, or other social media platform links mentioned in the knowledge base.

ATHLETE & DISCOUNT AUTORESPONSE RULE (CRITICAL):
- If the user asks about an athlete name, an athlete discount, "athlete code", "kortingscode van <naam>", or "discount code <name>":
  1) Confirm it exists ONLY if it is present in RELEVANT KNOWLEDGE.
  2) Provide the discount code exactly as written in RELEVANT KNOWLEDGE.
  3) Explain exactly how to use it in Shopify checkout in 2–4 short steps.
  4) If an Instagram URL is present for the athlete in RELEVANT KNOWLEDGE, include it immediately as a Markdown link:
     "Je kunt hem/haar ook volgen op Instagram: [klik hier](<instagram_url>)" (Dutch) or "You can also follow him/her on Instagram: [click here](<instagram_url>)" (English)
  5) Do NOT ask follow-up questions unless the code or athlete is ambiguous.

- If the user asks generally for "kortingscode", "discount", "promoties", "actie", "sale":
  1) List the relevant available discounts from RELEVANT KNOWLEDGE.
  2) For each: what it is for, the code, and how to apply.
  3) Keep it short and skimmable.

- If RELEVANT KNOWLEDGE is empty or says "No relevant knowledge matched.":
  - Do NOT guess.
  - Redirect to human support with the official support contact block.

- Use short paragraphs, optionally bullets for the steps.
- Do not output raw Instagram URLs; always use Markdown link format [klik hier](url) when you have it.
- Do not invent discounts, athletes, codes, or links.

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
    llmLatencyMs = Date.now() - tAi0;
    llmModel = "gpt-4.1-mini";
    tokenUsage = response && response.usage ? {
      promptTokens: response.usage.prompt_tokens || null,
      completionTokens: response.usage.completion_tokens || null,
      totalTokens: response.usage.total_tokens || null,
    } : null;

    const reply = response.choices[0].message.content;
    appendToHistory(sessionId, "assistant", reply);

    // Simple resolution detection: if bot gives a helpful answer without asking follow-up
    // and conversation has had sufficient exchanges, mark as resolved
    const currentConvState = conversationStateMap.get(sessionId);
    if (currentConvState && !currentConvState.ended && currentConvState.messageCount >= 4) {
      // Check if reply doesn't ask for follow-up (no question marks, no "stuur", "geef", "vertel")
      const replyLower = reply.toLowerCase();
      const hasQuestionMark = reply.includes("?");
      const asksForInput = /\b(stuur|geef|vertel|send|provide|tell|welke|which|wat|what)\b/.test(replyLower);
      const meta = getMeta(sessionId);
      const hasExpectedSlot = meta.expectedSlot && meta.expectedSlot.trim();
      
      if (!hasQuestionMark && !asksForInput && !hasExpectedSlot) {
        // Bot appears to have given a final answer
        endConversation(sessionId, "resolved_by_bot");
      }
    }

    const finalMetaForMetrics = getMeta(sessionId);
    const knowledgeGapDetected = isKnowledgeInsufficient(context, topChunks);
    const knowledgeGapTopic = finalMetaForMetrics.knowledgeGapTopic || null;
    const knowledgeGapClarificationAskedForMetrics = finalMetaForMetrics.knowledgeGapClarificationAsked || false;
    
    res.locals.chatMetrics = {
      intent: effectiveIntent,
      routedTo: "bot",
      escalateReason: null,
      conversationId: conversationId,
      clarificationRequired: false,
      clarificationType: null,
      clarificationAttemptCount: null,
      knowledgeGapDetected: knowledgeGapDetected,
      knowledgeGapTopic: knowledgeGapTopic,
      knowledgeGapClarificationAsked: knowledgeGapClarificationAskedForMetrics,
      knowledgeGapClarificationCount: knowledgeGapClarificationAskedForMetrics ? 1 : 0,
      shopifyLookupAttempted: shopifyLookupAttempted,
      shopifyFound: shopifyFound,
      shopifyError: shopifyError,
      llmProvider: "openai",
      llmModel: llmModel,
      llmLatencyMs: llmLatencyMs,
      tokenUsage: tokenUsage,
    };

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
    logJson("error", "chat_error", {
      requestId: req.requestId,
      route: "/chat",
      method: "POST",
      clientId: clientId || null,
      sessionId: sessionId || null,
      intent: effectiveIntent || null,
      shopifyLookupAttempted: shopifyLookupAttempted,
      shopifyFound: shopifyFound,
      shopifyError: shopifyError,
      llmProvider: "openai",
      llmModel: llmModel,
      llmLatencyMs: llmLatencyMs,
      tokenUsage: tokenUsage,
      error: e && e.message ? e.message : String(e),
      errorStack: e && e.stack ? String(e.stack).slice(0, 500) : null,
    });

    res.status(500);
    return res.json({ requestId: req.requestId, error: "Server error" });
  }
});

app.use((req, res) => {
  res.status(404).send("Not Found");
});

// Initialize client registry on startup
initializeClientRegistry();

app.listen(port, () => {
  const version = process.env.VERSION || process.env.RENDER_GIT_COMMIT || BUILD_VERSION || "unknown";
  logJson("info", "boot", {
    version: version,
    port: port,
    shopifyEnabled: Boolean(shopifyClient),
  });
});

