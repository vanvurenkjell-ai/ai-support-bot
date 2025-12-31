const session = require("express-session");
const crypto = require("crypto");

// Admin credentials from environment
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

// Validate admin credentials are set
if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.warn("[ADMIN AUTH] ADMIN_EMAIL and ADMIN_PASSWORD env vars must be set for admin portal");
}

// Constant-time password comparison to prevent timing attacks
function constantTimeCompare(a, b) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Verify admin credentials
function verifyAdminCredentials(email, password) {
  if (!email || !password) {
    return false;
  }
  return (
    constantTimeCompare(String(email).trim(), ADMIN_EMAIL) &&
    constantTimeCompare(String(password), ADMIN_PASSWORD)
  );
}

// Session configuration
const sessionConfig = {
  name: "admin.sid", // Session cookie name
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: "auto", // Automatically detect HTTPS (works with Render proxy when trust proxy is set)
    sameSite: "lax", // CSRF protection: lax for GET requests, stricter for POST
    maxAge: 1000 * 60 * 60 * 24, // 24 hours
    path: "/admin", // Cookie only sent for /admin routes
  },
  // In-memory session store (for single-instance deployments)
  // For multi-instance, use Redis or another shared store
};

// Create session middleware
const sessionMiddleware = session(sessionConfig);

// Simple logging helper (matches index.js pattern)
function logAdminEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "admin_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Authentication middleware: require admin session
// Supports both legacy super-admin (via ADMIN_EMAIL) and new role-based authz
function requireAdminAuth(req, res, next) {
  // Check if session exists and has admin data
  if (!req.session || !req.session.admin || !req.session.admin.email) {
    // Log unauthorized access attempt
    const requestId = req.requestId || "unknown";
    const ip = req.ip || "unknown"; // req.ip is set by trust proxy setting in index.js
    logAdminEvent("warn", "admin_unauthorized_access", {
      requestId: requestId,
      path: req.path,
      method: req.method,
      ip: ip,
      reason: "no_session_or_email",
    });
    
    // For API endpoints (like /admin/health), return 401 JSON
    // For HTML pages (like /admin and /admin/login), redirect to login
    const isApiEndpoint = req.path === "/admin/health" || (req.path.startsWith("/admin/") && req.path !== "/admin" && req.path !== "/admin/login");
    if (isApiEndpoint) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Authentication required",
      });
    }
    // For HTML pages, redirect to login
    return res.redirect("/admin/login");
  }

  // Backward compatibility: allow legacy super-admin (ADMIN_EMAIL match)
  // OR require authorization context (req.session.admin.authz)
  const isLegacySuperAdmin = req.session.admin.email === ADMIN_EMAIL;
  const hasAuthz = req.session.admin.authz && req.session.admin.authz.role;

  if (!isLegacySuperAdmin && !hasAuthz) {
    // Session exists but no valid authorization - deny access
    const requestId = req.requestId || "unknown";
    const ip = req.ip || "unknown";
    logAdminEvent("warn", "admin_unauthorized_access", {
      requestId: requestId,
      path: req.path,
      method: req.method,
      ip: ip,
      email: req.session.admin.email,
      reason: "missing_authz_context",
    });

    const isApiEndpoint = req.path === "/admin/health" || (req.path.startsWith("/admin/") && req.path !== "/admin" && req.path !== "/admin/login");
    if (isApiEndpoint) {
      return res.status(401).json({
        error: "Unauthorized",
        message: "Authentication required",
      });
    }
    return res.redirect("/admin/login");
  }

  next();
}

// Regenerate session on login to prevent session fixation
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

module.exports = {
  sessionMiddleware,
  requireAdminAuth,
  verifyAdminCredentials,
  regenerateSession,
  ADMIN_EMAIL,
};

