const express = require("express");
const router = express.Router();
const { sessionMiddleware, requireAdminAuth, verifyAdminCredentials, regenerateSession, ADMIN_EMAIL } = require("./auth");
const { generateCsrfToken, setCsrfToken, getCsrfToken, requireCsrf } = require("./csrf");

// Simple logging helper (matches index.js pattern for structured logs)
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

// Rate limiting for login endpoint: 5 attempts per 10 minutes per IP
const RL_LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RL_LOGIN_MAX_ATTEMPTS = 5;
const loginRateLimitStore = new Map();

function getClientIp(req) {
  return req.ip || "unknown";
}

function rateLimitLogin(req, res, next) {
  if (req.path !== "/admin/login" || req.method !== "POST") {
    return next();
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const entry = loginRateLimitStore.get(ip) || { windowStart: now, count: 0 };

  // Reset window if expired
  if (now - entry.windowStart > RL_LOGIN_WINDOW_MS) {
    entry.windowStart = now;
    entry.count = 0;
  }

  entry.count += 1;
  loginRateLimitStore.set(ip, entry);

  if (entry.count > RL_LOGIN_MAX_ATTEMPTS) {
    const requestId = req.requestId || "unknown";
    logAdminEvent("warn", "admin_login_rate_limit", {
      requestId: requestId,
      ip: ip,
      route: "/admin/login",
      count: entry.count,
    });
    return res.status(429).json({
      error: "Too many login attempts",
      message: "Please wait before trying again",
    });
  }

  next();
}

// Cleanup old rate limit entries
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of loginRateLimitStore.entries()) {
    if (now - entry.windowStart > RL_LOGIN_WINDOW_MS * 2) {
      loginRateLimitStore.delete(ip);
    }
  }
}, 60 * 1000); // Clean every minute

// Security headers middleware for /admin routes
function adminSecurityHeaders(req, res, next) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';");
  res.setHeader("X-Frame-Options", "DENY");
  next();
}

// Apply security headers to all admin routes
router.use(adminSecurityHeaders);

// Parse URL-encoded form data (for login/logout forms)
router.use(express.urlencoded({ extended: false }));

// Helper function to escape HTML (XSS protection)
function escapeHtml(text) {
  if (!text) return "";
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  };
  return String(text).replace(/[&<>"']/g, (m) => map[m]);
}

// Helper function to render login page with optional error message
function renderLoginPage(csrfToken, errorMessage = null) {
  const errorHtml = errorMessage ? `<p style="color: red;">${escapeHtml(errorMessage)}</p>` : "";
  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
</head>
<body>
  <h1>Admin Login</h1>
  ${errorHtml}
  <form method="POST" action="/admin/login">
    <input type="hidden" name="csrfToken" value="${csrfToken}">
    <div>
      <label for="email">Email:</label>
      <input type="email" id="email" name="email" required>
    </div>
    <div>
      <label for="password">Password:</label>
      <input type="password" id="password" name="password" required>
    </div>
    <button type="submit">Login</button>
  </form>
</body>
</html>
  `;
}

// Login page (GET /admin/login)
router.get("/login", (req, res) => {
  // If already authenticated, redirect to admin dashboard
  if (req.session?.admin && req.session.admin.email === ADMIN_EMAIL) {
    return res.redirect("/admin");
  }

  // Generate CSRF token for login form
  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  res.send(renderLoginPage(csrfToken));
});

// Login handler (POST /admin/login)
router.post("/login", rateLimitLogin, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const { email, password } = req.body || {};

  // Generate CSRF token for error page
  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  if (!email || !password) {
    // Log failed login attempt (no password)
    logAdminEvent("warn", "admin_login_failed", {
      event: "admin_login_failed",
      requestId: requestId,
      ip: ip,
      sessionId: req.sessionID || null,
      reason: "missing_credentials",
    });
    return res.status(400).send(renderLoginPage(csrfToken, "Email and password are required"));
  }

  // Verify credentials
  if (!verifyAdminCredentials(email, password)) {
    // Log failed login attempt (no password) - normalize email for logging (no secrets)
    const emailNormalized = email ? String(email).toLowerCase().trim() : null;
    logAdminEvent("warn", "admin_login_failed", {
      event: "admin_login_failed",
      requestId: requestId,
      ip: ip,
      emailAttempt: emailNormalized,
      sessionId: req.sessionID || null,
      reason: "invalid_credentials",
    });
    return res.status(401).send(renderLoginPage(csrfToken, "Invalid email or password"));
  }

  try {
    // Regenerate session to prevent session fixation
    await regenerateSession(req);

    // Set authenticated session with structured data
    req.session.admin = {
      email: ADMIN_EMAIL,
      loggedInAt: Date.now(),
    };

    // Generate new CSRF token for subsequent requests
    const newCsrfToken = generateCsrfToken();
    setCsrfToken(req, newCsrfToken);

    // Explicitly save session before redirecting
    req.session.save((err) => {
      if (err) {
        logAdminEvent("error", "admin_login_error", {
          requestId: requestId,
          ip: ip,
          error: err?.message || String(err),
        });
        return res.status(500).send(renderLoginPage(csrfToken, "Login failed. Please try again."));
      }

      // Log successful login with session diagnostic info
      const hasSetCookie = !!res.getHeader("Set-Cookie");
      logAdminEvent("info", "admin_login_success", {
        event: "admin_login_success",
        requestId: requestId,
        ip: ip,
        email: ADMIN_EMAIL,
        sessionId: req.sessionID || null,
        hasSetCookie: hasSetCookie,
      });

      // Redirect to admin dashboard after session is saved
      return res.redirect("/admin");
    });
  } catch (error) {
    logAdminEvent("error", "admin_login_error", {
      requestId: requestId,
      ip: ip,
      error: error?.message || String(error),
    });
    return res.status(500).send(renderLoginPage(csrfToken, "Login failed. Please try again."));
  }
});

// Logout handler (POST /admin/logout)
router.post("/logout", requireAdminAuth, requireCsrf, (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const adminEmail = req.session?.admin?.email || "unknown";

  // Log logout
  logAdminEvent("info", "admin_logout", {
    requestId: requestId,
    ip: ip,
    email: adminEmail,
  });

  // Destroy session
  req.session.destroy((err) => {
    if (err) {
      logAdminEvent("error", "admin_logout_error", {
        requestId: requestId,
        error: err?.message || String(err),
      });
    }
    // Redirect to login page
    res.redirect("/admin/login");
  });
});

// Admin dashboard (GET /admin)
router.get("/", requireAdminAuth, (req, res) => {
  // Log admin page access for diagnostics
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const hasCookieHeader = !!req.headers.cookie;
  const hasAdminSession = !!(req.session && req.session.admin && req.session.admin.email);
  logAdminEvent("info", "admin_page_hit", {
    event: "admin_page_hit",
    requestId: requestId,
    ip: ip,
    sessionId: req.sessionID || null,
    hasCookieHeader: hasCookieHeader,
    hasAdminSession: hasAdminSession,
    email: req.session?.admin?.email || null,
  });

  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  const adminEmail = req.session?.admin?.email || ADMIN_EMAIL;
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal</title>
</head>
<body>
  <h1>Admin Portal</h1>
  <p>You are logged in as <strong>${escapeHtml(adminEmail)}</strong></p>
  <form method="POST" action="/admin/logout">
    <input type="hidden" name="csrfToken" value="${csrfToken}">
    <button type="submit">Logout</button>
  </form>
</body>
</html>
  `;
  res.send(html);
});

// Health check endpoint (GET /admin/health)
router.get("/health", requireAdminAuth, (req, res) => {
  return res.json({
    status: "ok",
    authenticated: true,
    email: req.session?.admin?.email || ADMIN_EMAIL,
    timestamp: new Date().toISOString(),
  });
});

// TEMP DEBUG: remove after session issue resolved
// Debug endpoint to inspect session state
router.get("/debug-session", requireAdminAuth, (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  
  const hasCookieHeader = !!req.headers.cookie;
  const cookieHeaderLen = req.headers.cookie ? String(req.headers.cookie).length : 0;
  const hasSession = !!(req.session && typeof req.session === "object");
  const sessionKeys = hasSession ? Object.keys(req.session) : [];
  
  return res.json({
    ok: true,
    hasCookieHeader: hasCookieHeader,
    cookieHeaderLen: cookieHeaderLen,
    sessionId: req.sessionID || null,
    hasSession: hasSession,
    adminEmail: req.session?.admin?.email || null,
    sessionKeys: sessionKeys,
  });
});

module.exports = router;

