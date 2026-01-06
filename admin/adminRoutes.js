const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const { sessionMiddleware, requireAdminAuth, verifyAdminCredentials, regenerateSession, ADMIN_EMAIL } = require("./auth");
const { generateCsrfToken, setCsrfToken, getCsrfToken, requireCsrf } = require("./csrf");
// Import unified client store adapter (chooses Supabase or filesystem automatically)
const clientsStore = require("../lib/clientsStoreAdapter");
// Import authorization helpers
const { resolveUserFromSupabase, loadUserClientIds, isSuperAdmin, canAccessClient, getAuthorizedClientIds } = require("./adminAuthz");
// Import config validator (legacy - still used for form data transformation)
const { validateAndSanitizeConfigUpdate, mergeConfigUpdate } = require("./configValidator");
// Import schema system (new centralized validation)
const { applyPatch, normalizeConfig, getDefaultConfig } = require("../lib/clientConfigSchema");
// Import invitation management
const { createInvitation, listInvitationsForClient, getSupabaseClient } = require("../lib/clientInvitations");
// Import invitation acceptance
const { validateInvitationToken, acceptInvitation, validatePasswordStrength } = require("../lib/invitationAcceptance");
// Import invitation audit
const { logInvitationAudit } = require("../lib/invitationAudit");
// Import email sender
const { sendInvitationEmail } = require("../lib/emailSender");
// Import analytics service
const { executeQuery, getDefaultDateRange, validateDateRange, QUERY_DEFINITIONS } = require("../lib/clientAnalytics");

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

// Rate limiting for invitation acceptance: 10 GET requests per 10 minutes, 5 POST requests per 10 minutes per IP
const RL_ACCEPTANCE_GET_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RL_ACCEPTANCE_GET_MAX_ATTEMPTS = 10;
const RL_ACCEPTANCE_POST_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RL_ACCEPTANCE_POST_MAX_ATTEMPTS = 5;
const acceptanceRateLimitStoreGet = new Map();
const acceptanceRateLimitStorePost = new Map();

// Rate limiting for analytics endpoints: 20 requests per 5 minutes per IP
const RL_ANALYTICS_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const RL_ANALYTICS_MAX_ATTEMPTS = 20;
const analyticsRateLimitStore = new Map();

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

// Rate limiting for invitation acceptance endpoint
function rateLimitAcceptance(req, res, next) {
  if (req.path !== "/admin/invitations/accept") {
    return next();
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const isGet = req.method === "GET";
  const isPost = req.method === "POST";

  if (isGet) {
    const entry = acceptanceRateLimitStoreGet.get(ip) || { windowStart: now, count: 0 };

    // Reset window if expired
    if (now - entry.windowStart > RL_ACCEPTANCE_GET_WINDOW_MS) {
      entry.windowStart = now;
      entry.count = 0;
    }

    entry.count += 1;
    acceptanceRateLimitStoreGet.set(ip, entry);

    if (entry.count > RL_ACCEPTANCE_GET_MAX_ATTEMPTS) {
      const requestId = req.requestId || "unknown";
      logAdminEvent("warn", "invitation_acceptance_rate_limit", {
        requestId: requestId,
        ip: ip,
        route: "/admin/invitations/accept",
        method: "GET",
        count: entry.count,
      });
      return res.status(429).send(renderAcceptanceErrorPage("Too many requests", "Please wait before trying again."));
    }
  } else if (isPost) {
    const entry = acceptanceRateLimitStorePost.get(ip) || { windowStart: now, count: 0 };

    // Reset window if expired
    if (now - entry.windowStart > RL_ACCEPTANCE_POST_WINDOW_MS) {
      entry.windowStart = now;
      entry.count = 0;
    }

    entry.count += 1;
    acceptanceRateLimitStorePost.set(ip, entry);

    if (entry.count > RL_ACCEPTANCE_POST_MAX_ATTEMPTS) {
      const requestId = req.requestId || "unknown";
      logAdminEvent("warn", "invitation_acceptance_rate_limit", {
        requestId: requestId,
        ip: ip,
        route: "/admin/invitations/accept",
        method: "POST",
        count: entry.count,
      });
      return res.status(429).send(renderAcceptanceErrorPage("Too many attempts", "Please wait before trying again."));
    }
  }

  next();
}

// Rate limiting for analytics endpoints
function rateLimitAnalytics(req, res, next) {
  if (req.path !== "/admin/analytics" || req.method !== "GET") {
    return next();
  }

  const ip = getClientIp(req);
  const now = Date.now();
  const entry = analyticsRateLimitStore.get(ip) || { windowStart: now, count: 0 };

  // Reset window if expired
  if (now - entry.windowStart > RL_ANALYTICS_WINDOW_MS) {
    entry.windowStart = now;
    entry.count = 0;
  }

  entry.count += 1;
  analyticsRateLimitStore.set(ip, entry);

  if (entry.count > RL_ANALYTICS_MAX_ATTEMPTS) {
    const requestId = req.requestId || "unknown";
    logAdminEvent("warn", "admin_analytics_rate_limit", {
      requestId: requestId,
      ip: ip,
      route: "/admin/analytics",
      count: entry.count,
    });
    return res.status(429).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Rate Limit</title></head>
<body>
  <h1>Too Many Requests</h1>
  <p>Please wait before accessing analytics again.</p>
  <p><a href="/admin">Back to dashboard</a></p>
</body>
</html>
    `);
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
  for (const [ip, entry] of acceptanceRateLimitStoreGet.entries()) {
    if (now - entry.windowStart > RL_ACCEPTANCE_GET_WINDOW_MS * 2) {
      acceptanceRateLimitStoreGet.delete(ip);
    }
  }
  for (const [ip, entry] of acceptanceRateLimitStorePost.entries()) {
    if (now - entry.windowStart > RL_ACCEPTANCE_POST_WINDOW_MS * 2) {
      acceptanceRateLimitStorePost.delete(ip);
    }
  }
  for (const [ip, entry] of analyticsRateLimitStore.entries()) {
    if (now - entry.windowStart > RL_ANALYTICS_WINDOW_MS * 2) {
      analyticsRateLimitStore.delete(ip);
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

// Rate limiting for acceptance endpoint (must be before routes, applies to public endpoint)
router.use(rateLimitAcceptance);
router.use(rateLimitAnalytics);

// Parse URL-encoded form data (for login/logout forms and client config forms)
router.use(express.urlencoded({ extended: true }));

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

// Helper function to render invitation acceptance form
function renderAcceptanceForm(csrfToken, email, token, errorMessage = null) {
  const errorHtml = errorMessage ? `<div style="color: red; background: #ffe6e6; padding: 10px; border-radius: 4px; margin-bottom: 15px;">${escapeHtml(errorMessage)}</div>` : "";
  const escapedEmail = escapeHtml(email);
  const escapedToken = escapeHtml(token);
  
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Accept Invitation - ClientPulse</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; margin: 0; padding: 20px; }
    .container { max-width: 500px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { margin-top: 0; color: #333; }
    .form-group { margin-bottom: 20px; }
    label { display: block; margin-bottom: 5px; font-weight: bold; }
    input[type="email"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 16px; box-sizing: border-box; }
    input[type="email"]:disabled { background: #f5f5f5; color: #666; }
    .password-hint { font-size: 12px; color: #666; margin-top: 5px; }
    button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; font-size: 16px; cursor: pointer; }
    button:hover { background: #0056b3; }
    .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Accept Invitation</h1>
    <p>Welcome! Please set a password to complete your account setup.</p>
    ${errorHtml}
    <form method="POST" action="/admin/invitations/accept">
      <input type="hidden" name="csrfToken" value="${csrfToken}">
      <input type="hidden" name="token" value="${escapedToken}">
      <div class="form-group">
        <label for="email">Email:</label>
        <input type="email" id="email" name="email" value="${escapedEmail}" disabled required>
      </div>
      <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <div class="password-hint">Must be at least 8 characters and include both letters and numbers.</div>
      </div>
      <div class="form-group">
        <label for="confirmPassword">Confirm Password:</label>
        <input type="password" id="confirmPassword" name="confirmPassword" required>
      </div>
      <button type="submit">Create Account</button>
    </form>
    <div class="footer">
      <p>This invitation will expire in 7 days.</p>
    </div>
  </div>
</body>
</html>
  `;
}

// Helper function to render acceptance error page
function renderAcceptanceErrorPage(title, message) {
  const escapedTitle = escapeHtml(title);
  const escapedMessage = escapeHtml(message);
  
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapedTitle} - ClientPulse</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; margin: 0; padding: 20px; }
    .container { max-width: 500px; margin: 50px auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
    h1 { margin-top: 0; color: #d32f2f; }
    p { color: #666; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${escapedTitle}</h1>
    <p>${escapedMessage}</p>
    <p><a href="/admin/login">Go to login page</a></p>
  </div>
</body>
</html>
  `;
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
  // Support both legacy and new authz
  const isLegacyAuth = req.session?.admin && req.session.admin.email === ADMIN_EMAIL;
  const hasNewAuthz = req.session?.admin && req.session.admin.authz && req.session.admin.authz.role;
  if (isLegacyAuth || hasNewAuthz) {
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

  // Verify credentials and resolve user from Supabase (with legacy fallback)
  // This function handles:
  // 1. Legacy super-admin (ADMIN_EMAIL env var) - returns resolved user immediately
  // 2. Supabase users - verifies password_hash and returns resolved user
  // 3. Invalid credentials - returns null
  const resolvedUser = await resolveUserFromSupabase(email, password);
  
  if (!resolvedUser) {
    // No user resolved - credentials are invalid
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

  // User resolved successfully - set up session with authorization context
  try {
    // Regenerate session to prevent session fixation
    await regenerateSession(req);

    // Load client IDs for client_admin (super_admin gets null = all clients)
    let clientIds = null;
    if (resolvedUser.user.role === "client_admin" && resolvedUser.user.id) {
      clientIds = await loadUserClientIds(resolvedUser.user.id);
    } else if (resolvedUser.user.role === "super_admin") {
      clientIds = null; // null means "all clients" for super_admin
    }

    // Store resolved authorization context in session
    // Legacy admin normalization: legacy admin now has stable UUID (from getLegacyAdminUser)
    // This ensures invitations, audits, etc. always have valid actor_user_id
    const isLegacyAdmin = resolvedUser.user.is_legacy_admin === true && resolvedUser.user.role === "super_admin";
    req.session.admin = {
      email: resolvedUser.user.email,
      loggedInAt: Date.now(),
      authz: {
        role: resolvedUser.user.role, // Will be "super_admin" for legacy admin
        clientIds: clientIds,
        userId: resolvedUser.user.id, // Stable UUID for legacy admin (from getLegacyAdminUser)
      },
      // Mark legacy admin for tracking (useful for debugging and logging)
      ...(isLegacyAdmin ? { isLegacyAdmin: true } : {}),
    };

    logAdminEvent("info", "admin_authz_resolved", {
      requestId: requestId,
      email: resolvedUser.user.email,
      role: resolvedUser.user.role,
      clientIdsCount: clientIds ? clientIds.length : null,
      clientIds: clientIds || null, // Log client IDs for debugging (not sensitive)
      userId: resolvedUser.user.id || null,
    });
  } catch (error) {
    logAdminEvent("error", "admin_login_error", {
      requestId: requestId,
      ip: ip,
      error: error?.message || String(error),
    });
    return res.status(500).send(renderLoginPage(csrfToken, "Login failed. Please try again."));
  }

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
    const authz = req.session.admin.authz || { role: "super_admin", clientIds: null };
    logAdminEvent("info", "admin_login_success", {
      event: "admin_login_success",
      requestId: requestId,
      ip: ip,
      email: req.session.admin.email,
      role: authz.role,
      clientIdsCount: authz.clientIds ? authz.clientIds.length : null,
      sessionId: req.sessionID || null,
      hasSetCookie: hasSetCookie,
    });

    // Redirect to admin dashboard after session is saved
    return res.redirect("/admin");
  });
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

// Use centralized clientsStore module for all client config operations
const {
  getClientsRoot,
  validateClientId,
  getClientConfigPath,
  listClientIds,
  readClientConfig,
  writeClientConfigAtomic,
  deleteClient,
  getClientConfigStats,
} = clientsStore;

// Create default client config
function createDefaultConfig(clientId, displayName = null) {
  const name = displayName || clientId;
  return {
    version: "1.0.0",
    brandName: name,
    assistantName: `${name} klantenservice assistent`,
    language: "nl",
    noEmojis: true,
    support: {
      email: null,
      contactUrl: null,
      contactUrlMessageParam: "message",
    },
    widget: {
      title: displayName || `${name} AI-assistent`,
      greeting: `Hallo! Ik ben de ${name} klantenservice assistent. Fijn dat je er bent. Waar kan ik je mee helpen?`,
    },
    entryScreen: {
      enabled: true,
      title: displayName ? `Interesse in ${displayName}?` : null,
      disclaimer: null,
      primaryButton: { label: "Start chat", action: "openChat" },
      secondaryButtons: [],
    },
    colors: {
      primary: "#225ADF",
      accent: "#2563eb",
      background: "#ffffff",
      userBubble: "#225ADF",
      botBubble: "#ffffff",
    },
    features: {
      orderLookup: true,
      returns: true,
      productAdvice: true,
      humanHandoff: true,
    },
  };
}

// Create new client (wrapper using clientsStore)
async function createClient(clientId, displayName = null, actorContext = {}) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }
  
  const pathResult = getClientConfigPath(validation.clientId);
  if (!pathResult.valid) {
    return { success: false, error: "Invalid client ID path" };
  }
  
  // Check if client already exists (409 Conflict) - only for filesystem mode
  if (clientsStore.storeType === "filesystem" && fs.existsSync(pathResult.path)) {
    return { success: false, error: "Client already exists", statusCode: 409 };
  }
  
  try {
    // Create default config
    const defaultConfig = createDefaultConfig(validation.clientId, displayName);
    
    // For client creation, pass actor context
    const actorOptions = {
      actorUserId: actorContext.userId || null,
      actorEmail: actorContext.email || null,
      actorRole: actorContext.role || null,
      requestId: actorContext.requestId || null,
    };
    const writeResult = await writeClientConfigAtomic(
      validation.clientId, 
      defaultConfig, 
      actorContext.email || null, 
      actorOptions
    );
    
    if (!writeResult.success) {
      return writeResult;
    }
    
    return { success: true, path: pathResult.path };
  } catch (error) {
    logAdminEvent("error", "admin_client_create_error", {
      event: "admin_client_create_error",
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// Delete client wrapper with protection for "Advantum" (async for Supabase)
async function deleteClientSafe(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }
  
  // Safety: prevent deleting "Advantum" as a protected client
  if (validation.clientId === "Advantum") {
    return { success: false, error: "Cannot delete protected client" };
  }
  
  return await deleteClient(validation.clientId);
}

// Helper: Render navigation HTML
function renderNav(currentPage = "dashboard", csrfToken) {
  const navItems = [
    { path: "/admin/clients", label: "Clients", active: currentPage === "clients" },
    { path: "/admin/analytics", label: "Analytics", active: currentPage === "analytics" },
    { path: "/admin", label: "Dashboard", active: currentPage === "dashboard" },
  ];
  return `
    <nav style="margin-bottom: 20px; border-bottom: 1px solid #ccc; padding-bottom: 10px;">
      ${navItems.map(item => `
        <a href="${escapeHtml(item.path)}" style="margin-right: 15px; text-decoration: ${item.active ? "none" : "underline"}; color: ${item.active ? "#000" : "#0066cc"};">
          ${escapeHtml(item.label)}
        </a>
      `).join("")}
      <form method="POST" action="/admin/logout" style="display: inline; margin-left: 15px;">
        <input type="hidden" name="csrfToken" value="${csrfToken}">
        <button type="submit" style="background: transparent; color: #666; border: 1px solid #ccc; padding: 5px 10px; cursor: pointer; font-size: 0.9em;">Logout</button>
      </form>
    </nav>
  `;
}

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
  const userRole = req.session?.admin?.authz?.role || null;
  const isClientAdmin = userRole === "client_admin";
  
  // For client_admin, get their first (and typically only) client
  let primaryClientLink = "";
  if (isClientAdmin) {
    const authorizedClientIds = getAuthorizedClientIds(req) || [];
    if (authorizedClientIds.length > 0) {
      const primaryClientId = authorizedClientIds[0];
      primaryClientLink = `
  <div style="margin: 40px 0; padding: 30px; background: #f8f9fa; border: 2px solid #007bff; border-radius: 8px; text-align: center;">
    <h2 style="margin-top: 0;">Manage Widget & Behavior</h2>
    <p style="font-size: 1.1em; margin-bottom: 20px;">Configure your widget settings and customer experience.</p>
    <a href="/admin/clients/${encodeURIComponent(primaryClientId)}" style="display: inline-block; background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-size: 16px; font-weight: bold;">Manage Widget & Behavior</a>
  </div>
      `;
    }
  }
  
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal - Dashboard</title>
</head>
<body>
  <h1>Admin Portal</h1>
  <p style="color: #666; font-size: 0.9em;">Logged in as <strong>${escapeHtml(adminEmail)}</strong></p>
  ${renderNav("dashboard", csrfToken)}
  <h2>Dashboard</h2>
  ${primaryClientLink}
  ${!isClientAdmin ? '<p>Welcome to the admin portal. Use the navigation above to manage clients.</p>' : ''}
</body>
</html>
  `;
  res.send(html);
});

// Clients list (GET /admin/clients)
router.get("/clients", requireAdminAuth, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  
  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  // Fetch all clients from Supabase/filesystem (async)
  const allClients = await listClientIds();
  
  // Filter clients based on authorization
  let clients = allClients;
  const userEmail = req.session.admin.email;
  
  if (isSuperAdmin(req)) {
    // Super admin sees all clients
    clients = allClients;
  } else {
    // Client admin sees only their assigned clients
    const authorizedClientIds = getAuthorizedClientIds(req) || [];
    clients = allClients.filter(clientId => authorizedClientIds.includes(clientId));
    
    logAdminEvent("info", "admin_clients_list_filtered", {
      event: "admin_clients_list_filtered",
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      allClientsCount: allClients.length,
      filteredClientsCount: clients.length,
      authorizedClientIds: authorizedClientIds,
    });
  }

  const created = req.query.created === "1";
  const deleted = req.query.deleted === "1";
  const clientsRoot = getClientsRoot();
  
  logAdminEvent("info", "admin_clients_list_view", {
    event: "admin_clients_list_view",
    requestId: requestId,
    ip: ip,
    userEmail: userEmail,
    storeType: clientsStore.storeType,
    clientsCount: clients.length,
    clientIds: clients,
    isSuperAdmin: isSuperAdmin(req),
  });
  
  const successMessage = created ? '<p style="color: green; font-weight: bold;">✓ Client created successfully!</p>' : '';
  const deletedMessage = deleted ? '<p style="color: green; font-weight: bold;">✓ Client deleted successfully!</p>' : '';
  
  const isClientAdminView = !isSuperAdmin(req);
  
  // For client_admin, make client items more prominent; for super_admin, keep list format
  const clientsList = clients.length > 0
    ? (isClientAdminView 
        ? `<div style="display: grid; gap: 15px; margin-top: 20px;">
            ${clients.map(clientId => `
              <div style="padding: 20px; background: white; border: 2px solid #007bff; border-radius: 8px; text-align: center;">
                <a href="/admin/clients/${encodeURIComponent(clientId)}" style="font-size: 1.5em; font-weight: bold; color: #007bff; text-decoration: none;">${escapeHtml(clientId)}</a>
                <p style="margin-top: 10px; color: #666;">Manage widget settings and behavior</p>
              </div>
            `).join("")}
          </div>`
        : `<ul>${clients.map(clientId => `<li><a href="/admin/clients/${encodeURIComponent(clientId)}">${escapeHtml(clientId)}</a></li>`).join("")}</ul>`)
    : `<p>No clients found.</p>`;

  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal - Clients</title>
</head>
<body>
  <h1>Admin Portal</h1>
  <p style="color: #666; font-size: 0.9em;">Logged in as <strong>${escapeHtml(userEmail)}</strong></p>
  ${renderNav("clients", csrfToken)}
  <h2>Clients</h2>
  ${successMessage}
  ${deletedMessage}
  ${isSuperAdmin(req) ? `
  <div style="margin-bottom: 20px; padding: 10px; background: #e7f3ff; border: 1px solid #b3d9ff; border-radius: 4px;">
    <p><strong>Config storage:</strong> <code>${escapeHtml(clientsStore.storeType === "supabase" ? "Supabase" : clientsRoot)}</code></p>
    <p style="margin-top: 5px; font-size: 0.9em; color: #666;">${clientsStore.storeType === "supabase" ? "Clients are stored in Supabase database." : "Clients created here are stored on the server; they will not appear in GitHub automatically."}</p>
  </div>
  ` : ''}
  ${isSuperAdmin(req) ? `
  <h3>Create New Client</h3>
  <form method="POST" action="/admin/clients" style="margin-bottom: 30px; padding: 15px; border: 1px solid #ccc; max-width: 500px;">
    <input type="hidden" name="csrfToken" value="${csrfToken}">
    <div style="margin-bottom: 10px;">
      <label>Client ID (required): <input type="text" name="clientId" required pattern="[a-zA-Z][a-zA-Z0-9_-]{1,39}" style="width: 200px;" placeholder="e.g. MyClient"></label><br>
      <small>2-40 characters, must start with a letter, only letters/numbers/underscore/hyphen</small>
    </div>
    <div style="margin-bottom: 10px;">
      <label>Display Name (optional): <input type="text" name="displayName" maxlength="60" style="width: 200px;" placeholder="e.g. My Client Name"></label>
    </div>
    <button type="submit" style="background: #28a745; color: white; border: none; padding: 8px 16px; cursor: pointer;">Create Client</button>
  </form>
  ` : ''}
  ${isSuperAdmin(req) ? '<h3>Existing Clients</h3>' : ''}
  ${clientsList}
</body>
</html>
  `;
  res.send(html);
});

// Create client (POST /admin/clients) - super_admin only
router.post("/clients", requireAdminAuth, requireCsrf, async (req, res) => {
  // Authorization check: only super_admin can create clients
  if (!isSuperAdmin(req)) {
    const requestId = req.requestId || "unknown";
    const ip = getClientIp(req);
    logAdminEvent("warn", "admin_client_create_denied", {
      event: "admin_client_create_denied",
      requestId: requestId,
      ip: ip,
      userEmail: req.session.admin.email,
      reason: "not_super_admin",
    });
    
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(403).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Access Denied</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Access Denied</h2>
  <p style="color: red;">You do not have permission to create clients. Only super administrators can create new clients.</p>
  <p><a href="/admin/clients">Back to clients</a></p>
</body>
</html>
    `);
  }
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const { clientId, displayName } = req.body || {};
  const updatedBy = req.session?.admin?.email || null;
  
  if (!clientId || typeof clientId !== "string") {
    logAdminEvent("warn", "admin_client_create_failed", {
      event: "admin_client_create_failed",
      requestId: requestId,
      ip: ip,
      reason: "missing_client_id",
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Create Client</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Create Client</h2>
  <p style="color: red;">Error: Client ID is required.</p>
  <p><a href="/admin/clients">Back to clients</a></p>
</body>
</html>
    `);
  }
  
  // Pass actor context for audit logging
  const actorContext = {
    userId: req.session?.admin?.authz?.userId || null,
    email: req.session?.admin?.email || null,
    role: req.session?.admin?.authz?.role || (req.session?.admin?.email === ADMIN_EMAIL ? "super_admin" : null),
    requestId: requestId,
  };
  
  const result = await createClient(clientId, displayName, actorContext);
  
  if (!result.success) {
    const statusCode = result.statusCode || 400;
    logAdminEvent("warn", "admin_client_create_failed", {
      event: "admin_client_create_failed",
      requestId: requestId,
      ip: ip,
      clientId: clientId,
      reason: result.error,
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(statusCode).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Create Client</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Create Client</h2>
  <p style="color: red;">Error: ${escapeHtml(result.error)}</p>
  <p><a href="/admin/clients">Back to clients</a></p>
</body>
</html>
    `);
  }
  
  logAdminEvent("info", "admin_client_create_success", {
    event: "admin_client_create_success",
    requestId: requestId,
    ip: ip,
    clientId: clientId,
    path: result.path,
    storeType: clientsStore.storeType,
  });
  
  // Redirect to edit page
  return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?created=1`);
});

// Client config editor (GET /admin/clients/:clientId)
router.get("/clients/:clientId", requireAdminAuth, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientId = req.params.clientId;
  const saved = req.query.saved === "1";
  const created = req.query.created === "1";
  const welcome = req.query.welcome === "1";
  
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return res.status(400).send("Invalid client ID");
  }
  
  let config, pathResult, configStats;
  try {
    config = await readClientConfig(validation.clientId);
    if (!config) {
      return res.status(404).send("Client config not found");
    }
    
    pathResult = getClientConfigPath(validation.clientId);
    configStats = await getClientConfigStats(validation.clientId);
  } catch (error) {
    logAdminEvent("error", "admin_client_edit_read_error", {
      event: "admin_client_edit_read_error",
      requestId: requestId,
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return res.status(500).send("Error loading client config");
  }
  
  logAdminEvent("info", "admin_client_edit_view", {
    event: "admin_client_edit_view",
    requestId: requestId,
    clientId: validation.clientId,
  });
  
  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);
  
  const successMessage = saved ? '<p style="color: green; font-weight: bold;">✓ Changes saved successfully!</p>' : '';
  const createdMessage = created ? '<p style="color: green; font-weight: bold;">✓ Client created successfully!</p>' : '';
  const welcomeMessage = welcome ? '<p style="color: green; font-weight: bold; padding: 15px; background: #d4edda; border: 1px solid #c3e6cb; border-radius: 4px; margin-bottom: 20px;">✓ Welcome! Your account has been set up. You can now manage your widget settings below.</p>' : '';
  const inviteSuccessMessage = req.query.invite_success ? `<p style="color: green; font-weight: bold;">✓ Invitation sent to ${escapeHtml(req.query.invite_email || "")} (status: pending)</p>` : '';
  const inviteErrorMessage = req.query.invite_error ? `<p style="color: red; font-weight: bold;">Error: ${escapeHtml(req.query.invite_error)}</p>` : '';
  
  // Fetch invitations for this client (if super_admin)
  let invitations = [];
  if (isSuperAdmin(req)) {
    try {
      invitations = await listInvitationsForClient(validation.clientId);
    } catch (error) {
      logAdminEvent("error", "admin_invitation_list_error", {
        event: "admin_invitation_list_error",
        requestId: requestId,
        clientId: validation.clientId,
        error: error?.message || String(error),
      });
      // Continue without invitations if fetch fails
    }
  }
  
  const configPathInfo = configStats ? `
  <div style="margin-bottom: 20px; padding: 10px; background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px;">
    <p><strong>Config storage:</strong> <code>${escapeHtml(clientsStore.storeType === "supabase" ? "Supabase" : pathResult.path)}</code></p>
    <p style="margin-top: 5px;"><strong>Last modified:</strong> ${escapeHtml(configStats.mtimeISO || "N/A")}</p>
  </div>
  ` : '';
  
  // Helper to safely get nested value
  const getValue = (obj, path, defaultValue = "") => {
    const parts = path.split(".");
    let current = obj;
    for (const part of parts) {
      if (current && typeof current === "object" && part in current) {
        current = current[part];
      } else {
        return defaultValue;
      }
    }
    return current != null ? String(current) : defaultValue;
  };
  
  // Embed instructions snippet
  const embedSnippet = `<script>
  (function() {
    // Load widget script
    var script = document.createElement('script');
    script.src = 'https://ai-support-bot-a6n3.onrender.com/widget.js?client=${encodeURIComponent(validation.clientId)}';
    script.async = true;
    document.head.appendChild(script);
  })();
</script>`;
  
  const liquidSnippet = `{% comment %}
  AI Support Bot Widget
  Paste this code in your Shopify theme's layout/theme.liquid file before </body>
  Or add it as a section/snippet in your theme customizer
{% endcomment %}
<script>
  var clientId = "${escapeHtml(validation.clientId)}";
  // ... rest of widget code (paste AI-support-bot.liquid content here, replacing "Advantum" with clientId variable)
</script>`;
  
  const userRole = req.session?.admin?.authz?.role || null;
  const isClientAdminView = userRole === "client_admin";
  
  // Section A: At-a-glance / Primary Actions (always visible, most prominent)
  const sectionA = `
    <div style="background: #f8f9fa; border: 2px solid #007bff; border-radius: 8px; padding: 25px; margin-bottom: 30px;">
      <h2 style="margin-top: 0; color: #007bff;">At-a-Glance</h2>
      <p style="color: #666; margin-bottom: 20px;"><strong>What does my customer see?</strong></p>
      
      <div style="margin-bottom: 20px;">
        <label style="display: block; font-weight: bold; margin-bottom: 5px;">Widget Title:</label>
        <input type="text" name="widget[title]" value="${escapeHtml(getValue(config, "widget.title", ""))}" style="width: 100%; max-width: 500px; padding: 8px; font-size: 16px;" maxlength="60" required>
      </div>
      
      <div style="margin-bottom: 25px;">
        <label style="display: block; font-weight: bold; margin-bottom: 5px;">Greeting / Initial Message:</label>
        <textarea name="widget[greeting]" style="width: 100%; max-width: 500px; padding: 8px; font-size: 14px; height: 80px;" maxlength="240" required>${escapeHtml(getValue(config, "widget.greeting", ""))}</textarea>
      </div>
      
      <button type="submit" style="background: #28a745; color: white; border: none; padding: 12px 30px; cursor: pointer; font-size: 18px; font-weight: bold; border-radius: 4px;">Save Changes</button>
    </div>
  `;
  
  // Section B: Widget Appearance & Behavior (supporting, grouped)
  const sectionB = `
    <div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
      <h2 style="margin-top: 0;">Widget Appearance & Behavior</h2>
      
      <div style="margin-bottom: 25px;">
        <label style="display: block; font-weight: bold; margin-bottom: 5px;">Logo URL:</label>
        <input type="text" name="logoUrl" value="${escapeHtml(getValue(config, "logoUrl", ""))}" style="width: 100%; max-width: 600px; padding: 8px;" maxlength="300">
      </div>
      
      <fieldset style="border: 1px solid #ddd; padding: 15px; border-radius: 4px; margin-bottom: 25px;">
        <legend style="font-weight: bold; padding: 0 10px;">Colors</legend>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
          <div>
            <label style="display: block; margin-bottom: 5px;">Primary:</label>
            <input type="text" name="colors[primary]" value="${escapeHtml(getValue(config, "colors.primary", ""))}" style="width: 100%; padding: 6px;">
          </div>
          <div>
            <label style="display: block; margin-bottom: 5px;">Accent:</label>
            <input type="text" name="colors[accent]" value="${escapeHtml(getValue(config, "colors.accent", ""))}" style="width: 100%; padding: 6px;">
          </div>
          <div>
            <label style="display: block; margin-bottom: 5px;">Background:</label>
            <input type="text" name="colors[background]" value="${escapeHtml(getValue(config, "colors.background", ""))}" style="width: 100%; padding: 6px;">
          </div>
          <div>
            <label style="display: block; margin-bottom: 5px;">User Bubble:</label>
            <input type="text" name="colors[userBubble]" value="${escapeHtml(getValue(config, "colors.userBubble", ""))}" style="width: 100%; padding: 6px;">
          </div>
          <div>
            <label style="display: block; margin-bottom: 5px;">Bot Bubble:</label>
            <input type="text" name="colors[botBubble]" value="${escapeHtml(getValue(config, "colors.botBubble", ""))}" style="width: 100%; padding: 6px;">
          </div>
        </div>
      </fieldset>
      
      <details style="margin-top: 20px;">
        <summary style="cursor: pointer; font-weight: bold; padding: 10px; background: #f8f9fa; border: 1px solid #ddd; border-radius: 4px; user-select: none;">Entry Screen Settings</summary>
        <div style="padding: 20px 10px; border-top: 1px solid #ddd;">
          <div style="margin-bottom: 15px;">
            <label><input type="checkbox" name="entryScreen[enabled]" ${getValue(config, "entryScreen.enabled", false) ? "checked" : ""} style="margin-right: 5px;"> Enabled</label>
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Title:</label>
            <input type="text" name="entryScreen[title]" value="${escapeHtml(getValue(config, "entryScreen.title", ""))}" style="width: 100%; max-width: 500px; padding: 6px;" maxlength="60">
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Disclaimer:</label>
            <textarea name="entryScreen[disclaimer]" style="width: 100%; max-width: 500px; padding: 6px; height: 70px;" maxlength="240">${escapeHtml(getValue(config, "entryScreen.disclaimer", ""))}</textarea>
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Primary Button Label:</label>
            <input type="text" name="entryScreen[primaryButton][label]" value="${escapeHtml(getValue(config, "entryScreen.primaryButton.label", ""))}" style="width: 100%; max-width: 400px; padding: 6px;" maxlength="30">
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Secondary Button 1 Label:</label>
            <input type="text" name="entryScreen[secondaryButtons][0][label]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.0.label", ""))}" style="width: 100%; max-width: 400px; padding: 6px;" maxlength="30">
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Secondary Button 1 URL:</label>
            <input type="text" name="entryScreen[secondaryButtons][0][url]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.0.url", ""))}" style="width: 100%; max-width: 500px; padding: 6px;" maxlength="200">
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Secondary Button 2 Label:</label>
            <input type="text" name="entryScreen[secondaryButtons][1][label]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.1.label", ""))}" style="width: 100%; max-width: 400px; padding: 6px;" maxlength="30">
          </div>
          <div style="margin-bottom: 15px;">
            <label style="display: block; margin-bottom: 5px;">Secondary Button 2 URL:</label>
            <input type="text" name="entryScreen[secondaryButtons][1][url]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.1.url", ""))}" style="width: 100%; max-width: 500px; padding: 6px;" maxlength="200">
          </div>
        </div>
      </details>
    </div>
  `;
  
  // Section C: Support & Contact Settings (supporting)
  const sectionC = `
    <div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
      <h2 style="margin-top: 0;">Support & Contact Settings</h2>
      
      <div style="margin-bottom: 20px;">
        <label style="display: block; font-weight: bold; margin-bottom: 5px;">Support Email:</label>
        <input type="email" name="support[email]" value="${escapeHtml(getValue(config, "support.email", ""))}" style="width: 100%; max-width: 400px; padding: 8px;" maxlength="120">
      </div>
      
      <div style="margin-bottom: 20px;">
        <label style="display: block; font-weight: bold; margin-bottom: 5px;">Contact URL:</label>
        <input type="text" name="support[contactUrl]" value="${escapeHtml(getValue(config, "support.contactUrl", ""))}" style="width: 100%; max-width: 600px; padding: 8px;" maxlength="200">
      </div>
      
      <div style="margin-bottom: 20px;">
        <label style="display: block; font-weight: bold; margin-bottom: 5px;">Contact URL Message Parameter:</label>
        <input type="text" name="support[contactUrlMessageParam]" value="${escapeHtml(getValue(config, "support.contactUrlMessageParam", ""))}" style="width: 100%; max-width: 300px; padding: 8px;" maxlength="30">
      </div>
    </div>
  `;
  
  // Section D: Advanced / Setup (rare, collapsed by default for client_admin)
  const sectionD = isClientAdminView ? `
    <details style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
      <summary style="cursor: pointer; font-weight: bold; padding: 10px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; user-select: none;">Advanced Setup — Usually Done Once</summary>
      <div style="padding: 20px 10px; border-top: 1px solid #ddd;">
        <div style="margin-bottom: 25px; padding: 15px; background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px;">
          <h3 style="margin-top: 0;">Embed Instructions</h3>
          <p><strong>For Shopify (.liquid):</strong></p>
          <p>Copy the <code>AI-support-bot.liquid</code> file content and replace the hardcoded clientId value with your client ID (${escapeHtml(validation.clientId)}).</p>
          <p>Then paste it in your theme's layout file (theme.liquid) before the closing <code>&lt;/body&gt;</code> tag, or add it as a section/snippet in the theme customizer.</p>
          <p><strong>Important:</strong> Make sure to set <code>var clientId = "${escapeHtml(validation.clientId)}";</code> in the script.</p>
        </div>
        <div style="padding: 15px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px;">
          <p><strong>Client ID:</strong> <code>${escapeHtml(validation.clientId)}</code></p>
          <p style="font-size: 0.9em; color: #666; margin-bottom: 0;">Use this client ID when configuring the widget embed code.</p>
        </div>
      </div>
    </details>
  ` : `
    <div style="background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 30px;">
      <h2 style="margin-top: 0;">Advanced Setup</h2>
      <div style="margin-bottom: 25px; padding: 15px; background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px;">
        <h3 style="margin-top: 0;">Embed Instructions</h3>
        <p><strong>For Shopify (.liquid):</strong></p>
        <p>Copy the <code>AI-support-bot.liquid</code> file content and replace the hardcoded clientId value with your client ID (${escapeHtml(validation.clientId)}).</p>
        <p>Then paste it in your theme's layout file (theme.liquid) before the closing <code>&lt;/body&gt;</code> tag, or add it as a section/snippet in the theme customizer.</p>
        <p><strong>Important:</strong> Make sure to set <code>var clientId = "${escapeHtml(validation.clientId)}";</code> in the script.</p>
      </div>
      <div style="padding: 15px; background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px;">
        <p><strong>Client ID:</strong> <code>${escapeHtml(validation.clientId)}</code></p>
        <p style="font-size: 0.9em; color: #666; margin-bottom: 0;">Use this client ID when configuring the widget embed code.</p>
      </div>
    </div>
  `;
  
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal - Edit ${escapeHtml(validation.clientId)}</title>
</head>
<body>
  <h1>Admin Portal</h1>
  <p style="color: #666; font-size: 0.9em;">Logged in as <strong>${escapeHtml(req.session?.admin?.email || "")}</strong></p>
  ${renderNav("clients", csrfToken)}
  <h2>${isClientAdminView ? "Manage Widget & Behavior" : "Edit Client: " + escapeHtml(validation.clientId)}</h2>
  ${welcomeMessage}
  ${createdMessage}
  ${successMessage}
  ${inviteSuccessMessage}
  ${inviteErrorMessage}
  <p style="margin-bottom: 20px;"><a href="/admin/clients" style="color: #666; text-decoration: none;">← Back to clients</a></p>
  ${isSuperAdmin(req) && configPathInfo ? configPathInfo : ''}
  
  <form method="POST" action="/admin/clients/${encodeURIComponent(validation.clientId)}" style="max-width: 900px;">
    <input type="hidden" name="csrfToken" value="${csrfToken}">
    
    ${sectionA}
    ${sectionB}
    ${sectionC}
    ${sectionD}
    
    <div style="margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd;">
      <button type="submit" style="background: #28a745; color: white; border: none; padding: 12px 30px; cursor: pointer; font-size: 18px; font-weight: bold; border-radius: 4px;">Save Changes</button>
    </div>
  </form>
  
  <hr style="margin: 40px 0;">
  
  ${isSuperAdmin(req) ? `
  <h3>Client Admin Access</h3>
  <div style="margin-bottom: 30px; padding: 15px; border: 1px solid #ccc; max-width: 600px;">
    <p>Invite a client administrator to manage this client's configuration. The invited user will receive access to edit this client's settings.</p>
    <form method="POST" action="/admin/invitations" style="margin-top: 15px;">
      <input type="hidden" name="csrfToken" value="${csrfToken}">
      <input type="hidden" name="client_id" value="${escapeHtml(validation.clientId)}">
      <div style="margin-bottom: 10px;">
        <label>Email: <input type="email" name="email" required style="width: 300px;" placeholder="user@example.com"></label>
      </div>
      <button type="submit" style="background: #28a745; color: white; border: none; padding: 8px 16px; cursor: pointer;">Invite Client Admin</button>
    </form>
    ${invitations.length > 0 ? `
    <div style="margin-top: 20px; padding-top: 15px; border-top: 1px solid #ddd;">
      <p><strong>Existing Invitations:</strong></p>
      <table style="width: 100%; border-collapse: collapse; margin-top: 10px;">
        <thead>
          <tr style="border-bottom: 1px solid #ddd;">
            <th style="text-align: left; padding: 5px;">Email</th>
            <th style="text-align: left; padding: 5px;">Status</th>
            <th style="text-align: left; padding: 5px;">Expires</th>
            ${isSuperAdmin(req) ? '<th style="text-align: left; padding: 5px;">Actions</th>' : ''}
          </tr>
        </thead>
        <tbody>
          ${invitations.map(inv => {
            const expiresAt = inv.expires_at ? new Date(inv.expires_at).toLocaleDateString() : 'N/A';
            const canResend = isSuperAdmin(req) && inv.status === 'pending' && (!inv.expires_at || new Date(inv.expires_at) > new Date());
            const canRevoke = isSuperAdmin(req) && inv.status === 'pending';
            return `
          <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 5px;">${escapeHtml(inv.email)}</td>
            <td style="padding: 5px;">${escapeHtml(inv.status)}</td>
            <td style="padding: 5px;">${escapeHtml(expiresAt)}</td>
            ${isSuperAdmin(req) ? `
            <td style="padding: 5px;">
              ${canResend ? `
              <form method="POST" action="/admin/invitations/${escapeHtml(inv.id)}/resend" style="display: inline-block; margin-right: 5px;">
                <input type="hidden" name="csrfToken" value="${csrfToken}">
                <button type="submit" style="background: #007bff; color: white; border: none; padding: 4px 8px; cursor: pointer; font-size: 12px;">Resend</button>
              </form>
              ` : ''}
              ${canRevoke ? `
              <form method="POST" action="/admin/invitations/${escapeHtml(inv.id)}/revoke" style="display: inline-block;" onsubmit="return confirm('Are you sure you want to revoke this invitation?');">
                <input type="hidden" name="csrfToken" value="${csrfToken}">
                <button type="submit" style="background: #dc3545; color: white; border: none; padding: 4px 8px; cursor: pointer; font-size: 12px;">Revoke</button>
              </form>
              ` : ''}
            </td>
            ` : ''}
          </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
    ` : ''}
  </div>
  
  <hr style="margin: 40px 0;">
  
  <h3>Delete Client</h3>
  <div style="padding: 15px; background: #fff3cd; border: 1px solid #ffc107; margin-bottom: 20px;">
    <p><strong>Warning:</strong> This will permanently delete the client configuration. This action cannot be undone.</p>
    ${validation.clientId === "Advantum" ? '<p style="color: red;"><strong>Note:</strong> This client is protected and cannot be deleted.</p>' : ''}
  </div>
  ${validation.clientId !== "Advantum" ? `
  <form method="POST" action="/admin/clients/${encodeURIComponent(validation.clientId)}/delete" style="max-width: 500px;">
    <input type="hidden" name="csrfToken" value="${csrfToken}">
    <div style="margin-bottom: 15px;">
      <label>Type the client ID to confirm deletion: <input type="text" name="confirmClientId" required style="width: 200px;"></label>
    </div>
    <button type="submit" style="background: #dc3545; color: white; border: none; padding: 10px 20px; cursor: pointer; font-size: 16px;">Delete Client</button>
  </form>
  ` : ''}
  ` : ''}
</body>
</html>
  `;
  res.send(html);
});

// Client config update (POST /admin/clients/:clientId) - form submission
router.post("/clients/:clientId", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientIdRaw = req.params.clientId;
  const userEmail = req.session.admin.email;
  
  const validation = validateClientId(clientIdRaw);
  if (!validation.valid) {
    return res.status(400).send("Invalid client ID");
  }
  const clientId = validation.clientId;
  
  // Authorization check: user must be able to access this client
  if (!canAccessClient(req, clientId)) {
    logAdminEvent("warn", "admin_client_update_denied", {
      event: "admin_client_update_denied",
      requestId: requestId,
      userEmail: userEmail,
      clientId: clientId,
      reason: "not_authorized",
    });
    
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(403).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Access Denied</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Access Denied</h2>
  <p style="color: red;">You do not have permission to update this client.</p>
  <p><a href="/admin/clients">Back to clients</a></p>
</body>
</html>
    `);
  }
  
  // Transform form data to API format
  const updateData = {};
  if (req.body.colors) {
    updateData.colors = req.body.colors;
  }
  if (req.body.widget) {
    updateData.widget = req.body.widget;
  }
  if (req.body.logoUrl !== undefined) {
    updateData.logoUrl = req.body.logoUrl;
  }
  if (req.body.entryScreen) {
    updateData.entryScreen = { ...req.body.entryScreen };
    // Fix secondary buttons array - form sends as indexed array
    if (req.body.entryScreen.secondaryButtons && Array.isArray(req.body.entryScreen.secondaryButtons)) {
      const buttons = [];
      for (const btn of req.body.entryScreen.secondaryButtons) {
        if (btn && btn.label && btn.url) {
          buttons.push({ label: btn.label, action: "link", url: btn.url });
        }
      }
      updateData.entryScreen.secondaryButtons = buttons.slice(0, 2); // Max 2
    }
    // Ensure primaryButton.action is set
    if (updateData.entryScreen.primaryButton && !updateData.entryScreen.primaryButton.action) {
      updateData.entryScreen.primaryButton.action = "openChat";
    }
  }
  if (req.body.support) {
    updateData.support = req.body.support;
  }
  
  // Validate clientId and get path (use clientsStore)
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid) {
    return res.status(404).send("Client config not found");
  }
  
  try {
    // Read existing config (use clientsStore - async for Supabase)
    const existingConfig = await readClientConfig(clientId);
    if (!existingConfig) {
      return res.status(404).send("Client config not found");
    }
    
    // Determine actor role for validation (same allowlist for all roles for safety)
    const actorRole = isSuperAdmin(req) ? "super_admin" : "client_admin";
    
    // Validate and sanitize update using strict validator
    const validationResult = validateAndSanitizeConfigUpdate(existingConfig, updateData, actorRole);
    
    if (validationResult.errors.length > 0 || !validationResult.sanitizedConfig) {
      logAdminEvent("warn", "admin_client_update_validation_failed", {
        event: "admin_client_update_validation_failed",
        requestId: requestId,
        clientId: clientId,
        userEmail: userEmail,
        actorRole: actorRole,
        errors: validationResult.errors,
        disallowedFields: Object.keys(validationResult.fieldErrors || {}),
      });
      
      // Re-render edit page with error messages
      const csrfToken = generateCsrfToken();
      setCsrfToken(req, csrfToken);
      
      // Helper to safely get nested value
      const getValue = (obj, path, defaultValue = "") => {
        const parts = path.split(".");
        let current = obj;
        for (const part of parts) {
          if (current && typeof current === "object" && part in current) {
            current = current[part];
          } else {
            return defaultValue;
          }
        }
        return current != null ? String(current) : defaultValue;
      };
      
      // Re-read config for form re-rendering
      const config = existingConfig;
      const configStats = await clientsStore.getClientConfigStats(clientId);
      
      const errorSummary = validationResult.errors.length > 0
        ? `<div style="padding: 15px; background: #fff3cd; border: 1px solid #ffc107; margin-bottom: 20px;">
            <p style="color: red; font-weight: bold;">Validation errors:</p>
            <ul>
              ${validationResult.errors.map(err => `<li>${escapeHtml(err)}</li>`).join("")}
            </ul>
          </div>`
        : "";
      
      // Re-render form (similar to GET route) with error messages
      // For brevity, redirect back to edit page with error param and show error message
      // Or re-render the form here (full implementation would need the full form HTML)
      return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Validation Error</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Edit Client: ${escapeHtml(clientId)}</h2>
  ${errorSummary}
  <p><a href="/admin/clients/${encodeURIComponent(clientId)}">← Back to edit page</a></p>
  <p>Please fix the validation errors and try again.</p>
</body>
</html>
      `);
    }
    
    // Merge sanitized update into existing config
    const updatedConfig = mergeConfigUpdate(existingConfig, validationResult.sanitizedConfig);
    
    // Write updated config (atomic write - async for Supabase)
    // Pass actor context for audit logging
    const updatedBy = req.session?.admin?.email || null;
    const actorOptions = {
      actorUserId: req.session?.admin?.authz?.userId || null,
      actorEmail: req.session?.admin?.email || null,
      actorRole: req.session?.admin?.authz?.role || (req.session?.admin?.email === ADMIN_EMAIL ? "super_admin" : null),
      requestId: requestId,
    };
    const writeResult = await writeClientConfigAtomic(clientId, updatedConfig, updatedBy, actorOptions);
    if (!writeResult.success) {
      logAdminEvent("error", "admin_client_update_write_failed", {
        event: "admin_client_update_write_failed",
        requestId: requestId,
        clientId: clientId,
        error: writeResult.error,
      });
      return res.status(500).send("Error writing client config");
    }
    
    const writtenEntryScreenTitle = updatedConfig.entryScreen?.title || null;
    
    // Note: /widget-config reads fresh from storage (bypasses clientRegistry cache), so no cache invalidation needed
    
    logAdminEvent("info", "admin_client_update_persisted", {
      event: "admin_client_update_persisted",
      requestId: requestId,
      clientId: clientId,
      writtenPath: writeResult.path || pathResult.path,
      writtenEntryScreenTitle: writtenEntryScreenTitle,
      storeType: clientsStore.storeType,
    });
    
    logAdminEvent("info", "admin_client_update_success", {
      event: "admin_client_update_success",
      requestId: requestId,
      clientId: clientId,
      userEmail: userEmail,
      actorRole: actorRole,
    });
    
    // Redirect back to edit page with success message
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?saved=1`);
  } catch (error) {
    logAdminEvent("error", "admin_client_update_error", {
      event: "admin_client_update_error",
      requestId: requestId,
      clientId: clientId,
      error: error?.message || String(error),
    });
    return res.status(500).send("Error updating client config");
  }
});

// Delete client (POST /admin/clients/:clientId/delete)
router.post("/clients/:clientId/delete", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const clientIdRaw = req.params.clientId;
  const { confirmClientId } = req.body || {};
  
  const validation = validateClientId(clientIdRaw);
  if (!validation.valid) {
    logAdminEvent("warn", "admin_client_delete_failed", {
      event: "admin_client_delete_failed",
      requestId: requestId,
      ip: ip,
      clientId: clientIdRaw,
      reason: "invalid_client_id",
    });
    return res.status(400).send("Invalid client ID");
  }
  
  const clientId = validation.clientId;
  
  // Safety: prevent deleting "Advantum" as a protected client
  if (clientId === "Advantum") {
    logAdminEvent("warn", "admin_client_delete_failed", {
      event: "admin_client_delete_failed",
      requestId: requestId,
      ip: ip,
      clientId: clientId,
      reason: "protected_client",
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(403).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Delete Client</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Delete Client</h2>
  <p style="color: red;">Error: Cannot delete protected client.</p>
  <p><a href="/admin/clients/${encodeURIComponent(clientId)}">Back to client</a></p>
</body>
</html>
    `);
  }
  
  // Require confirmation - user must type the clientId exactly
  if (!confirmClientId || String(confirmClientId).trim() !== clientId) {
    logAdminEvent("warn", "admin_client_delete_failed", {
      event: "admin_client_delete_failed",
      requestId: requestId,
      ip: ip,
      clientId: clientId,
      reason: "confirmation_mismatch",
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Delete Client</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Delete Client</h2>
  <p style="color: red;">Error: Confirmation does not match client ID. Please type the client ID exactly.</p>
  <p><a href="/admin/clients/${encodeURIComponent(clientId)}">Back to client</a></p>
</body>
</html>
    `);
  }
  
  const result = deleteClientSafe(clientId);
  
  if (!result.success) {
    logAdminEvent("warn", "admin_client_delete_failed", {
      event: "admin_client_delete_failed",
      requestId: requestId,
      ip: ip,
      clientId: clientId,
      reason: result.error,
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Portal - Delete Client</title></head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Delete Client</h2>
  <p style="color: red;">Error: ${escapeHtml(result.error)}</p>
  <p><a href="/admin/clients/${encodeURIComponent(clientId)}">Back to client</a></p>
</body>
</html>
    `);
  }
  
  logAdminEvent("info", "admin_client_delete_success", {
    event: "admin_client_delete_success",
    requestId: requestId,
    ip: ip,
    clientId: clientId,
    storeType: clientsStore.storeType,
  });
  
  // Redirect to clients list with success message
  return res.redirect("/admin/clients?deleted=1");
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

// Create invitation (POST /admin/invitations) - super_admin only
// Handles both JSON API requests and HTML form submissions
router.post("/invitations", requireAdminAuth, requireCsrf, async (req, res) => {
  // Authorization check: only super_admin can create invitations
  if (!isSuperAdmin(req)) {
    const requestId = req.requestId || "unknown";
    const ip = getClientIp(req);
    logAdminEvent("warn", "admin_invitation_create_denied", {
      event: "admin_invitation_create_denied",
      requestId: requestId,
      ip: ip,
      userEmail: req.session?.admin?.email || "unknown",
      reason: "not_super_admin",
    });
    
    // Check if this is a form submission (redirect) or API call (JSON)
    const isFormSubmission = req.headers["content-type"]?.includes("application/x-www-form-urlencoded");
    if (isFormSubmission && req.body.client_id) {
      return res.redirect(`/admin/clients/${encodeURIComponent(req.body.client_id)}?invite_error=${encodeURIComponent("Access denied. Only super administrators can create invitations.")}`);
    }
    
    return res.status(403).json({
      error: "Access denied",
      message: "Only super administrators can create invitations",
    });
  }

  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const { email, client_id: clientId } = req.body || {};
  const isFormSubmission = req.headers["content-type"]?.includes("application/x-www-form-urlencoded");

  // Validate required fields
  if (!email || typeof email !== "string") {
    logAdminEvent("warn", "admin_invitation_create_failed", {
      event: "admin_invitation_create_failed",
      requestId: requestId,
      ip: ip,
      reason: "missing_email",
    });
    
    if (isFormSubmission && clientId) {
      return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?invite_error=${encodeURIComponent("Email is required")}`);
    }
    
    return res.status(400).json({
      error: "Validation error",
      message: "Email is required",
    });
  }

  if (!clientId || typeof clientId !== "string") {
    logAdminEvent("warn", "admin_invitation_create_failed", {
      event: "admin_invitation_create_failed",
      requestId: requestId,
      ip: ip,
      reason: "missing_client_id",
    });
    
    if (isFormSubmission) {
      return res.redirect("/admin/clients?invite_error=" + encodeURIComponent("Client ID is required"));
    }
    
    return res.status(400).json({
      error: "Validation error",
      message: "Client ID is required",
    });
  }

  // Get actor user ID from session
  const actorUserId = req.session?.admin?.authz?.userId || null;
  if (!actorUserId) {
    logAdminEvent("error", "admin_invitation_create_failed", {
      event: "admin_invitation_create_failed",
      requestId: requestId,
      ip: ip,
      reason: "missing_actor_user_id",
      note: "Super admin session missing user ID",
    });
    
    if (isFormSubmission) {
      return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?invite_error=${encodeURIComponent("Unable to identify creator")}`);
    }
    
    return res.status(500).json({
      error: "Internal error",
      message: "Unable to identify creator",
    });
  }

  // Construct base URL for acceptance link
  const protocol = req.protocol || "https";
  const host = req.get("host") || req.headers.host || "localhost";
  const baseUrl = `${protocol}://${host}`;

  // Create invitation
  const result = await createInvitation(email, clientId, actorUserId, requestId, baseUrl);

  if (!result.success) {
    logAdminEvent("warn", "admin_invitation_create_failed", {
      event: "admin_invitation_create_failed",
      requestId: requestId,
      ip: ip,
      email: email,
      clientId: clientId,
      createdByUserId: actorUserId,
      reason: result.error,
    });
    
    // For form submissions, redirect with error message (safe, user-friendly)
    if (isFormSubmission) {
      const errorMessage = result.error === "Invalid email format" 
        ? "Invalid email format"
        : result.error === "A pending invitation already exists for this email and client"
        ? "A pending invitation already exists for this email"
        : "Failed to create invitation. Please try again.";
      
      return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?invite_error=${encodeURIComponent(errorMessage)}`);
    }
    
    return res.status(400).json({
      error: "Invitation creation failed",
      message: result.error,
    });
  }

  logAdminEvent("info", "admin_invitation_create_success", {
    event: "admin_invitation_create_success",
    requestId: requestId,
    ip: ip,
    invitationId: result.invitation.id,
    email: result.invitation.email,
    clientId: result.invitation.client_id,
    createdByUserId: actorUserId,
  });

  // For form submissions, redirect back to client page with success message
  if (isFormSubmission) {
    return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?invite_success=1&invite_email=${encodeURIComponent(email)}`);
  }

  // Return invitation details (without token) for API calls
  return res.status(201).json({
    invitation: {
      id: result.invitation.id,
      email: result.invitation.email,
      client_id: result.invitation.client_id,
      role: result.invitation.role,
      status: result.invitation.status,
      expires_at: result.invitation.expires_at,
      created_at: result.invitation.created_at,
    },
  });
});

// GET /admin/invitations/accept - Public invitation acceptance page (no auth required)
router.get("/invitations/accept", async (req, res) => {
  const requestId = req.requestId || "unknown";
  const token = req.query.token;

  if (!token || typeof token !== "string") {
    logAdminEvent("warn", "invitation_acceptance_missing_token", {
      requestId: requestId,
      ip: getClientIp(req),
    });
    return res.status(400).send(renderAcceptanceErrorPage("Invalid Request", "Invalid or missing invitation token."));
  }

  // Validate token
  const validation = await validateInvitationToken(token);
  if (!validation.valid || !validation.invitation) {
    logAdminEvent("warn", "invitation_acceptance_invalid_token_get", {
      requestId: requestId,
      ip: getClientIp(req),
      error: validation.error || "invalid_token",
    });
    return res.status(400).send(renderAcceptanceErrorPage("Invalid Invitation", validation.error || "This invitation is invalid or has expired."));
  }

  // Generate CSRF token for form submission
  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  // Render acceptance form
  res.send(renderAcceptanceForm(csrfToken, validation.invitation.email, token));
});

// POST /admin/invitations/accept - Accept invitation and create account (public, CSRF protected)
router.post("/invitations/accept", requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const { token, email, password, confirmPassword } = req.body || {};

  // Validate required fields
  if (!token || typeof token !== "string") {
    logAdminEvent("warn", "invitation_acceptance_missing_token", {
      requestId: requestId,
      ip: ip,
    });
    return res.status(400).send(renderAcceptanceErrorPage("Invalid Request", "Invalid or missing invitation token."));
  }

  if (!password || typeof password !== "string") {
    return res.status(400).send(renderAcceptanceErrorPage("Validation Error", "Password is required."));
  }

  if (password !== confirmPassword) {
    return res.status(400).send(renderAcceptanceErrorPage("Validation Error", "Passwords do not match."));
  }

  // Accept invitation (creates user, links to client, marks invitation as accepted)
  const result = await acceptInvitation(token, password, requestId);

  if (!result.success) {
    logAdminEvent("warn", "invitation_acceptance_failed", {
      requestId: requestId,
      ip: ip,
      error: result.error || "unknown",
    });

    // Re-validate token to get email for error form display
    const validation = await validateInvitationToken(token);
    if (validation.valid && validation.invitation) {
      const csrfToken = generateCsrfToken();
      setCsrfToken(req, csrfToken);
      return res.status(400).send(renderAcceptanceForm(csrfToken, validation.invitation.email, token, result.error || "Failed to create account. Please try again."));
    }

    return res.status(400).send(renderAcceptanceErrorPage("Acceptance Failed", result.error || "Failed to create account. Please contact support."));
  }

  // Account created successfully - set up authenticated session
  try {
    // Regenerate session to prevent session fixation
    await regenerateSession(req);

    // Load client IDs for the new user
    const clientIds = result.clientId ? [result.clientId] : [];

    // Set up session
    req.session.admin = {
      email: result.user.email,
      loggedInAt: Date.now(),
      authz: {
        role: result.user.role,
        clientIds: clientIds,
        userId: result.user.id,
      },
    };

    logAdminEvent("info", "invitation_acceptance_success_session", {
      requestId: requestId,
      userId: result.user.id,
      email: result.user.email,
      clientId: result.clientId,
    });

    // Redirect to client management page
    res.redirect(`/admin/clients/${encodeURIComponent(result.clientId)}?welcome=1`);
  } catch (error) {
    logAdminEvent("error", "invitation_acceptance_session_error", {
      requestId: requestId,
      userId: result.user?.id,
      error: error?.message || String(error),
      note: "Account created but session setup failed - user will need to log in",
    });
    // Account was created, but session setup failed - redirect to login
    res.redirect("/admin/login?account_created=1");
  }
});

// DELETE /admin/users/:userId - Delete user (super_admin only)
router.delete("/users/:userId", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const userId = req.params.userId;

  // Authorization check: only super_admin can delete users
  if (!isSuperAdmin(req)) {
    logAdminEvent("warn", "admin_user_delete_denied", {
      requestId: requestId,
      ip: ip,
      userId: userId,
      userEmail: req.session?.admin?.email || "unknown",
      reason: "not_super_admin",
    });
    return res.status(403).json({
      error: "Access denied",
      message: "Only super administrators can delete users",
    });
  }

  // Prevent deleting legacy admin
  const { getLegacyAdminUser } = require("../lib/legacyAdminIdentity");
  try {
    const legacyAdmin = getLegacyAdminUser();
    if (userId === legacyAdmin.id) {
      logAdminEvent("warn", "admin_user_delete_denied", {
        requestId: requestId,
        ip: ip,
        userId: userId,
        reason: "cannot_delete_legacy_admin",
      });
      return res.status(403).json({
        error: "Cannot delete legacy admin",
        message: "The legacy admin user cannot be deleted",
      });
    }
  } catch (error) {
    // If legacy admin check fails, continue (legacy admin might not be configured)
  }

  const supabase = require("@supabase/supabase-js").createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false } }
  );

  if (!supabase) {
    return res.status(500).json({
      error: "System error",
      message: "Database not available",
    });
  }

  try {
    // Check if user exists
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, email, role")
      .eq("id", userId)
      .maybeSingle();

    if (userError || !user) {
      logAdminEvent("warn", "admin_user_delete_not_found", {
        requestId: requestId,
        ip: ip,
        userId: userId,
      });
      return res.status(404).json({
        error: "User not found",
        message: "User does not exist",
      });
    }

    // Delete client_users relationships first (foreign key constraint)
    const { error: clientUsersError } = await supabase
      .from("client_users")
      .delete()
      .eq("user_id", userId);

    if (clientUsersError) {
      logAdminEvent("error", "admin_user_delete_client_users_error", {
        requestId: requestId,
        ip: ip,
        userId: userId,
        error: clientUsersError?.message || String(clientUsersError),
      });
      return res.status(500).json({
        error: "Delete failed",
        message: "Failed to remove user from clients",
      });
    }

    // Delete user
    const { error: deleteError } = await supabase
      .from("users")
      .delete()
      .eq("id", userId);

    if (deleteError) {
      logAdminEvent("error", "admin_user_delete_error", {
        requestId: requestId,
        ip: ip,
        userId: userId,
        error: deleteError?.message || String(deleteError),
      });
      return res.status(500).json({
        error: "Delete failed",
        message: "Failed to delete user",
      });
    }

    logAdminEvent("info", "admin_user_deleted", {
      requestId: requestId,
      ip: ip,
      deletedUserId: userId,
      deletedUserEmail: user.email,
      deletedBy: req.session?.admin?.email || "unknown",
    });

    return res.status(200).json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    logAdminEvent("error", "admin_user_delete_error", {
      requestId: requestId,
      ip: ip,
      userId: userId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return res.status(500).json({
      error: "System error",
      message: "An error occurred while deleting the user",
    });
  }
});

// POST /admin/invitations/:id/resend - Resend invitation email (super_admin only)
router.post("/invitations/:id/resend", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const invitationId = req.params.id;

  // Authorization check: only super_admin can resend invitations
  if (!isSuperAdmin(req)) {
    logAdminEvent("warn", "admin_invitation_resend_denied", {
      requestId: requestId,
      ip: ip,
      invitationId: invitationId,
      userEmail: req.session?.admin?.email || "unknown",
      reason: "not_super_admin",
    });
    return res.status(403).json({
      error: "Access denied",
      message: "Only super administrators can resend invitations",
    });
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return res.status(500).json({
      error: "System error",
      message: "Database not available",
    });
  }

  try {
    // Lookup invitation
    const { data: invitation, error: lookupError } = await supabase
      .from("client_invitations")
      .select("id, email, client_id, role, status, expires_at, created_by_user_id")
      .eq("id", invitationId)
      .maybeSingle();

    if (lookupError || !invitation) {
      logAdminEvent("warn", "admin_invitation_resend_not_found", {
        requestId: requestId,
        ip: ip,
        invitationId: invitationId,
      });
      return res.status(404).json({
        error: "Invitation not found",
        message: "Invitation does not exist",
      });
    }

    // Only allow resend if status is pending and not expired
    const now = new Date();
    const expiresAt = new Date(invitation.expires_at);
    const isExpired = expiresAt <= now;

    if (invitation.status !== "pending") {
      return res.status(400).json({
        error: "Cannot resend",
        message: `Cannot resend invitation with status: ${invitation.status}`,
      });
    }

    if (isExpired) {
      return res.status(400).json({
        error: "Cannot resend",
        message: "Invitation has expired",
      });
    }

    // Generate a new token for the resend (we need raw token for email)
    // Note: We keep the same token_hash in DB, but generate a new raw token for email
    // Actually, we can't regenerate a matching token - we'd need to store the raw token somewhere
    // OR: we need to regenerate both token and hash, but then old link won't work
    // Better approach: Keep existing token_hash, but we can't send email with old token
    // For now, generate new token and hash, update the hash in DB, send email with new token
    // This invalidates the old link, which is acceptable for resend operation
    const { generateInvitationToken } = require("../lib/clientInvitations");
    const { token, tokenHash } = await generateInvitationToken();

    // Update token_hash in database (this invalidates old link)
    const { error: updateError } = await supabase
      .from("client_invitations")
      .update({ token_hash: tokenHash })
      .eq("id", invitationId)
      .eq("status", "pending"); // Only update if still pending

    if (updateError) {
      logAdminEvent("error", "admin_invitation_resend_update_error", {
        requestId: requestId,
        ip: ip,
        invitationId: invitationId,
        error: updateError?.message || String(updateError),
      });
      return res.status(500).json({
        error: "Resend failed",
        message: "Failed to update invitation",
      });
    }

    // Construct base URL for acceptance link
    const protocol = req.protocol || "https";
    const host = req.get("host") || req.headers.host || "localhost";
    const baseUrl = `${protocol}://${host}`;

    // Send email (fail-safe: email failure does not rollback token update)
    const emailResult = await sendInvitationEmail({
      to: invitation.email,
      client_id: invitation.client_id,
      invite_id: invitation.id,
      token: token, // New token for resend
      baseUrl: baseUrl,
      requestId: requestId,
    });

    // Log audit entry (fail-safe)
    const actorUserId = req.session?.admin?.authz?.userId || null;
    const actorEmail = req.session?.admin?.email || null;
    const actorRole = req.session?.admin?.authz?.role || null;

    await logInvitationAudit({
      invitationId: invitation.id,
      clientId: invitation.client_id,
      actorUserId: actorUserId,
      actorEmail: actorEmail,
      actorRole: actorRole,
      action: "resent",
      beforeStatus: "pending",
      afterStatus: "pending",
      meta: {
        requestId: requestId,
        emailSent: emailResult.success,
        emailError: emailResult.error || null,
        ip: ip,
      },
    });

    if (!emailResult.success) {
      // Email failed but invitation token was updated
      logAdminEvent("warn", "admin_invitation_resend_email_failed", {
        requestId: requestId,
        ip: ip,
        invitationId: invitation.id,
        email: invitation.email,
        emailError: emailResult.error || "unknown",
        note: "Invitation token updated but email sending failed",
      });
      return res.status(200).json({
        success: true,
        message: "Invitation token updated, but email failed to send",
        emailSent: false,
        emailError: emailResult.error,
      });
    }

    logAdminEvent("info", "admin_invitation_resend_success", {
      requestId: requestId,
      ip: ip,
      invitationId: invitation.id,
      email: invitation.email,
      clientId: invitation.client_id,
      resentBy: actorEmail || "unknown",
    });

    // Check if this is a form submission (redirect) or API call (JSON)
    const isFormSubmission = req.headers["content-type"]?.includes("application/x-www-form-urlencoded");
    if (isFormSubmission) {
      return res.redirect(`/admin/clients/${encodeURIComponent(invitation.client_id)}?invite_resent=1&invite_email=${encodeURIComponent(invitation.email)}`);
    }

    return res.status(200).json({
      success: true,
      message: "Invitation email resent successfully",
      emailSent: true,
    });
  } catch (error) {
    logAdminEvent("error", "admin_invitation_resend_error", {
      requestId: requestId,
      ip: ip,
      invitationId: invitationId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return res.status(500).json({
      error: "System error",
      message: "An error occurred while resending the invitation",
    });
  }
});

// POST /admin/invitations/:id/revoke - Revoke invitation (super_admin only)
router.post("/invitations/:id/revoke", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const invitationId = req.params.id;

  // Authorization check: only super_admin can revoke invitations
  if (!isSuperAdmin(req)) {
    logAdminEvent("warn", "admin_invitation_revoke_denied", {
      requestId: requestId,
      ip: ip,
      invitationId: invitationId,
      userEmail: req.session?.admin?.email || "unknown",
      reason: "not_super_admin",
    });
    return res.status(403).json({
      error: "Access denied",
      message: "Only super administrators can revoke invitations",
    });
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return res.status(500).json({
      error: "System error",
      message: "Database not available",
    });
  }

  try {
    // Lookup invitation
    const { data: invitation, error: lookupError } = await supabase
      .from("client_invitations")
      .select("id, email, client_id, role, status")
      .eq("id", invitationId)
      .maybeSingle();

    if (lookupError || !invitation) {
      logAdminEvent("warn", "admin_invitation_revoke_not_found", {
        requestId: requestId,
        ip: ip,
        invitationId: invitationId,
      });
      return res.status(404).json({
        error: "Invitation not found",
        message: "Invitation does not exist",
      });
    }

    // If already accepted, do not allow revoke
    if (invitation.status === "accepted") {
      return res.status(400).json({
        error: "Cannot revoke",
        message: "Cannot revoke an accepted invitation",
      });
    }

    // If already revoked or expired, idempotent response (200)
    if (invitation.status === "revoked" || invitation.status === "expired") {
      return res.status(200).json({
        success: true,
        message: `Invitation is already ${invitation.status}`,
        status: invitation.status,
      });
    }

    // Update status to revoked
    const beforeStatus = invitation.status;
    const { error: updateError } = await supabase
      .from("client_invitations")
      .update({ status: "revoked" })
      .eq("id", invitationId)
      .neq("status", "accepted") // Do not update if already accepted
      .neq("status", "revoked"); // Idempotent: do not update if already revoked

    if (updateError) {
      logAdminEvent("error", "admin_invitation_revoke_update_error", {
        requestId: requestId,
        ip: ip,
        invitationId: invitationId,
        error: updateError?.message || String(updateError),
      });
      return res.status(500).json({
        error: "Revoke failed",
        message: "Failed to update invitation status",
      });
    }

    // Log audit entry (fail-safe)
    const actorUserId = req.session?.admin?.authz?.userId || null;
    const actorEmail = req.session?.admin?.email || null;
    const actorRole = req.session?.admin?.authz?.role || null;

    await logInvitationAudit({
      invitationId: invitation.id,
      clientId: invitation.client_id,
      actorUserId: actorUserId,
      actorEmail: actorEmail,
      actorRole: actorRole,
      action: "revoked",
      beforeStatus: beforeStatus,
      afterStatus: "revoked",
      meta: {
        requestId: requestId,
        ip: ip,
      },
    });

    logAdminEvent("info", "admin_invitation_revoke_success", {
      requestId: requestId,
      ip: ip,
      invitationId: invitation.id,
      email: invitation.email,
      clientId: invitation.client_id,
      beforeStatus: beforeStatus,
      revokedBy: actorEmail || "unknown",
    });

    // Check if this is a form submission (redirect) or API call (JSON)
    const isFormSubmission = req.headers["content-type"]?.includes("application/x-www-form-urlencoded");
    if (isFormSubmission) {
      return res.redirect(`/admin/clients/${encodeURIComponent(invitation.client_id)}?invite_revoked=1&invite_email=${encodeURIComponent(invitation.email)}`);
    }

    return res.status(200).json({
      success: true,
      message: "Invitation revoked successfully",
      status: "revoked",
    });
  } catch (error) {
    logAdminEvent("error", "admin_invitation_revoke_error", {
      requestId: requestId,
      ip: ip,
      invitationId: invitationId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return res.status(500).json({
      error: "System error",
      message: "An error occurred while revoking the invitation",
    });
  }
});

// Analytics page (GET /admin/analytics)
router.get("/analytics", requireAdminAuth, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const userEmail = req.session?.admin?.email || null;
  const userRole = req.session?.admin?.authz?.role || null;
  const isSuperAdminUser = isSuperAdmin(req);

  // Determine client selection (server-side, never user-controlled)
  const authorizedClientIds = getAuthorizedClientIds(req) || [];
  let selectedClientId = req.query.clientId || null;

  // For client_admin: must use one of their authorized clients
  if (!isSuperAdminUser) {
    if (authorizedClientIds.length === 0) {
      logAdminEvent("warn", "admin_analytics_no_clients", {
        requestId: requestId,
        ip: ip,
        userEmail: userEmail,
        reason: "no_authorized_clients",
      });
      const csrfToken = generateCsrfToken();
      setCsrfToken(req, csrfToken);
      return res.status(403).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Access Denied</title></head>
<body>
  <h1>Access Denied</h1>
  <p>You do not have access to any clients.</p>
  <p><a href="/admin">Back to dashboard</a></p>
</body>
</html>
      `);
    }

    // Auto-select if only one client
    if (authorizedClientIds.length === 1) {
      selectedClientId = authorizedClientIds[0];
    } else {
      // Multiple clients: validate selection
      if (selectedClientId && !authorizedClientIds.includes(selectedClientId)) {
        logAdminEvent("warn", "admin_analytics_unauthorized_client", {
          requestId: requestId,
          ip: ip,
          userEmail: userEmail,
          attemptedClientId: selectedClientId,
          authorizedClientIds: authorizedClientIds,
        });
        selectedClientId = null; // Reset to first authorized
      }
      if (!selectedClientId) {
        selectedClientId = authorizedClientIds[0]; // Default to first
      }
    }
  } else {
    // Super admin: can select any client (for now, default to first if not specified)
    // In future, could add client selector UI
    if (!selectedClientId && authorizedClientIds.length > 0) {
      selectedClientId = authorizedClientIds[0];
    }
  }

  if (!selectedClientId) {
    logAdminEvent("warn", "admin_analytics_no_client_selected", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Error</title></head>
<body>
  <h1>Error</h1>
  <p>No client selected.</p>
  <p><a href="/admin">Back to dashboard</a></p>
</body>
</html>
    `);
  }

  // Validate client access (fail-closed)
  if (!canAccessClient(req, selectedClientId)) {
    logAdminEvent("warn", "admin_analytics_access_denied", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      clientId: selectedClientId,
      reason: "not_authorized",
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(403).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Access Denied</title></head>
<body>
  <h1>Access Denied</h1>
  <p>You do not have permission to view analytics for this client.</p>
  <p><a href="/admin">Back to dashboard</a></p>
</body>
</html>
    `);
  }

  // Parse date ranges from query params (with defaults)
  const kpiRangeDays = parseInt(req.query.kpiRange) || 30;
  const trendsRangeDays = parseInt(req.query.trendsRange) || 30;
  const reasonsRangeDays = parseInt(req.query.reasonsRange) || 90;
  const intentsRangeDays = parseInt(req.query.intentsRange) || 90;

  // Build date ranges
  const now = new Date();
  const kpiEndDate = new Date(now);
  const kpiStartDate = new Date(now);
  kpiStartDate.setDate(kpiStartDate.getDate() - kpiRangeDays);

  const trendsEndDate = new Date(now);
  const trendsStartDate = new Date(now);
  trendsStartDate.setDate(trendsStartDate.getDate() - trendsRangeDays);

  const reasonsEndDate = new Date(now);
  const reasonsStartDate = new Date(now);
  reasonsStartDate.setDate(reasonsStartDate.getDate() - reasonsRangeDays);

  const intentsEndDate = new Date(now);
  const intentsStartDate = new Date(now);
  intentsStartDate.setDate(intentsStartDate.getDate() - intentsRangeDays);

  // Validate date ranges
  const kpiValidation = validateDateRange(kpiStartDate, kpiEndDate);
  const trendsValidation = validateDateRange(trendsStartDate, trendsEndDate);
  const reasonsValidation = validateDateRange(reasonsStartDate, reasonsEndDate);
  const intentsValidation = validateDateRange(intentsStartDate, intentsEndDate);

  if (!kpiValidation.valid || !trendsValidation.valid || !reasonsValidation.valid || !intentsValidation.valid) {
    logAdminEvent("warn", "admin_analytics_invalid_date_range", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      clientId: selectedClientId,
      errors: {
        kpi: kpiValidation.error,
        trends: trendsValidation.error,
        reasons: reasonsValidation.error,
        intents: intentsValidation.error,
      },
    });
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    return res.status(400).send(`
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Invalid Date Range</title></head>
<body>
  <h1>Invalid Date Range</h1>
  <p>One or more date ranges are invalid. Date ranges must be between 7 and 90 days.</p>
  <p><a href="/admin/analytics">Try again</a></p>
</body>
</html>
    `);
  }

  // Execute queries (fail-safe: empty results on error)
  let kpiData = {};
  let trendsData = {};
  let escalationData = {};
  let intentData = {};
  let smokeTestResult = null;

  try {
    // Smoke test: run a simple query to validate dataset/time window connectivity
    // This helps diagnose if the issue is dataset/time range or query-specific
    try {
      const { runQuery } = require("../lib/axiomClient");
      const dataset = process.env.AXIOM_DATASET || "advantum-prod-log";
      const smokeTestQuery = `['${dataset}']
| where event == "request_end"
| where route == "/chat"
| take 1`;
      
      const smokeTestRows = await runQuery({
        queryText: smokeTestQuery,
        params: {
          start_time: kpiStartDate.toISOString(),
          end_time: kpiEndDate.toISOString(),
          dataset: dataset,
        },
        dataset: dataset,
      });
      
      smokeTestResult = {
        rowsReturned: smokeTestRows.length,
        dataset: dataset,
        timeRange: {
          start: kpiStartDate.toISOString(),
          end: kpiEndDate.toISOString(),
        },
      };
      
      logAdminEvent("info", "admin_analytics_smoke_test", {
        requestId: requestId,
        ip: ip,
        userEmail: userEmail,
        clientId: selectedClientId,
        smokeTestResult: smokeTestResult,
        note: "Smoke test query completed (server-side diagnostic)",
      });
    } catch (smokeError) {
      // Fail-safe: don't block analytics page if smoke test fails
      logAdminEvent("warn", "admin_analytics_smoke_test_failed", {
        requestId: requestId,
        ip: ip,
        userEmail: userEmail,
        clientId: selectedClientId,
        error: smokeError?.message || String(smokeError),
        note: "Smoke test failed (non-blocking)",
      });
    }
    // Headline KPIs (using kpi date range)
    const [totalChats, botHandledPct, totalEscalations, moneySaved, avgResponseTimeData] = await Promise.all([
      executeQuery("total_chats_v1", selectedClientId, kpiStartDate, kpiEndDate).catch(() => ({ totalChats: 0 })),
      executeQuery("bot_handled_pct_v1", selectedClientId, kpiStartDate, kpiEndDate).catch(() => ({ botHandledPct: 0 })),
      executeQuery("total_escalations_v1", selectedClientId, kpiStartDate, kpiEndDate).catch(() => ({ totalEscalations: 0 })),
      executeQuery("money_saved_total_v1", selectedClientId, kpiStartDate, kpiEndDate).catch(() => ({ estimatedSavedEUR: 0, estimatedSavedEURDisplay: "€0.00" })),
      executeQuery("avg_response_time_by_day_v1", selectedClientId, kpiStartDate, kpiEndDate).catch(() => ({ series: [], weightedAvg: 0 })),
    ]);

    kpiData = {
      totalChats: totalChats.totalChats || 0,
      botHandledPct: botHandledPct.botHandledPct || 0,
      totalEscalations: totalEscalations.totalEscalations || 0,
      moneySaved: moneySaved.estimatedSavedEURDisplay || "€0.00",
      avgResponseTime: avgResponseTimeData.weightedAvg || 0,
    };

    // Volume & Trends (using trends date range)
    const [chatsPerDay, botHandlingOverTime, escalationsPerDay, moneySavedPerDay, avgResponseTimeSeries] = await Promise.all([
      executeQuery("chats_per_day_v1", selectedClientId, trendsStartDate, trendsEndDate).catch(() => ({ series: [] })),
      executeQuery("bot_handling_over_time_v1", selectedClientId, trendsStartDate, trendsEndDate).catch(() => ({ series: [] })),
      executeQuery("escalations_per_day_v1", selectedClientId, trendsStartDate, trendsEndDate).catch(() => ({ series: [] })),
      executeQuery("money_saved_per_day_v1", selectedClientId, trendsStartDate, trendsEndDate).catch(() => ({ series: [] })),
      executeQuery("avg_response_time_by_day_v1", selectedClientId, trendsStartDate, trendsEndDate).catch(() => ({ series: [] })),
    ]);

    trendsData = {
      chatsPerDay: chatsPerDay.series || [],
      botHandlingOverTime: botHandlingOverTime.series || [],
      escalationsPerDay: escalationsPerDay.series || [],
      moneySavedPerDay: moneySavedPerDay.series || [],
      avgResponseTimeSeries: avgResponseTimeSeries.series || [],
    };

    // Escalation Insights (using reasons date range for breakdown, kpi range for rate)
    const [escalationRate, escalationReasons] = await Promise.all([
      executeQuery("escalation_rate_pct_v1", selectedClientId, kpiStartDate, kpiEndDate).catch(() => ({ escalationPercentage: 0 })),
      executeQuery("escalation_reasons_breakdown_v1", selectedClientId, reasonsStartDate, reasonsEndDate).catch(() => ({ breakdown: [] })),
    ]);

    escalationData = {
      escalationRate: escalationRate.escalationPercentage || 0,
      reasonsBreakdown: escalationReasons.breakdown || [],
    };

    // Intent & Usage (using intents date range)
    const topIntents = await executeQuery("top_intents_v1", selectedClientId, intentsStartDate, intentsEndDate).catch(() => ({ intents: [] }));
    intentData = {
      topIntents: topIntents.intents || [],
    };

    logAdminEvent("info", "admin_analytics_view", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      clientId: selectedClientId,
      kpiRangeDays: kpiRangeDays,
      trendsRangeDays: trendsRangeDays,
      reasonsRangeDays: reasonsRangeDays,
      intentsRangeDays: intentsRangeDays,
    });
  } catch (error) {
    logAdminEvent("error", "admin_analytics_query_error", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      clientId: selectedClientId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    // Continue with empty data (fail-safe)
  }

  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  // Render analytics page
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Analytics - ${escapeHtml(selectedClientId)}</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { margin-top: 0; }
    h2 { border-bottom: 2px solid #007bff; padding-bottom: 5px; margin-top: 30px; }
    h3 { margin-top: 20px; color: #555; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .kpi-card { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 15px; text-align: center; }
    .kpi-value { font-size: 2em; font-weight: bold; color: #007bff; margin: 10px 0; }
    .kpi-label { color: #666; font-size: 0.9em; }
    .date-range-selector { margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; }
    .date-range-selector label { margin-right: 10px; }
    .date-range-selector select { padding: 5px; margin-right: 15px; }
    .date-range-selector button { padding: 5px 15px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    table th, table td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    table th { background: #f8f9fa; font-weight: bold; }
    .empty-state { padding: 40px; text-align: center; color: #666; }
    .client-selector { margin: 20px 0; }
    .client-selector select { padding: 5px 10px; font-size: 1em; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Analytics</h1>
    <p style="color: #666; font-size: 0.9em;">Logged in as <strong>${escapeHtml(userEmail)}</strong></p>
    ${renderNav("analytics", csrfToken)}
    
    ${authorizedClientIds.length > 1 ? `
    <div class="client-selector">
      <label>Client: 
        <select onchange="window.location.href='/admin/analytics?clientId=' + this.value">
          ${authorizedClientIds.map(id => `
            <option value="${escapeHtml(id)}" ${id === selectedClientId ? "selected" : ""}>${escapeHtml(id)}</option>
          `).join("")}
        </select>
      </label>
    </div>
    ` : `<p><strong>Client:</strong> ${escapeHtml(selectedClientId)}</p>`}

    <div class="date-range-selector">
      <form method="GET" action="/admin/analytics" style="display: inline;">
        ${authorizedClientIds.length > 1 ? `<input type="hidden" name="clientId" value="${escapeHtml(selectedClientId)}">` : ""}
        <label>KPIs & Trends Range:</label>
        <select name="kpiRange">
          <option value="7" ${kpiRangeDays === 7 ? "selected" : ""}>Last 7 days</option>
          <option value="30" ${kpiRangeDays === 30 ? "selected" : ""}>Last 30 days</option>
          <option value="60" ${kpiRangeDays === 60 ? "selected" : ""}>Last 60 days</option>
          <option value="90" ${kpiRangeDays === 90 ? "selected" : ""}>Last 90 days</option>
        </select>
        <input type="hidden" name="trendsRange" value="${kpiRangeDays}">
        <label>Reasons & Intents Range:</label>
        <select name="reasonsRange">
          <option value="30" ${reasonsRangeDays === 30 ? "selected" : ""}>Last 30 days</option>
          <option value="60" ${reasonsRangeDays === 60 ? "selected" : ""}>Last 60 days</option>
          <option value="90" ${reasonsRangeDays === 90 ? "selected" : ""}>Last 90 days</option>
        </select>
        <input type="hidden" name="intentsRange" value="${reasonsRangeDays}">
        <button type="submit">Update</button>
      </form>
    </div>

    <h2>Headline KPIs (Last ${kpiRangeDays} days)</h2>
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Conversations</div>
        <div class="kpi-value">${kpiData.totalChats || 0}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Bot Handling Rate</div>
        <div class="kpi-value">${(kpiData.botHandledPct || 0).toFixed(1)}%</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Total Escalations</div>
        <div class="kpi-value">${kpiData.totalEscalations || 0}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Estimated Money Saved</div>
        <div class="kpi-value">${kpiData.moneySaved || "€0.00"}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Average Response Time</div>
        <div class="kpi-value">${kpiData.avgResponseTime || 0}ms</div>
      </div>
    </div>

    <h2>Volume & Trends (Last ${trendsRangeDays} days)</h2>
    ${trendsData.chatsPerDay && trendsData.chatsPerDay.length > 0 ? `
    <h3>Chats per Day</h3>
    <table>
      <thead><tr><th>Date</th><th>Chats</th></tr></thead>
      <tbody>
        ${trendsData.chatsPerDay.map(item => `
          <tr><td>${item.date ? new Date(item.date).toLocaleDateString() : "N/A"}</td><td>${item.chats || 0}</td></tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No data for selected period.</div>`}

    ${trendsData.botHandlingOverTime && trendsData.botHandlingOverTime.length > 0 ? `
    <h3>Bot Handling Rate Over Time</h3>
    <table>
      <thead><tr><th>Date</th><th>Bot Handling Rate</th><th>Bot Handled</th><th>Escalated</th><th>Total</th></tr></thead>
      <tbody>
        ${trendsData.botHandlingOverTime.map(item => `
          <tr>
            <td>${item.date ? new Date(item.date).toLocaleDateString() : "N/A"}</td>
            <td>${(item.botHandlingRatePct || 0).toFixed(1)}%</td>
            <td>${item.botHandledChats || 0}</td>
            <td>${item.escalatedChats || 0}</td>
            <td>${item.totalChats || 0}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No data for selected period.</div>`}

    ${trendsData.escalationsPerDay && trendsData.escalationsPerDay.length > 0 ? `
    <h3>Escalations per Day</h3>
    <table>
      <thead><tr><th>Date</th><th>Escalations</th></tr></thead>
      <tbody>
        ${trendsData.escalationsPerDay.map(item => `
          <tr><td>${item.date ? new Date(item.date).toLocaleDateString() : "N/A"}</td><td>${item.escalations || 0}</td></tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No data for selected period.</div>`}

    ${trendsData.moneySavedPerDay && trendsData.moneySavedPerDay.length > 0 ? `
    <h3>Money Saved per Day</h3>
    <table>
      <thead><tr><th>Date</th><th>Money Saved</th></tr></thead>
      <tbody>
        ${trendsData.moneySavedPerDay.map(item => `
          <tr><td>${item.date ? new Date(item.date).toLocaleDateString() : "N/A"}</td><td>${item.estimatedSavedEUR || "€0.00"}</td></tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No data for selected period.</div>`}

    ${trendsData.avgResponseTimeSeries && trendsData.avgResponseTimeSeries.length > 0 ? `
    <h3>Average Response Time per Day</h3>
    <table>
      <thead><tr><th>Date</th><th>Avg Response Time (ms)</th></tr></thead>
      <tbody>
        ${trendsData.avgResponseTimeSeries.map(item => `
          <tr><td>${item.date ? new Date(item.date).toLocaleDateString() : "N/A"}</td><td>${item.avgLatencyMs || 0}</td></tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No data for selected period.</div>`}

    <h2>Escalation Insights</h2>
    <div class="kpi-card" style="max-width: 300px;">
      <div class="kpi-label">Escalation Rate (Last ${kpiRangeDays} days)</div>
      <div class="kpi-value">${(escalationData.escalationRate || 0).toFixed(1)}%</div>
    </div>

    ${escalationData.reasonsBreakdown && escalationData.reasonsBreakdown.length > 0 ? `
    <h3>Escalation Reasons Breakdown (Last ${reasonsRangeDays} days)</h3>
    <table>
      <thead><tr><th>Reason</th><th>Escalations</th></tr></thead>
      <tbody>
        ${escalationData.reasonsBreakdown.map(item => `
          <tr><td>${escapeHtml(item.reason || "Unknown")}</td><td>${item.escalations || 0}</td></tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No escalation data for selected period.</div>`}

    <h2>Intent & Usage</h2>
    ${intentData.topIntents && intentData.topIntents.length > 0 ? `
    <h3>Top Customer Intents (Last ${intentsRangeDays} days)</h3>
    <table>
      <thead><tr><th>Intent</th><th>Chats</th></tr></thead>
      <tbody>
        ${intentData.topIntents.map(item => `
          <tr><td>${escapeHtml(item.intent || "Unknown")}</td><td>${item.chats || 0}</td></tr>
        `).join("")}
      </tbody>
    </table>
    ` : `<div class="empty-state">No intent data for selected period.</div>`}
  </div>
</body>
</html>
  `;

  res.send(html);
});

// Analytics health check (GET /admin/analytics/health) - super_admin only, for debugging Axiom connectivity
router.get("/analytics/health", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const userEmail = req.session?.admin?.email || null;

  // Super admin only
  if (!isSuperAdmin(req)) {
    logAdminEvent("warn", "admin_analytics_health_denied", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      reason: "not_super_admin",
    });
    return res.status(403).json({ error: "Access denied", message: "Only super administrators can access this endpoint" });
  }

  try {
    // Run a simple test query: count chats in last 1 day
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 1);

    const testQueryText = `['advantum-prod-log']
| where event == "request_end"
| where route == "/chat"
| summarize totalChats = count()`;

    const { runQuery } = require("../lib/axiomClient");
    const rows = await runQuery({
      queryText: testQueryText,
      params: {
        start_time: startDate.toISOString(),
        end_time: endDate.toISOString(),
      },
    });

    const result = {
      status: "ok",
      timestamp: new Date().toISOString(),
      testQuery: {
        startTime: startDate.toISOString(),
        endTime: endDate.toISOString(),
        rowsReturned: rows.length,
        sampleRow: rows[0] || null,
      },
      config: {
        hasApiToken: !!process.env.AXIOM_API_TOKEN,
        hasApiUrl: !!process.env.AXIOM_API_URL,
        hasOrgId: !!process.env.AXIOM_ORG_ID,
        apiUrl: process.env.AXIOM_API_URL || "https://api.axiom.co",
      },
    };

    logAdminEvent("info", "admin_analytics_health_check", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      rowsReturned: rows.length,
    });

    return res.json(result);
  } catch (error) {
    logAdminEvent("error", "admin_analytics_health_check_error", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });

    return res.status(500).json({
      status: "error",
      error: error?.message || String(error),
      timestamp: new Date().toISOString(),
    });
  }
});

// Axiom ingestion health check (GET /admin/axiom/ingest-health) - super_admin only
router.get("/axiom/ingest-health", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const userEmail = req.session?.admin?.email || null;

  // Super admin only
  if (!isSuperAdmin(req)) {
    logAdminEvent("warn", "admin_axiom_ingest_health_denied", {
      requestId: requestId,
      ip: ip,
      userEmail: userEmail,
      reason: "not_super_admin",
    });
    return res.status(403).json({ error: "Access denied", message: "Only super administrators can access this endpoint" });
  }

  // Check Axiom ingestion configuration (read from index.js env vars)
  const AXIOM_TOKEN = process.env.AXIOM_API_TOKEN || process.env.AXIOM_TOKEN;
  const AXIOM_DATASET = process.env.AXIOM_DATASET;
  const AXIOM_ENABLED = Boolean(AXIOM_TOKEN && AXIOM_DATASET);

  logAdminEvent("info", "admin_axiom_ingest_health_check", {
    requestId: requestId,
    ip: ip,
    userEmail: userEmail,
    enabled: AXIOM_ENABLED,
    hasToken: !!AXIOM_TOKEN,
    hasDataset: !!AXIOM_DATASET,
  });

  return res.json({
    enabled: AXIOM_ENABLED,
    hasToken: !!AXIOM_TOKEN,
    hasDataset: !!AXIOM_DATASET,
    dataset: AXIOM_DATASET || null,
  });
});

module.exports = router;

/*
HOW TO TEST (Manual Checklist):
1. Login: Visit /admin, login with ADMIN_EMAIL/ADMIN_PASSWORD env vars
2. Go to Clients: Click "Clients" in navigation, should see list of client IDs (Advantum, testbrand, etc.)
3. Create Client:
   - Fill in "Client ID" field (e.g., "TestClient") - must start with letter, 2-40 chars
   - Optionally fill in "Display Name"
   - Click "Create Client"
   - Should redirect to edit page with "✓ Client created successfully!" message
   - Verify Clients/TestClient/client-config.json exists with default config
4. Edit Client: Click a client ID, should show edit form with current config values pre-filled
5. Edit and Save:
   - Change widget.title to a new value (max 60 chars)
   - Change widget.greeting to a new value (max 240 chars)
   - Change colors.primary to a valid hex color (e.g., #FF0000)
   - Click "Save Changes"
6. Verify: Should redirect with "✓ Changes saved successfully!" message
7. Verify File: Check Clients/<clientId>/client-config.json on server, should contain updated values
8. Reload: Refresh the edit page, form should show the updated values (persistence confirmed)
9. Embed Instructions: Check edit page shows embed instructions with correct clientId
10. Delete Client:
    - Scroll to "Delete Client" section
    - Type the client ID exactly to confirm
    - Click "Delete Client"
    - Should redirect to /admin/clients with "✓ Client deleted successfully!" message
    - Verify Clients/<clientId>/client-config.json no longer exists
    - Verify "Advantum" cannot be deleted (protected client)
11. Test Validation:
    - Try creating client with invalid ID (starts with number, too short, special chars)
    - Try saving with invalid color or URL not starting with https://, should show validation error
12. Test Protection: Logout, try accessing /admin/clients directly, should redirect to login
13. Widget Still Works: Verify /widget-config?client=<clientId> still returns correct config for existing clients
*/

