const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
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

// Helper: Get Clients directory root (same logic as index.js)
function getClientsRoot() {
  // Try multiple possible locations for Clients directory
  // 1. From Backend/admin/ -> ../.. -> repo root -> Clients
  const fromAdminDir = path.resolve(__dirname, "..", "..", "Clients");
  // 2. From Backend/ -> Clients (matching index.js approach, though it may not exist)
  const fromBackendDir = path.resolve(__dirname, "..", "Clients");
  // 3. Try process.cwd() + Clients (if running from repo root)
  const fromCwd = path.resolve(process.cwd(), "Clients");
  
  // Check which one exists (prefer fromAdminDir first)
  if (fs.existsSync(fromAdminDir)) {
    return fromAdminDir;
  }
  if (fs.existsSync(fromBackendDir)) {
    return fromBackendDir;
  }
  if (fs.existsSync(fromCwd)) {
    return fromCwd;
  }
  // Default to fromAdminDir even if it doesn't exist (will error later)
  return fromAdminDir;
}

// Helper: Get client list from Clients directory
function getClientList() {
  try {
    const clientsRoot = getClientsRoot();
    logAdminEvent("debug", "admin_clients_list_scan", {
      event: "admin_clients_list_scan",
      clientsRoot: clientsRoot,
      exists: fs.existsSync(clientsRoot),
    });
    
    if (!fs.existsSync(clientsRoot)) {
      logAdminEvent("warn", "admin_clients_root_not_found", {
        event: "admin_clients_root_not_found",
        clientsRoot: clientsRoot,
      });
      return [];
    }
    
    const entries = fs.readdirSync(clientsRoot, { withFileTypes: true });
    const clients = entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .filter(name => /^[a-zA-Z0-9_-]{1,40}$/.test(name))
      .sort();
    
    logAdminEvent("info", "admin_clients_list_found", {
      event: "admin_clients_list_found",
      clientsRoot: clientsRoot,
      count: clients.length,
      clientIds: clients,
    });
    
    return clients;
  } catch (error) {
    logAdminEvent("error", "admin_clients_list_error", {
      event: "admin_clients_list_error",
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 200) : null,
    });
    return [];
  }
}

// Helper: Get client config path (with path traversal protection)
function getClientConfigPath(clientId) {
  if (!clientId || typeof clientId !== "string" || !/^[a-zA-Z0-9_-]{1,40}$/.test(clientId.trim())) {
    return null;
  }
  const clientsRoot = getClientsRoot();
  const clientDir = path.join(clientsRoot, clientId.trim());
  const configPath = path.join(clientDir, "client-config.json");
  const resolvedPath = path.resolve(configPath);
  const clientsRootNormalized = path.normalize(clientsRoot);
  const resolvedNormalized = path.normalize(resolvedPath);
  if (!resolvedNormalized.startsWith(clientsRootNormalized + path.sep) && resolvedNormalized !== clientsRootNormalized) {
    return null;
  }
  return resolvedPath;
}

// Helper: Render navigation HTML
function renderNav(currentPage = "dashboard", csrfToken) {
  const navItems = [
    { path: "/admin", label: "Dashboard", active: currentPage === "dashboard" },
    { path: "/admin/clients", label: "Clients", active: currentPage === "clients" },
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
        <button type="submit" style="background: #dc3545; color: white; border: none; padding: 5px 10px; cursor: pointer;">Logout</button>
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
  <p>Logged in as <strong>${escapeHtml(adminEmail)}</strong></p>
  ${renderNav("dashboard", csrfToken)}
  <h2>Dashboard</h2>
  <p>Welcome to the admin portal. Use the navigation above to manage clients.</p>
</body>
</html>
  `;
  res.send(html);
});

// Clients list (GET /admin/clients)
router.get("/clients", requireAdminAuth, (req, res) => {
  const requestId = req.requestId || "unknown";
  logAdminEvent("info", "admin_clients_list_view", {
    event: "admin_clients_list_view",
    requestId: requestId,
  });

  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  const clients = getClientList();
  const clientsRoot = getClientsRoot();
  
  // DEBUG: Log the scan results
  logAdminEvent("debug", "admin_clients_list_debug", {
    event: "admin_clients_list_debug",
    requestId: requestId,
    clientsRoot: clientsRoot,
    clientsFound: clients.length,
    clientIds: clients,
  });
  
  const clientsList = clients.length > 0
    ? `<ul>${clients.map(clientId => `<li><a href="/admin/clients/${escapeHtml(clientId)}">${escapeHtml(clientId)}</a></li>`).join("")}</ul>`
    : `<p>No clients found. (Scanned: ${escapeHtml(clientsRoot)})</p>`;

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
  ${renderNav("clients", csrfToken)}
  <h2>Clients</h2>
  ${clientsList}
</body>
</html>
  `;
  res.send(html);
});

// Client config editor (GET /admin/clients/:clientId)
router.get("/clients/:clientId", requireAdminAuth, (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientId = req.params.clientId;
  const saved = req.query.saved === "1";
  
  if (!clientId || typeof clientId !== "string" || !/^[a-zA-Z0-9_-]{1,40}$/.test(clientId.trim())) {
    return res.status(400).send("Invalid client ID");
  }
  
  const configPath = getClientConfigPath(clientId);
  if (!configPath || !fs.existsSync(configPath)) {
    return res.status(404).send("Client config not found");
  }
  
  try {
    const configContent = fs.readFileSync(configPath, "utf8");
    const config = JSON.parse(configContent);
    
    logAdminEvent("info", "admin_client_edit_view", {
      event: "admin_client_edit_view",
      requestId: requestId,
      clientId: clientId,
    });
    
    const csrfToken = generateCsrfToken();
    setCsrfToken(req, csrfToken);
    
    const successMessage = saved ? '<p style="color: green; font-weight: bold;">✓ Changes saved successfully!</p>' : '';
    
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
    
    const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Portal - Edit ${escapeHtml(clientId)}</title>
</head>
<body>
  <h1>Admin Portal</h1>
  ${renderNav("clients", csrfToken)}
  <h2>Edit Client: ${escapeHtml(clientId)}</h2>
  ${successMessage}
  <p><a href="/admin/clients">← Back to clients</a></p>
  
  <form method="POST" action="/admin/clients/${escapeHtml(clientId)}" style="max-width: 800px;">
    <input type="hidden" name="csrfToken" value="${csrfToken}">
    
    <h3>Colors</h3>
    <div style="margin-bottom: 15px;">
      <label>Primary: <input type="text" name="colors[primary]" value="${escapeHtml(getValue(config, "colors.primary", ""))}" style="width: 200px;"></label><br>
      <label>Accent: <input type="text" name="colors[accent]" value="${escapeHtml(getValue(config, "colors.accent", ""))}" style="width: 200px;"></label><br>
      <label>Background: <input type="text" name="colors[background]" value="${escapeHtml(getValue(config, "colors.background", ""))}" style="width: 200px;"></label><br>
      <label>User Bubble: <input type="text" name="colors[userBubble]" value="${escapeHtml(getValue(config, "colors.userBubble", ""))}" style="width: 200px;"></label><br>
      <label>Bot Bubble: <input type="text" name="colors[botBubble]" value="${escapeHtml(getValue(config, "colors.botBubble", ""))}" style="width: 200px;"></label><br>
    </div>
    
    <h3>Widget</h3>
    <div style="margin-bottom: 15px;">
      <label>Title: <input type="text" name="widget[title]" value="${escapeHtml(getValue(config, "widget.title", ""))}" style="width: 400px;" maxlength="60"></label><br>
      <label>Greeting: <textarea name="widget[greeting]" style="width: 400px; height: 60px;" maxlength="240">${escapeHtml(getValue(config, "widget.greeting", ""))}</textarea></label><br>
    </div>
    
    <h3>Logo URL</h3>
    <div style="margin-bottom: 15px;">
      <label>Logo URL: <input type="text" name="logoUrl" value="${escapeHtml(getValue(config, "logoUrl", ""))}" style="width: 500px;" maxlength="300"></label><br>
    </div>
    
    <h3>Entry Screen</h3>
    <div style="margin-bottom: 15px;">
      <label><input type="checkbox" name="entryScreen[enabled]" ${getValue(config, "entryScreen.enabled", false) ? "checked" : ""}> Enabled</label><br>
      <label>Title: <input type="text" name="entryScreen[title]" value="${escapeHtml(getValue(config, "entryScreen.title", ""))}" style="width: 400px;" maxlength="60"></label><br>
      <label>Disclaimer: <textarea name="entryScreen[disclaimer]" style="width: 400px; height: 60px;" maxlength="240">${escapeHtml(getValue(config, "entryScreen.disclaimer", ""))}</textarea></label><br>
      <label>Primary Button Label: <input type="text" name="entryScreen[primaryButton][label]" value="${escapeHtml(getValue(config, "entryScreen.primaryButton.label", ""))}" style="width: 300px;" maxlength="30"></label><br>
      <label>Secondary Button 1 Label: <input type="text" name="entryScreen[secondaryButtons][0][label]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.0.label", ""))}" style="width: 300px;" maxlength="30"></label><br>
      <label>Secondary Button 1 URL: <input type="text" name="entryScreen[secondaryButtons][0][url]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.0.url", ""))}" style="width: 400px;" maxlength="200"></label><br>
      <label>Secondary Button 2 Label: <input type="text" name="entryScreen[secondaryButtons][1][label]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.1.label", ""))}" style="width: 300px;" maxlength="30"></label><br>
      <label>Secondary Button 2 URL: <input type="text" name="entryScreen[secondaryButtons][1][url]" value="${escapeHtml(getValue(config, "entryScreen.secondaryButtons.1.url", ""))}" style="width: 400px;" maxlength="200"></label><br>
    </div>
    
    <h3>Support</h3>
    <div style="margin-bottom: 15px;">
      <label>Email: <input type="email" name="support[email]" value="${escapeHtml(getValue(config, "support.email", ""))}" style="width: 300px;" maxlength="120"></label><br>
      <label>Contact URL: <input type="text" name="support[contactUrl]" value="${escapeHtml(getValue(config, "support.contactUrl", ""))}" style="width: 500px;" maxlength="200"></label><br>
      <label>Contact URL Message Param: <input type="text" name="support[contactUrlMessageParam]" value="${escapeHtml(getValue(config, "support.contactUrlMessageParam", ""))}" style="width: 200px;" maxlength="30"></label><br>
    </div>
    
    <button type="submit" style="background: #28a745; color: white; border: none; padding: 10px 20px; cursor: pointer; font-size: 16px;">Save Changes</button>
  </form>
</body>
</html>
    `;
    res.send(html);
  } catch (error) {
    logAdminEvent("error", "admin_client_edit_error", {
      event: "admin_client_edit_error",
      requestId: requestId,
      clientId: clientId,
      error: error?.message || String(error),
    });
    return res.status(500).send("Error loading client config");
  }
});

// Client config update (POST /admin/clients/:clientId) - form submission
router.post("/clients/:clientId", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientId = req.params.clientId;
  
  if (!clientId || typeof clientId !== "string" || !/^[a-zA-Z0-9_-]{1,40}$/.test(clientId.trim())) {
    return res.status(400).send("Invalid client ID");
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
  
  // Use the API validation logic by importing it
  const adminApiRoutes = require("./adminApiRoutes");
  const validateConfigUpdate = adminApiRoutes.validateConfigUpdate;
  const getApiClientConfigPath = adminApiRoutes.getClientConfigPath;
  
  // Validate clientId and get path (reuse API logic)
  const pathResult = getApiClientConfigPath(clientId);
  if (!pathResult.valid || !fs.existsSync(pathResult.path)) {
    return res.status(404).send("Client config not found");
  }
  
  try {
    // Read existing config
    const existingContent = fs.readFileSync(pathResult.path, "utf8");
    const existingConfig = JSON.parse(existingContent);
    
    // Validate update (reuse API validation)
    const validationResult = validateConfigUpdate(updateData);
    if (validationResult.errors.length > 0) {
      logAdminEvent("warn", "admin_client_update_validation_failed", {
        event: "admin_client_update_validation_failed",
        requestId: requestId,
        clientId: clientId,
        errors: validationResult.errors,
      });
      return res.status(400).send(`Validation failed: ${validationResult.errors.join(", ")}`);
    }
    
    // Merge allowed fields into existing config
    const updatedConfig = JSON.parse(JSON.stringify(existingConfig));
    if (validationResult.allowed.colors) {
      updatedConfig.colors = { ...updatedConfig.colors, ...validationResult.allowed.colors };
    }
    if (validationResult.allowed.widget) {
      updatedConfig.widget = { ...updatedConfig.widget, ...validationResult.allowed.widget };
    }
    if (validationResult.allowed.logoUrl !== undefined) {
      updatedConfig.logoUrl = validationResult.allowed.logoUrl;
    }
    if (validationResult.allowed.entryScreen) {
      updatedConfig.entryScreen = { ...updatedConfig.entryScreen, ...validationResult.allowed.entryScreen };
      if (validationResult.allowed.entryScreen.primaryButton) {
        updatedConfig.entryScreen.primaryButton = {
          ...updatedConfig.entryScreen.primaryButton,
          ...validationResult.allowed.entryScreen.primaryButton,
        };
      }
      if (validationResult.allowed.entryScreen.secondaryButtons !== undefined) {
        updatedConfig.entryScreen.secondaryButtons = validationResult.allowed.entryScreen.secondaryButtons;
      }
    }
    if (validationResult.allowed.support) {
      updatedConfig.support = { ...updatedConfig.support, ...validationResult.allowed.support };
    }
    
    // Write updated config to disk
    const configJson = JSON.stringify(updatedConfig, null, 2) + "\n";
    fs.writeFileSync(pathResult.path, configJson, "utf8");
    const bytesWritten = Buffer.byteLength(configJson, "utf8");
    const writtenEntryScreenTitle = updatedConfig.entryScreen?.title || null;
    
    // Note: /widget-config reads fresh from disk (bypasses clientRegistry cache), so no cache invalidation needed
    
    logAdminEvent("info", "admin_client_update_persisted", {
      event: "admin_client_update_persisted",
      requestId: requestId,
      clientId: clientId,
      writtenPath: pathResult.path,
      writtenEntryScreenTitle: writtenEntryScreenTitle,
      bytesWritten: bytesWritten,
    });
    
    logAdminEvent("info", "admin_client_update_success", {
      event: "admin_client_update_success",
      requestId: requestId,
      clientId: clientId,
      updatedFields: Object.keys(validationResult.allowed),
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

/*
HOW TO TEST (Manual Checklist):
1. Login: Visit /admin, login with ADMIN_EMAIL/ADMIN_PASSWORD env vars
2. Go to Clients: Click "Clients" in navigation, should see list of client IDs (Advantum, testbrand, etc.)
3. Edit Client: Click "Advantum", should show edit form with current config values pre-filled
4. Edit and Save: 
   - Change widget.title to a new value (max 60 chars)
   - Change widget.greeting to a new value (max 240 chars)
   - Change colors.primary to a valid hex color (e.g., #FF0000)
   - Click "Save Changes"
5. Verify: Should redirect with "✓ Changes saved successfully!" message
6. Verify File: Check Clients/Advantum/client-config.json on server, should contain updated values
7. Reload: Refresh the edit page, form should show the updated values (persistence confirmed)
8. Test Validation: Try saving with invalid color or URL not starting with https://, should show validation error
9. Test Protection: Logout, try accessing /admin/clients directly, should redirect to login
*/

