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
function createClient(clientId, displayName = null) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }
  
  const pathResult = getClientConfigPath(validation.clientId);
  if (!pathResult.valid) {
    return { success: false, error: "Invalid client ID path" };
  }
  
  // Check if client already exists (409 Conflict)
  if (fs.existsSync(pathResult.path)) {
    return { success: false, error: "Client already exists", statusCode: 409 };
  }
  
  try {
    // Create default config
    const defaultConfig = createDefaultConfig(validation.clientId, displayName);
    const writeResult = writeClientConfigAtomic(validation.clientId, defaultConfig);
    
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

// Delete client wrapper with protection for "Advantum"
function deleteClientSafe(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }
  
  // Safety: prevent deleting "Advantum" as a protected client
  if (validation.clientId === "Advantum") {
    return { success: false, error: "Cannot delete protected client" };
  }
  
  return deleteClient(validation.clientId);
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
  const ip = getClientIp(req);
  logAdminEvent("info", "admin_clients_list_view", {
    event: "admin_clients_list_view",
    requestId: requestId,
    ip: ip,
  });

  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);

  const clients = listClientIds();
  const created = req.query.created === "1";
  const deleted = req.query.deleted === "1";
  const clientsRoot = getClientsRoot();
  
  const successMessage = created ? '<p style="color: green; font-weight: bold;">✓ Client created successfully!</p>' : '';
  const deletedMessage = deleted ? '<p style="color: green; font-weight: bold;">✓ Client deleted successfully!</p>' : '';
  
  const clientsList = clients.length > 0
    ? `<ul>${clients.map(clientId => `<li><a href="/admin/clients/${encodeURIComponent(clientId)}">${escapeHtml(clientId)}</a></li>`).join("")}</ul>`
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
  ${renderNav("clients", csrfToken)}
  <h2>Clients</h2>
  ${successMessage}
  ${deletedMessage}
  <div style="margin-bottom: 20px; padding: 10px; background: #e7f3ff; border: 1px solid #b3d9ff; border-radius: 4px;">
    <p><strong>Config storage path:</strong> <code>${escapeHtml(clientsRoot)}</code></p>
    <p style="margin-top: 5px; font-size: 0.9em; color: #666;">Clients created here are stored on the server; they will not appear in GitHub automatically.</p>
  </div>
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
  <h3>Existing Clients</h3>
  ${clientsList}
</body>
</html>
  `;
  res.send(html);
});

// Create client (POST /admin/clients)
router.post("/clients", requireAdminAuth, requireCsrf, (req, res) => {
  const requestId = req.requestId || "unknown";
  const ip = getClientIp(req);
  const { clientId, displayName } = req.body || {};
  
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
  
  const result = createClient(clientId, displayName);
  
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
  });
  
  // Redirect to edit page
  return res.redirect(`/admin/clients/${encodeURIComponent(clientId)}?created=1`);
});

// Client config editor (GET /admin/clients/:clientId)
router.get("/clients/:clientId", requireAdminAuth, (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientId = req.params.clientId;
  const saved = req.query.saved === "1";
  const created = req.query.created === "1";
  
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return res.status(400).send("Invalid client ID");
  }
  
  const config = readClientConfig(validation.clientId);
  if (!config) {
    return res.status(404).send("Client config not found");
  }
  
  const pathResult = getClientConfigPath(validation.clientId);
  const configStats = getClientConfigStats(validation.clientId);
  
  logAdminEvent("info", "admin_client_edit_view", {
    event: "admin_client_edit_view",
    requestId: requestId,
    clientId: validation.clientId,
  });
  
  const csrfToken = generateCsrfToken();
  setCsrfToken(req, csrfToken);
  
  const successMessage = saved ? '<p style="color: green; font-weight: bold;">✓ Changes saved successfully!</p>' : '';
  const createdMessage = created ? '<p style="color: green; font-weight: bold;">✓ Client created successfully!</p>' : '';
  
  const configPathInfo = configStats ? `
  <div style="margin-bottom: 20px; padding: 10px; background: #f5f5f5; border: 1px solid #ddd; border-radius: 4px;">
    <p><strong>Config file path:</strong> <code>${escapeHtml(pathResult.path)}</code></p>
    <p style="margin-top: 5px;"><strong>Last modified:</strong> ${escapeHtml(configStats.mtimeISO)}</p>
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
  ${renderNav("clients", csrfToken)}
  <h2>Edit Client: ${escapeHtml(validation.clientId)}</h2>
  ${createdMessage}
  ${successMessage}
  <p><a href="/admin/clients">← Back to clients</a></p>
  ${configPathInfo}
  <h3>Embed Instructions</h3>
  <div style="margin-bottom: 30px; padding: 15px; background: #f5f5f5; border: 1px solid #ddd;">
    <p><strong>For Shopify (.liquid):</strong></p>
    <p>Copy the <code>AI-support-bot.liquid</code> file content and replace the hardcoded clientId value with your client ID (${escapeHtml(validation.clientId)}).</p>
    <p>Then paste it in your theme's layout file (theme.liquid) before the closing <code>&lt;/body&gt;</code> tag, or add it as a section/snippet in the theme customizer.</p>
    <p><strong>Important:</strong> Make sure to set <code>var clientId = "${escapeHtml(validation.clientId)}";</code> in the script.</p>
  </div>
  
  <form method="POST" action="/admin/clients/${encodeURIComponent(validation.clientId)}" style="max-width: 800px;">
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
</body>
</html>
  `;
  res.send(html);
});

// Client config update (POST /admin/clients/:clientId) - form submission
router.post("/clients/:clientId", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientIdRaw = req.params.clientId;
  
  const validation = validateClientId(clientIdRaw);
  if (!validation.valid) {
    return res.status(400).send("Invalid client ID");
  }
  const clientId = validation.clientId;
  
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
  
  // Validate clientId and get path (use clientsStore)
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid || !fs.existsSync(pathResult.path)) {
    return res.status(404).send("Client config not found");
  }
  
  try {
    // Read existing config (use clientsStore)
    const existingConfig = readClientConfig(clientId);
    if (!existingConfig) {
      return res.status(404).send("Client config not found");
    }
    
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

// Delete client (POST /admin/clients/:clientId/delete)
router.post("/clients/:clientId/delete", requireAdminAuth, requireCsrf, (req, res) => {
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

