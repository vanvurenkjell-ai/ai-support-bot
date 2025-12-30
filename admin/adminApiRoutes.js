const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const { requireAdminAuth } = require("./auth");
const { requireCsrf } = require("./csrf");

// Simple logging helper
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

// Path traversal protection: validate clientId
function validateClientId(clientId) {
  if (!clientId || typeof clientId !== "string") {
    return { valid: false, reason: "missing_or_invalid_type" };
  }
  const trimmed = String(clientId).trim();
  if (trimmed.length === 0 || trimmed.length > 40) {
    return { valid: false, reason: "invalid_length" };
  }
  if (!/^[a-zA-Z0-9_-]{1,40}$/.test(trimmed)) {
    return { valid: false, reason: "invalid_chars" };
  }
  return { valid: true, clientId: trimmed };
}

// Get safe path to client config
function getClientConfigPath(clientId) {
  // Clients folder is at repo root, admin routes are in Backend/admin/
  const clientsRoot = path.resolve(__dirname, "..", "..", "Clients");
  const clientDir = path.join(clientsRoot, clientId);
  const configPath = path.join(clientDir, "client-config.json");
  
  // Resolve to absolute path
  const resolvedPath = path.resolve(configPath);
  const clientsRootNormalized = path.normalize(clientsRoot);
  const resolvedNormalized = path.normalize(resolvedPath);
  
  // Enforce containment
  if (!resolvedNormalized.startsWith(clientsRootNormalized + path.sep) && resolvedNormalized !== clientsRootNormalized) {
    return { valid: false, path: null, reason: "containment_failed" };
  }
  
  return { valid: true, path: resolvedPath, dir: clientDir };
}

// Get list of client IDs from Clients directory
function getClientList() {
  try {
    const clientsRoot = path.resolve(__dirname, "..", "..", "Clients");
    if (!fs.existsSync(clientsRoot)) {
      return [];
    }
    const entries = fs.readdirSync(clientsRoot, { withFileTypes: true });
    return entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .filter(name => /^[a-zA-Z0-9_-]{1,40}$/.test(name))
      .sort();
  } catch (error) {
    logAdminEvent("error", "admin_client_list_error", {
      error: error?.message || String(error),
    });
    return [];
  }
}

// Color validation: allow hex, rgb/rgba, or named colors
function isValidColor(color) {
  if (!color || typeof color !== "string") return false;
  const trimmed = color.trim();
  if (trimmed.length > 32) return false;
  
  // Hex colors: #RGB, #RRGGBB, #RRGGBBAA
  if (/^#[0-9A-Fa-f]{3,8}$/.test(trimmed)) return true;
  
  // rgb() or rgba()
  if (/^rgba?\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*(,\s*[\d.]+\s*)?\)$/.test(trimmed)) return true;
  
  // Named colors (letters only, common CSS color names)
  if (/^[a-zA-Z]+$/.test(trimmed)) return true;
  
  return false;
}

// URL validation: must start with https://
function isValidUrl(url, maxLength = 300) {
  if (!url || typeof url !== "string") return false;
  const trimmed = url.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return false;
  return trimmed.startsWith("https://");
}

// Email validation: must contain @
function isValidEmail(email, maxLength = 120) {
  if (!email || typeof email !== "string") return false;
  const trimmed = email.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return false;
  return trimmed.includes("@");
}

// Validate and sanitize config update
function validateConfigUpdate(input) {
  const errors = [];
  const allowed = {};
  
  // Colors
  if (input.colors) {
    allowed.colors = {};
    const colorFields = ["primary", "accent", "background", "userBubble", "botBubble"];
    for (const field of colorFields) {
      if (input.colors[field] !== undefined) {
        if (isValidColor(input.colors[field])) {
          allowed.colors[field] = String(input.colors[field]).trim();
        } else {
          errors.push(`colors.${field}`);
        }
      }
    }
  }
  
  // Widget
  if (input.widget) {
    allowed.widget = {};
    if (input.widget.title !== undefined) {
      const title = String(input.widget.title || "").trim();
      if (title.length <= 60) {
        allowed.widget.title = title;
      } else {
        errors.push("widget.title");
      }
    }
    if (input.widget.greeting !== undefined) {
      const greeting = String(input.widget.greeting || "").trim();
      if (greeting.length <= 200) {
        allowed.widget.greeting = greeting;
      } else {
        errors.push("widget.greeting");
      }
    }
  }
  
  // Logo URL
  if (input.logoUrl !== undefined) {
    if (isValidUrl(input.logoUrl, 300)) {
      allowed.logoUrl = String(input.logoUrl).trim();
    } else {
      errors.push("logoUrl");
    }
  }
  
  // Entry screen
  if (input.entryScreen) {
    allowed.entryScreen = {};
    if (input.entryScreen.enabled !== undefined) {
      allowed.entryScreen.enabled = Boolean(input.entryScreen.enabled);
    }
    if (input.entryScreen.title !== undefined) {
      const title = String(input.entryScreen.title || "").trim();
      if (title.length <= 80) {
        allowed.entryScreen.title = title;
      } else {
        errors.push("entryScreen.title");
      }
    }
    if (input.entryScreen.disclaimer !== undefined) {
      const disclaimer = String(input.entryScreen.disclaimer || "").trim();
      if (disclaimer.length <= 300) {
        allowed.entryScreen.disclaimer = disclaimer;
      } else {
        errors.push("entryScreen.disclaimer");
      }
    }
    if (input.entryScreen.primaryButton) {
      allowed.entryScreen.primaryButton = {};
      if (input.entryScreen.primaryButton.label !== undefined) {
        const label = String(input.entryScreen.primaryButton.label || "").trim();
        if (label.length <= 40) {
          allowed.entryScreen.primaryButton.label = label;
        } else {
          errors.push("entryScreen.primaryButton.label");
        }
      }
      if (input.entryScreen.primaryButton.action !== undefined) {
        if (input.entryScreen.primaryButton.action === "openChat") {
          allowed.entryScreen.primaryButton.action = "openChat";
        } else {
          errors.push("entryScreen.primaryButton.action");
        }
      }
    }
    if (input.entryScreen.secondaryButtons !== undefined) {
      if (Array.isArray(input.entryScreen.secondaryButtons)) {
        if (input.entryScreen.secondaryButtons.length <= 2) {
          allowed.entryScreen.secondaryButtons = [];
          for (let i = 0; i < input.entryScreen.secondaryButtons.length; i++) {
            const btn = input.entryScreen.secondaryButtons[i];
            if (btn && typeof btn === "object") {
              const label = String(btn.label || "").trim();
              const action = String(btn.action || "").trim();
              const url = String(btn.url || "").trim();
              if (label.length <= 40 && action === "link" && isValidUrl(url, 300)) {
                allowed.entryScreen.secondaryButtons.push({ label, action: "link", url });
              } else {
                errors.push(`entryScreen.secondaryButtons[${i}]`);
              }
            } else {
              errors.push(`entryScreen.secondaryButtons[${i}]`);
            }
          }
        } else {
          errors.push("entryScreen.secondaryButtons");
        }
      } else {
        errors.push("entryScreen.secondaryButtons");
      }
    }
  }
  
  // Support
  if (input.support) {
    allowed.support = {};
    if (input.support.email !== undefined) {
      if (isValidEmail(input.support.email, 120)) {
        allowed.support.email = String(input.support.email).trim();
      } else {
        errors.push("support.email");
      }
    }
    if (input.support.contactUrl !== undefined) {
      if (isValidUrl(input.support.contactUrl, 300)) {
        allowed.support.contactUrl = String(input.support.contactUrl).trim();
      } else {
        errors.push("support.contactUrl");
      }
    }
    if (input.support.contactUrlMessageParam !== undefined) {
      const param = String(input.support.contactUrlMessageParam || "").trim();
      if (param.length <= 40 && /^[a-zA-Z0-9_]+$/.test(param)) {
        allowed.support.contactUrlMessageParam = param;
      } else {
        errors.push("support.contactUrlMessageParam");
      }
    }
  }
  
  return { allowed, errors };
}

// GET /admin/api/clients - List all clients
router.get("/clients", requireAdminAuth, (req, res) => {
  const requestId = req.requestId || "unknown";
  try {
    const clients = getClientList();
    logAdminEvent("info", "admin_api_clients_list", {
      event: "admin_api_clients_list",
      requestId: requestId,
      count: clients.length,
    });
    return res.json({ clients });
  } catch (error) {
    logAdminEvent("error", "admin_api_clients_list_error", {
      event: "admin_api_clients_list_error",
      requestId: requestId,
      error: error?.message || String(error),
    });
    return res.status(500).json({ error: "Internal server error" });
  }
});

// GET /admin/api/clients/:clientId - Get client config
router.get("/clients/:clientId", requireAdminAuth, (req, res) => {
  const requestId = req.requestId || "unknown";
  const validation = validateClientId(req.params.clientId);
  
  if (!validation.valid) {
    logAdminEvent("warn", "admin_api_client_invalid_id", {
      event: "admin_api_client_invalid_id",
      requestId: requestId,
      clientId: req.params.clientId,
      reason: validation.reason,
    });
    return res.status(400).json({ error: "Invalid client ID" });
  }
  
  const pathResult = getClientConfigPath(validation.clientId);
  if (!pathResult.valid) {
    logAdminEvent("warn", "admin_api_client_path_error", {
      event: "admin_api_client_path_error",
      requestId: requestId,
      clientId: validation.clientId,
      reason: pathResult.reason,
    });
    return res.status(400).json({ error: "Invalid client ID" });
  }
  
  try {
    if (!fs.existsSync(pathResult.path)) {
      return res.status(404).json({ error: "Client config not found" });
    }
    
    const configContent = fs.readFileSync(pathResult.path, "utf8");
    const config = JSON.parse(configContent);
    
    logAdminEvent("info", "admin_api_client_get", {
      event: "admin_api_client_get",
      requestId: requestId,
      clientId: validation.clientId,
    });
    
    return res.json({ clientId: validation.clientId, config });
  } catch (error) {
    logAdminEvent("error", "admin_api_client_get_error", {
      event: "admin_api_client_get_error",
      requestId: requestId,
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    
    if (error instanceof SyntaxError) {
      return res.status(500).json({ error: "Invalid JSON in config file" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /admin/api/clients/:clientId - Update client config
router.post("/clients/:clientId", requireAdminAuth, requireCsrf, (req, res) => {
  const requestId = req.requestId || "unknown";
  const validation = validateClientId(req.params.clientId);
  
  if (!validation.valid) {
    logAdminEvent("warn", "admin_api_client_update_invalid_id", {
      event: "admin_api_client_update_invalid_id",
      requestId: requestId,
      clientId: req.params.clientId,
      reason: validation.reason,
    });
    return res.status(400).json({ error: "Invalid client ID" });
  }
  
  const pathResult = getClientConfigPath(validation.clientId);
  if (!pathResult.valid) {
    logAdminEvent("warn", "admin_api_client_update_path_error", {
      event: "admin_api_client_update_path_error",
      requestId: requestId,
      clientId: validation.clientId,
      reason: pathResult.reason,
    });
    return res.status(400).json({ error: "Invalid client ID" });
  }
  
  try {
    if (!fs.existsSync(pathResult.path)) {
      return res.status(404).json({ error: "Client config not found" });
    }
    
    // Read existing config
    const existingContent = fs.readFileSync(pathResult.path, "utf8");
    const existingConfig = JSON.parse(existingContent);
    
    // Validate and sanitize update
    const validationResult = validateConfigUpdate(req.body);
    if (validationResult.errors.length > 0) {
      logAdminEvent("warn", "admin_api_client_update_validation_failed", {
        event: "admin_api_client_update_validation_failed",
        requestId: requestId,
        clientId: validation.clientId,
        errors: validationResult.errors,
      });
      return res.status(400).json({
        error: "Validation failed",
        invalidFields: validationResult.errors,
      });
    }
    
    // Merge allowed fields into existing config (deep merge for nested objects)
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
      updatedConfig.entryScreen = {
        ...updatedConfig.entryScreen,
        ...validationResult.allowed.entryScreen,
      };
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
    
    // Write updated config
    fs.writeFileSync(pathResult.path, JSON.stringify(updatedConfig, null, 2) + "\n", "utf8");
    
    logAdminEvent("info", "admin_api_client_update_success", {
      event: "admin_api_client_update_success",
      requestId: requestId,
      clientId: validation.clientId,
      updatedFields: Object.keys(validationResult.allowed),
    });
    
    return res.json({ success: true, clientId: validation.clientId, config: updatedConfig });
  } catch (error) {
    logAdminEvent("error", "admin_api_client_update_error", {
      event: "admin_api_client_update_error",
      requestId: requestId,
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    
    if (error instanceof SyntaxError) {
      return res.status(500).json({ error: "Invalid JSON in config file" });
    }
    return res.status(500).json({ error: "Internal server error" });
  }
});

// Export router and validation functions for reuse
module.exports = router;
module.exports.validateConfigUpdate = validateConfigUpdate;
module.exports.getClientConfigPath = getClientConfigPath;

