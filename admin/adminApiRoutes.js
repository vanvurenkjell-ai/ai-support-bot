const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const { requireAdminAuth } = require("./auth");
const { requireCsrf } = require("./csrf");
const clientsStore = require("../lib/clientsStoreAdapter");
const { validateAndSanitizeConfigUpdate, mergeConfigUpdate } = require("./configValidator");
const { isSuperAdmin, canAccessClient, getAuthorizedClientIds } = require("./adminAuthz");
const { applyPatch, normalizeConfig, getDefaultConfig } = require("../lib/clientConfigSchema");

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

// Use centralized clientsStore module
const {
  getClientsRoot,
  validateClientId,
  getClientConfigPath,
  listClientIds,
  readClientConfig,
  writeClientConfigAtomic,
} = clientsStore;

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
      if (greeting.length <= 240) {
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
      if (title.length <= 60) {
        allowed.entryScreen.title = title;
      } else {
        errors.push("entryScreen.title");
      }
    }
    if (input.entryScreen.disclaimer !== undefined) {
      const disclaimer = String(input.entryScreen.disclaimer || "").trim();
      if (disclaimer.length <= 240) {
        allowed.entryScreen.disclaimer = disclaimer;
      } else {
        errors.push("entryScreen.disclaimer");
      }
    }
    if (input.entryScreen.primaryButton) {
      allowed.entryScreen.primaryButton = {};
      if (input.entryScreen.primaryButton.label !== undefined) {
        const label = String(input.entryScreen.primaryButton.label || "").trim();
        if (label.length <= 30) {
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
              if (label.length <= 30 && action === "link" && isValidUrl(url, 200)) {
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
      if (isValidUrl(input.support.contactUrl, 200)) {
        allowed.support.contactUrl = String(input.support.contactUrl).trim();
      } else {
        errors.push("support.contactUrl");
      }
    }
    if (input.support.contactUrlMessageParam !== undefined) {
      const param = String(input.support.contactUrlMessageParam || "").trim();
      if (param.length <= 30 && /^[a-zA-Z0-9_]+$/.test(param)) {
        allowed.support.contactUrlMessageParam = param;
      } else {
        errors.push("support.contactUrlMessageParam");
      }
    }
  }
  
  return { allowed, errors };
}

// GET /admin/api/clients - List all clients
router.get("/clients", requireAdminAuth, async (req, res) => {
  const requestId = req.requestId || "unknown";
  try {
    const allClients = await listClientIds();
    
    // Filter clients based on authorization
    let clients = allClients;
    if (isSuperAdmin(req)) {
      clients = allClients;
    } else {
      const authorizedClientIds = getAuthorizedClientIds(req) || [];
      clients = allClients.filter(clientId => authorizedClientIds.includes(clientId));
    }
    logAdminEvent("info", "admin_api_clients_list", {
      event: "admin_api_clients_list",
      requestId: requestId,
      count: clients.length,
      storeType: clientsStore.storeType,
    });
    return res.json(clients);
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
router.get("/clients/:clientId", requireAdminAuth, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientId = req.params.clientId;
  const userEmail = req.session.admin.email;
  
  // Authorization check: user must be able to access this client
  if (!canAccessClient(req, clientId)) {
    logAdminEvent("warn", "admin_api_client_access_denied", {
      event: "admin_api_client_access_denied",
      requestId: requestId,
      userEmail: userEmail,
      clientId: clientId,
      reason: "not_authorized",
    });
    return res.status(403).json({
      error: "Forbidden",
      message: "You do not have permission to access this client",
    });
  }
  
  const validation = validateClientId(clientId);
  
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
    const config = await readClientConfig(validation.clientId);
    if (!config) {
      return res.status(404).json({ error: "Client config not found" });
    }
    
    logAdminEvent("info", "admin_api_client_get", {
      event: "admin_api_client_get",
      requestId: requestId,
      clientId: validation.clientId,
      storeType: clientsStore.storeType,
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
router.post("/clients/:clientId", requireAdminAuth, requireCsrf, async (req, res) => {
  const requestId = req.requestId || "unknown";
  const clientId = req.params.clientId;
  const userEmail = req.session.admin.email;
  
  // Authorization check: user must be able to access this client
  if (!canAccessClient(req, clientId)) {
    logAdminEvent("warn", "admin_api_client_update_denied", {
      event: "admin_api_client_update_denied",
      requestId: requestId,
      userEmail: userEmail,
      clientId: clientId,
      reason: "not_authorized",
    });
    return res.status(403).json({
      error: "Forbidden",
      message: "You do not have permission to update this client",
    });
  }
  
  const validation = validateClientId(clientId);
  
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
    // Read existing config (async for Supabase)
    const existingConfig = await readClientConfig(validation.clientId);
    if (!existingConfig) {
      return res.status(404).json({ error: "Client config not found" });
    }
    
    // Determine actor role for validation
    const actorRole = isSuperAdmin(req) ? "super_admin" : "client_admin";
    
    // Use schema-based validation and patch application
    const patchResult = applyPatch(existingConfig, req.body, actorRole);
    
    if (!patchResult.ok) {
      logAdminEvent("warn", "admin_api_client_update_validation_failed", {
        event: "admin_api_client_update_validation_failed",
        requestId: requestId,
        clientId: validation.clientId,
        userEmail: userEmail,
        actorRole: actorRole,
        errors: patchResult.errors.map(e => `${e.path}: ${e.message}`),
      });
      return res.status(400).json({
        ok: false,
        error: "Validation failed",
        errors: patchResult.errors.map(e => e.path ? `${e.path}: ${e.message}` : e.message),
        fieldErrors: patchResult.errors.reduce((acc, e) => {
          if (e.path) acc[e.path] = e.message;
          return acc;
        }, {}),
      });
    }
    
    // Use normalized and validated config from schema system
    const updatedConfig = patchResult.value;
    
    // Write updated config (atomic write - async for Supabase)
    const updatedBy = req.session?.admin?.email || null;
    const writeResult = await writeClientConfigAtomic(validation.clientId, updatedConfig, updatedBy);
    if (!writeResult.success) {
      logAdminEvent("error", "admin_api_client_update_write_failed", {
        event: "admin_api_client_update_write_failed",
        requestId: requestId,
        clientId: validation.clientId,
        error: writeResult.error,
      });
      return res.status(500).json({ error: "Error writing client config" });
    }
    
    logAdminEvent("info", "admin_api_client_update_success", {
      event: "admin_api_client_update_success",
      requestId: requestId,
      clientId: validation.clientId,
      userEmail: userEmail,
      actorRole: actorRole,
      schemaVersion: updatedConfig.schemaVersion,
      storeType: clientsStore.storeType,
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

// Export router and validation function for reuse
module.exports = router;
module.exports.validateConfigUpdate = validateConfigUpdate;

