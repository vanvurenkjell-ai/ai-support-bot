// Strict config update validator with allowlist enforcement
// This module ensures only safe, whitelisted fields can be updated
// Prevents injection of unsafe keys (API keys, system prompts, etc.)

// Simple logging helper
function logValidationEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "config_validation_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Strict allowlist of editable config fields
// Only these fields (and their allowed nested structure) can be updated
const ALLOWED_TOP_LEVEL_KEYS = [
  "colors",
  "widget",
  "logoUrl",
  "entryScreen",
  "support",
];

const ALLOWED_COLOR_KEYS = ["primary", "accent", "background", "userBubble", "botBubble"];
const ALLOWED_WIDGET_KEYS = ["title", "greeting"];
const ALLOWED_ENTRY_SCREEN_KEYS = ["enabled", "title", "disclaimer", "primaryButton", "secondaryButtons"];
const ALLOWED_PRIMARY_BUTTON_KEYS = ["label"];
const ALLOWED_SECONDARY_BUTTON_KEYS = ["label", "url"];
const ALLOWED_SUPPORT_KEYS = ["email", "contactUrl", "contactUrlMessageParam"];

// Validation rules and limits
const FIELD_LIMITS = {
  "widget.title": 60,
  "widget.greeting": 300,
  "entryScreen.title": 60,
  "entryScreen.disclaimer": 500,
  "entryScreen.primaryButton.label": 40,
  "entryScreen.secondaryButtons.label": 40,
  "support.email": 254,
  "support.contactUrl": 2048,
  "support.contactUrlMessageParam": 50,
  "logoUrl": 2048,
};

// Validate hex color (strict: must be #RGB or #RRGGBB)
function isValidHexColor(color) {
  if (!color || typeof color !== "string") return false;
  const trimmed = color.trim().toLowerCase();
  // Must be #RGB or #RRGGBB
  return /^#[0-9a-f]{3}$|^#[0-9a-f]{6}$/.test(trimmed);
}

// Normalize hex color to #RRGGBB format
function normalizeHexColor(color) {
  if (!color) return null;
  const trimmed = color.trim().toLowerCase();
  if (/^#[0-9a-f]{3}$/.test(trimmed)) {
    // Expand #RGB to #RRGGBB
    return "#" + trimmed[1] + trimmed[1] + trimmed[2] + trimmed[2] + trimmed[3] + trimmed[3];
  }
  if (/^#[0-9a-f]{6}$/.test(trimmed)) {
    return trimmed;
  }
  return null;
}

// Validate URL (must be http:// or https://)
function isValidUrl(url, maxLength = 2048) {
  if (url === null || url === undefined) return false;
  if (typeof url !== "string") return false;
  const trimmed = url.trim();
  if (trimmed.length === 0) return false; // Empty URLs not allowed for URL fields
  if (trimmed.length > maxLength) return false;
  return trimmed.startsWith("http://") || trimmed.startsWith("https://");
}

// Validate email (basic format check)
function isValidEmail(email, maxLength = 254) {
  if (email === null || email === undefined) return false;
  if (typeof email !== "string") return false;
  const trimmed = email.trim();
  if (trimmed.length === 0) return false; // Empty emails not allowed
  if (trimmed.length > maxLength) return false;
  // Basic email format: must contain @ and have at least one char before/after
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

// Validate URL message parameter (alphanumeric + underscore/hyphen)
function isValidUrlMessageParam(param) {
  if (param === null || param === undefined) return false;
  if (typeof param !== "string") return false;
  const trimmed = param.trim();
  if (trimmed.length === 0) return false;
  if (trimmed.length > FIELD_LIMITS["support.contactUrlMessageParam"]) return false;
  return /^[A-Za-z0-9_-]+$/.test(trimmed);
}

// Check if a key path is allowed in the allowlist
function isAllowedKeyPath(path) {
  const parts = path.split(".");
  if (parts.length === 0) return false;

  // Top-level keys
  if (parts.length === 1) {
    return ALLOWED_TOP_LEVEL_KEYS.includes(parts[0]);
  }

  // Nested keys
  if (parts[0] === "colors" && parts.length === 2) {
    return ALLOWED_COLOR_KEYS.includes(parts[1]);
  }
  if (parts[0] === "widget" && parts.length === 2) {
    return ALLOWED_WIDGET_KEYS.includes(parts[1]);
  }
  if (parts[0] === "entryScreen" && parts.length === 2) {
    return ALLOWED_ENTRY_SCREEN_KEYS.includes(parts[1]);
  }
  if (parts[0] === "entryScreen" && parts.length === 3 && parts[1] === "primaryButton") {
    return ALLOWED_PRIMARY_BUTTON_KEYS.includes(parts[2]);
  }
  if (parts[0] === "entryScreen" && parts.length === 3 && parts[1] === "secondaryButtons") {
    // Array index check happens separately
    return ALLOWED_SECONDARY_BUTTON_KEYS.includes(parts[2]);
  }
  if (parts[0] === "support" && parts.length === 2) {
    return ALLOWED_SUPPORT_KEYS.includes(parts[1]);
  }
  if (parts[0] === "logoUrl" && parts.length === 1) {
    return true;
  }

  return false;
}

// System-managed fields that are submitted by the form but should NOT be editable by client_admins
// These fields are automatically stripped from the update payload before validation,
// then preserved from existingConfig during merge. This prevents validation errors when
// the form includes these fields while still ensuring client_admins cannot change them.
//
// Why this is needed:
// - The admin form includes system-managed fields like `entryScreen.primaryButton.action`
// - These fields must remain unchanged (they're set by the system, not users)
// - Without stripping them first, validation fails with "Disallowed field" errors
// - Solution: Strip them before validation, preserve from existingConfig during merge
const SYSTEM_MANAGED_PATHS = [
  "entryScreen.primaryButton.action",
  // Secondary button actions are handled in array processing (detected by path pattern)
];

// Remove system-managed fields from an object recursively
function removeSystemManagedFields(obj, prefix = "", preservedPaths = []) {
  if (obj === null || obj === undefined || typeof obj !== "object") {
    return obj;
  }

  if (Array.isArray(obj)) {
    // For arrays, recursively process each element
    return obj.map((item, index) => {
      if (item === null || typeof item !== "object") {
        return item;
      }
      // For array elements, process them as objects without adding array index to path
      // (since we're already inside the array context)
      const cleanedItem = {};
      for (const key in item) {
        if (!item.hasOwnProperty(key)) continue;
        const fullPath = prefix ? `${prefix}[${index}].${key}` : `[${index}].${key}`;

        // Check if this path is system-managed
        let isSystemManaged = SYSTEM_MANAGED_PATHS.includes(fullPath);
        
        // Also check for secondaryButtons array element action fields
        if (key === "action" && (prefix.includes("secondaryButtons") || fullPath.includes("secondaryButtons"))) {
          isSystemManaged = true;
          preservedPaths.push(fullPath);
          // Skip this field - it will be preserved from existing config
          continue;
        }

        if (isSystemManaged) {
          preservedPaths.push(fullPath);
          continue;
        }

        // Process nested objects recursively
        if (item[key] !== null && typeof item[key] === "object" && !Array.isArray(item[key])) {
          const nested = removeSystemManagedFields(item[key], fullPath, preservedPaths);
          if (nested !== null && typeof nested === "object" && Object.keys(nested).length > 0) {
            cleanedItem[key] = nested;
          }
        } else {
          cleanedItem[key] = item[key];
        }
      }
      // Only return cleaned item if it has properties
      return Object.keys(cleanedItem).length > 0 ? cleanedItem : null;
    }).filter(item => item !== null);
  }

  const cleaned = {};
  for (const key in obj) {
    if (!obj.hasOwnProperty(key)) continue;
    const fullPath = prefix ? `${prefix}.${key}` : key;

    // Check if this path is system-managed
    let isSystemManaged = SYSTEM_MANAGED_PATHS.includes(fullPath);
    
    // Also check for secondaryButtons[].action paths (special handling for arrays)
    if (key === "action" && fullPath.includes("secondaryButtons")) {
      isSystemManaged = true;
    }

    if (isSystemManaged) {
      preservedPaths.push(fullPath);
      // Skip this field - it will be preserved from existing config
      continue;
    }

    // Recursively process nested objects and arrays
    if (obj[key] !== null && typeof obj[key] === "object") {
      const nested = removeSystemManagedFields(obj[key], fullPath, preservedPaths);
      if (nested !== null && typeof nested === "object") {
        if (Array.isArray(nested)) {
          if (nested.length > 0) {
            cleaned[key] = nested;
          }
        } else if (Object.keys(nested).length > 0) {
          cleaned[key] = nested;
        }
      }
    } else {
      cleaned[key] = obj[key];
    }
  }

  return cleaned;
}

// Preserve system-managed fields from existing config before validation
// This ensures client_admins can't change these fields, but they don't cause validation errors
function preserveSystemManagedFields(existingConfig, proposedUpdate, actorRole) {
  // Only apply to client_admin - super_admin can edit everything
  if (actorRole === "super_admin") {
    return proposedUpdate;
  }

  const preservedPaths = [];
  const cleanedUpdate = removeSystemManagedFields(proposedUpdate, "", preservedPaths);

  if (preservedPaths.length > 0) {
    logValidationEvent("info", "config_sanitize_preserved_system_fields", {
      actorRole: actorRole,
      preservedPaths: preservedPaths,
      note: "System-managed fields removed from update payload; will be preserved from existing config",
    });
  }

  return cleanedUpdate;
}

// Extract all key paths from an object (for allowlist checking)
function extractKeyPaths(obj, prefix = "") {
  const paths = [];
  if (obj === null || obj === undefined || typeof obj !== "object" || Array.isArray(obj)) {
    return paths;
  }

  for (const key in obj) {
    if (!obj.hasOwnProperty(key)) continue;
    const fullPath = prefix ? `${prefix}.${key}` : key;
    
    if (obj[key] !== null && typeof obj[key] === "object" && !Array.isArray(obj[key])) {
      // Recursively extract nested paths
      paths.push(...extractKeyPaths(obj[key], fullPath));
    } else {
      paths.push(fullPath);
    }
  }

  return paths;
}

// Validate and sanitize config update
// Returns: { sanitizedConfig, errors: [], fieldErrors: {} }
function validateAndSanitizeConfigUpdate(existingConfig, proposedUpdate, actorRole = "client_admin") {
  const errors = [];
  const fieldErrors = {};
  const sanitizedConfig = {};

  // Step 0: Strip system-managed fields from proposed update (for client_admin)
  // These fields will be preserved from existingConfig during merge
  const cleanedUpdate = preserveSystemManagedFields(existingConfig, proposedUpdate, actorRole);

  // Step 1: Check for disallowed top-level keys (on cleaned update)
  const allProposedPaths = extractKeyPaths(cleanedUpdate);
  const disallowedPaths = allProposedPaths.filter(path => !isAllowedKeyPath(path));

  if (disallowedPaths.length > 0) {
    for (const path of disallowedPaths) {
      errors.push(`Disallowed field: ${path}`);
      fieldErrors[path] = "This field cannot be updated";
    }
    logValidationEvent("warn", "config_validation_disallowed_keys", {
      disallowedPaths: disallowedPaths,
      actorRole: actorRole,
    });
    // Fail closed: return errors immediately if disallowed keys found
    return {
      sanitizedConfig: null,
      errors: errors,
      fieldErrors: fieldErrors,
    };
  }

  // Step 2: Validate and sanitize allowed fields
  try {
    // Colors (use cleaned update)
    if (cleanedUpdate.colors) {
      sanitizedConfig.colors = {};
      for (const colorKey of ALLOWED_COLOR_KEYS) {
        if (cleanedUpdate.colors[colorKey] !== undefined) {
          const colorValue = cleanedUpdate.colors[colorKey];
          const normalized = normalizeHexColor(colorValue);
          if (normalized) {
            sanitizedConfig.colors[colorKey] = normalized;
          } else {
            const fieldPath = `colors.${colorKey}`;
            errors.push(`Invalid hex color: ${fieldPath}`);
            fieldErrors[fieldPath] = "Must be a valid hex color (#RGB or #RRGGBB)";
          }
        }
      }
    }

    // Widget (use cleaned update)
    if (cleanedUpdate.widget) {
      sanitizedConfig.widget = {};
      
      if (cleanedUpdate.widget.title !== undefined) {
        const title = String(cleanedUpdate.widget.title || "").trim();
        const maxLen = FIELD_LIMITS["widget.title"];
        if (title.length > maxLen) {
          errors.push(`widget.title exceeds maximum length of ${maxLen} characters`);
          fieldErrors["widget.title"] = `Maximum ${maxLen} characters`;
        } else {
          sanitizedConfig.widget.title = title;
        }
      }
      
      if (cleanedUpdate.widget.greeting !== undefined) {
        const greeting = String(cleanedUpdate.widget.greeting || "").trim();
        const maxLen = FIELD_LIMITS["widget.greeting"];
        if (greeting.length > maxLen) {
          errors.push(`widget.greeting exceeds maximum length of ${maxLen} characters`);
          fieldErrors["widget.greeting"] = `Maximum ${maxLen} characters`;
        } else {
          sanitizedConfig.widget.greeting = greeting;
        }
      }
    }

    // Logo URL (use cleaned update)
    if (cleanedUpdate.logoUrl !== undefined) {
      const logoUrl = String(cleanedUpdate.logoUrl || "").trim();
      if (logoUrl.length === 0) {
        // Empty logoUrl is allowed (optional field)
        sanitizedConfig.logoUrl = null;
      } else if (isValidUrl(logoUrl, FIELD_LIMITS["logoUrl"])) {
        sanitizedConfig.logoUrl = logoUrl;
      } else {
        errors.push("logoUrl must be a valid HTTP or HTTPS URL");
        fieldErrors["logoUrl"] = "Must be a valid HTTP or HTTPS URL";
      }
    }

    // Entry Screen (use cleaned update)
    if (cleanedUpdate.entryScreen) {
      sanitizedConfig.entryScreen = {};

      if (cleanedUpdate.entryScreen.enabled !== undefined) {
        // Parse boolean safely (handle checkbox values)
        const enabled = cleanedUpdate.entryScreen.enabled;
        sanitizedConfig.entryScreen.enabled = enabled === true || enabled === "true" || enabled === "on" || enabled === 1 || enabled === "1";
      }

      if (cleanedUpdate.entryScreen.title !== undefined) {
        const title = String(cleanedUpdate.entryScreen.title || "").trim();
        const maxLen = FIELD_LIMITS["entryScreen.title"];
        if (title.length > maxLen) {
          errors.push(`entryScreen.title exceeds maximum length of ${maxLen} characters`);
          fieldErrors["entryScreen.title"] = `Maximum ${maxLen} characters`;
        } else {
          sanitizedConfig.entryScreen.title = title || null;
        }
      }

      if (cleanedUpdate.entryScreen.disclaimer !== undefined) {
        const disclaimer = String(cleanedUpdate.entryScreen.disclaimer || "").trim();
        const maxLen = FIELD_LIMITS["entryScreen.disclaimer"];
        if (disclaimer.length > maxLen) {
          errors.push(`entryScreen.disclaimer exceeds maximum length of ${maxLen} characters`);
          fieldErrors["entryScreen.disclaimer"] = `Maximum ${maxLen} characters`;
        } else {
          sanitizedConfig.entryScreen.disclaimer = disclaimer || null;
        }
      }

      // Primary Button (use cleaned update - action field already stripped)
      if (cleanedUpdate.entryScreen.primaryButton) {
        sanitizedConfig.entryScreen.primaryButton = {};
        
        if (cleanedUpdate.entryScreen.primaryButton.label !== undefined) {
          const label = String(cleanedUpdate.entryScreen.primaryButton.label || "").trim();
          const maxLen = FIELD_LIMITS["entryScreen.primaryButton.label"];
          if (label.length > maxLen) {
            errors.push(`entryScreen.primaryButton.label exceeds maximum length of ${maxLen} characters`);
            fieldErrors["entryScreen.primaryButton.label"] = `Maximum ${maxLen} characters`;
          } else {
            sanitizedConfig.entryScreen.primaryButton.label = label || null;
          }
        }
        
        // Note: action field is system-managed and preserved from existingConfig during merge
        // We don't set it here to avoid overwriting the preserved value
      }

      // Secondary Buttons (use cleaned update - action fields already stripped)
      if (cleanedUpdate.entryScreen.secondaryButtons !== undefined) {
        if (Array.isArray(cleanedUpdate.entryScreen.secondaryButtons)) {
          const buttons = [];
          const maxButtons = 2;
          
          for (let i = 0; i < Math.min(cleanedUpdate.entryScreen.secondaryButtons.length, maxButtons); i++) {
            const btn = cleanedUpdate.entryScreen.secondaryButtons[i];
            if (!btn || typeof btn !== "object") {
              errors.push(`entryScreen.secondaryButtons[${i}] must be an object`);
              fieldErrors[`entryScreen.secondaryButtons[${i}]`] = "Invalid button format";
              continue;
            }

            const label = btn.label ? String(btn.label).trim() : "";
            const url = btn.url ? String(btn.url).trim() : "";

            if (!label || !url) {
              // Skip incomplete buttons
              continue;
            }

            const labelMaxLen = FIELD_LIMITS["entryScreen.secondaryButtons.label"];
            if (label.length > labelMaxLen) {
              errors.push(`entryScreen.secondaryButtons[${i}].label exceeds maximum length of ${labelMaxLen} characters`);
              fieldErrors[`entryScreen.secondaryButtons[${i}].label`] = `Maximum ${labelMaxLen} characters`;
              continue;
            }

            if (!isValidUrl(url, FIELD_LIMITS["support.contactUrl"])) {
              errors.push(`entryScreen.secondaryButtons[${i}].url must be a valid HTTP or HTTPS URL`);
              fieldErrors[`entryScreen.secondaryButtons[${i}].url`] = "Must be a valid HTTP or HTTPS URL";
              continue;
            }

            buttons.push({
              label: label,
              // Note: action field is system-managed and preserved from existingConfig during merge
              // We set it here as fallback, but mergeConfigUpdate will use existing value if present
              action: "link",
              url: url,
            });
          }

          sanitizedConfig.entryScreen.secondaryButtons = buttons;
        } else {
          errors.push("entryScreen.secondaryButtons must be an array");
          fieldErrors["entryScreen.secondaryButtons"] = "Must be an array";
        }
      }
    }

    // Support (use cleaned update)
    if (cleanedUpdate.support) {
      sanitizedConfig.support = {};

      if (cleanedUpdate.support.email !== undefined) {
        const email = String(cleanedUpdate.support.email || "").trim();
        if (email.length === 0) {
          sanitizedConfig.support.email = null;
        } else if (isValidEmail(email, FIELD_LIMITS["support.email"])) {
          sanitizedConfig.support.email = email;
        } else {
          errors.push("support.email must be a valid email address");
          fieldErrors["support.email"] = "Must be a valid email address";
        }
      }

      if (cleanedUpdate.support.contactUrl !== undefined) {
        const contactUrl = String(cleanedUpdate.support.contactUrl || "").trim();
        if (contactUrl.length === 0) {
          sanitizedConfig.support.contactUrl = null;
        } else if (isValidUrl(contactUrl, FIELD_LIMITS["support.contactUrl"])) {
          sanitizedConfig.support.contactUrl = contactUrl;
        } else {
          errors.push("support.contactUrl must be a valid HTTP or HTTPS URL");
          fieldErrors["support.contactUrl"] = "Must be a valid HTTP or HTTPS URL";
        }
      }

      if (cleanedUpdate.support.contactUrlMessageParam !== undefined) {
        const param = String(cleanedUpdate.support.contactUrlMessageParam || "").trim();
        if (param.length === 0) {
          sanitizedConfig.support.contactUrlMessageParam = null;
        } else if (isValidUrlMessageParam(param)) {
          sanitizedConfig.support.contactUrlMessageParam = param;
        } else {
          errors.push("support.contactUrlMessageParam must contain only letters, numbers, underscores, and hyphens");
          fieldErrors["support.contactUrlMessageParam"] = "Must contain only letters, numbers, underscores, and hyphens";
        }
      }
    }
  } catch (error) {
    logValidationEvent("error", "config_validation_error", {
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 200) : null,
    });
    errors.push("Validation error: " + (error?.message || String(error)));
    return {
      sanitizedConfig: null,
      errors: errors,
      fieldErrors: fieldErrors,
    };
  }

  return {
    sanitizedConfig: sanitizedConfig,
    errors: errors,
    fieldErrors: fieldErrors,
  };
}

// Merge sanitized update into existing config
// This preserves existing fields not being updated and merges nested objects correctly
// System-managed fields are preserved from existingConfig (never overwritten by sanitizedUpdate)
function mergeConfigUpdate(existingConfig, sanitizedUpdate) {
  // Deep clone existing config
  const merged = JSON.parse(JSON.stringify(existingConfig || {}));

  // Merge sanitized updates
  if (sanitizedUpdate.colors) {
    merged.colors = { ...merged.colors, ...sanitizedUpdate.colors };
  }

  if (sanitizedUpdate.widget) {
    merged.widget = { ...merged.widget, ...sanitizedUpdate.widget };
  }

  if (sanitizedUpdate.logoUrl !== undefined) {
    merged.logoUrl = sanitizedUpdate.logoUrl;
  }

  if (sanitizedUpdate.entryScreen) {
    merged.entryScreen = merged.entryScreen || {};
    
    if (sanitizedUpdate.entryScreen.enabled !== undefined) {
      merged.entryScreen.enabled = sanitizedUpdate.entryScreen.enabled;
    }
    
    if (sanitizedUpdate.entryScreen.title !== undefined) {
      merged.entryScreen.title = sanitizedUpdate.entryScreen.title;
    }
    
    if (sanitizedUpdate.entryScreen.disclaimer !== undefined) {
      merged.entryScreen.disclaimer = sanitizedUpdate.entryScreen.disclaimer;
    }
    
    if (sanitizedUpdate.entryScreen.primaryButton) {
      // Preserve system-managed fields (action) from existing config
      const existingAction = merged.entryScreen.primaryButton?.action;
      merged.entryScreen.primaryButton = {
        ...(merged.entryScreen.primaryButton || {}),
        ...sanitizedUpdate.entryScreen.primaryButton,
      };
      // Restore system-managed action field if it existed
      if (existingAction) {
        merged.entryScreen.primaryButton.action = existingAction;
      } else {
        // Fallback if not in existing config
        merged.entryScreen.primaryButton.action = "openChat";
      }
    }
    
    if (sanitizedUpdate.entryScreen.secondaryButtons !== undefined) {
      // Preserve system-managed action fields from existing config
      const existingButtons = merged.entryScreen.secondaryButtons || [];
      merged.entryScreen.secondaryButtons = sanitizedUpdate.entryScreen.secondaryButtons.map((btn, index) => {
        const existingBtn = existingButtons[index];
        // Preserve action from existing button if present
        if (existingBtn && existingBtn.action) {
          return { ...btn, action: existingBtn.action };
        }
        // Fallback to "link" if not in existing config
        return { ...btn, action: btn.action || "link" };
      });
    }
  }

  if (sanitizedUpdate.support) {
    merged.support = { ...merged.support, ...sanitizedUpdate.support };
  }

  return merged;
}

module.exports = {
  validateAndSanitizeConfigUpdate,
  mergeConfigUpdate,
  preserveSystemManagedFields,
  isValidHexColor,
  isValidUrl,
  isValidEmail,
  isValidUrlMessageParam,
  normalizeHexColor,
  logValidationEvent,
};

