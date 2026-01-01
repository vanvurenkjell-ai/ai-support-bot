// Centralized, versioned config schema with strict validation
// This module is the single source of truth for client config structure
// All configs are normalized, validated, and migrated through this module

const { z } = require("zod");

// Schema version (increment when making breaking changes)
const DEFAULT_SCHEMA_VERSION = 1;

// Simple logging helper
function logSchemaEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "config_schema_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Helper: Validate hex color (#RGB or #RRGGBB)
const hexColorSchema = z.string().regex(/^#[0-9a-f]{3}$|^#[0-9a-f]{6}$/i, {
  message: "Must be a valid hex color (#RGB or #RRGGBB)",
}).transform(val => val.toLowerCase());

// Helper: Validate URL (http:// or https://) or empty string
const urlSchema = z.string().max(2048).refine(
  (val) => val === "" || val.startsWith("http://") || val.startsWith("https://"),
  { message: "Must be a valid HTTP or HTTPS URL, or empty string" }
);

// Helper: Validate email or empty string
const emailSchema = z.string().max(254).refine(
  (val) => val === "" || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val),
  { message: "Must be a valid email address, or empty string" }
);

// Helper: Validate URL message parameter (alphanumeric + underscore/hyphen)
const urlMessageParamSchema = z.string().max(50).regex(/^[A-Za-z0-9_-]*$/, {
  message: "Must contain only letters, numbers, underscores, and hyphens",
});

// Zod schema for config version 1
const configSchemaV1 = z.object({
  schemaVersion: z.literal(1).default(1),
  
  colors: z.object({
    primary: hexColorSchema.default("#225ADF"),
    accent: hexColorSchema.default("#2563eb"),
    background: hexColorSchema.default("#ffffff"),
    userBubble: hexColorSchema.default("#225ADF"),
    botBubble: hexColorSchema.default("#ffffff"),
  }).default({}),
  
  widget: z.object({
    title: z.string().max(60).default("AI Assistant"),
    greeting: z.string().max(500).default("Hello! How can I help you today?"),
  }).default({}),
  
  logoUrl: urlSchema.nullable().default(null),
  
  entryScreen: z.object({
    enabled: z.boolean().default(true),
    title: z.string().max(60).nullable().default(null),
    disclaimer: z.string().max(800).nullable().default(null),
    primaryButton: z.object({
      label: z.string().max(40).default("Start chat"),
      action: z.literal("openChat").default("openChat"),
    }).default({}),
    secondaryButtons: z.array(
      z.object({
        label: z.string().max(40),
        action: z.literal("link").default("link"),
        url: urlSchema,
      })
    ).max(2).default([]),
  }).default({}),
  
  support: z.object({
    email: emailSchema.nullable().default(null),
    contactUrl: urlSchema.nullable().default(null),
    contactUrlMessageParam: urlMessageParamSchema.nullable().default(null),
  }).default({}),
  
  // Legacy/optional fields that may exist in existing configs
  // These are preserved during normalization but not strictly validated
  // They're allowed to pass through but won't be in the strict schema
  // Examples: brandName, assistantName, language, noEmojis, features, version, supportEmail, contactFormUrl
}).passthrough(); // Allow extra fields during parsing, but we'll strip them in normalizeConfig

// After parsing, we strip unknown keys to keep config clean
// But we preserve legacy fields that are commonly used by the runtime
const LEGACY_FIELDS_TO_PRESERVE = [
  "brandName",
  "assistantName",
  "language",
  "noEmojis",
  "features",
  "version",
  "supportEmail",
  "contactFormUrl",
];

// Current schema (version 1)
const currentSchema = configSchemaV1;

// Allowed fields for client_admin updates (subset of schema)
const CLIENT_ADMIN_ALLOWED_PATHS = [
  "colors.primary",
  "colors.accent",
  "colors.background",
  "colors.userBubble",
  "colors.botBubble",
  "widget.title",
  "widget.greeting",
  "logoUrl",
  "entryScreen.enabled",
  "entryScreen.title",
  "entryScreen.disclaimer",
  "entryScreen.primaryButton.label",
  "entryScreen.secondaryButtons",
  "support.email",
  "support.contactUrl",
  "support.contactUrlMessageParam",
];

// Check if a path is allowed for a given role
function isPathAllowedForRole(path, role) {
  if (role === "super_admin") {
    return true; // Super admin can edit all schema-defined fields
  }
  if (role === "client_admin") {
    // Check exact match or prefix match for nested paths
    return CLIENT_ADMIN_ALLOWED_PATHS.some(allowed => {
      if (path === allowed) return true;
      // For array paths like "entryScreen.secondaryButtons", allow nested paths
      if (allowed === "entryScreen.secondaryButtons" && path.startsWith("entryScreen.secondaryButtons")) {
        return true;
      }
      return false;
    });
  }
  return false;
}

// Extract all key paths from an object
function extractKeyPaths(obj, prefix = "") {
  const paths = [];
  if (obj === null || obj === undefined || typeof obj !== "object") {
    return paths;
  }

  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      if (item !== null && typeof item === "object") {
        paths.push(...extractKeyPaths(item, `${prefix}[${index}]`));
      }
    });
    return paths;
  }

  for (const key in obj) {
    if (!obj.hasOwnProperty(key)) continue;
    const fullPath = prefix ? `${prefix}.${key}` : key;
    
    if (obj[key] !== null && typeof obj[key] === "object" && !Array.isArray(obj[key])) {
      paths.push(...extractKeyPaths(obj[key], fullPath));
    } else {
      paths.push(fullPath);
    }
  }

  return paths;
}

// Get default config (fully populated with safe defaults)
function getDefaultConfig(clientId = null) {
  return {
    schemaVersion: DEFAULT_SCHEMA_VERSION,
    colors: {
      primary: "#225ADF",
      accent: "#2563eb",
      background: "#ffffff",
      userBubble: "#225ADF",
      botBubble: "#ffffff",
    },
    widget: {
      title: "AI Assistant",
      greeting: "Hello! How can I help you today?",
    },
    logoUrl: null,
    entryScreen: {
      enabled: true,
      title: null,
      disclaimer: null,
      primaryButton: {
        label: "Start chat",
        action: "openChat",
      },
      secondaryButtons: [],
    },
    support: {
      email: null,
      contactUrl: null,
      contactUrlMessageParam: null,
    },
  };
}

// Migrate config to latest schema version
function migrateConfig(input) {
  if (!input || typeof input !== "object") {
    return getDefaultConfig();
  }

  // Get schema version (default to 1 if missing)
  const inputVersion = input.schemaVersion || 1;

  // If already at latest version, return as-is (will be normalized later)
  if (inputVersion >= DEFAULT_SCHEMA_VERSION) {
    return input;
  }

  // Migration logic for future versions
  // For now, v1 is the only version, so just ensure schemaVersion is set
  const migrated = { ...input };
  if (!migrated.schemaVersion) {
    migrated.schemaVersion = 1;
  }

  // TODO: Add migration logic for v2, v3, etc. as needed
  // Example:
  // if (inputVersion === 1 && DEFAULT_SCHEMA_VERSION > 1) {
  //   // Migrate from v1 to v2
  //   migrated.someNewField = migrated.oldField || defaultValue;
  //   delete migrated.oldField;
  //   migrated.schemaVersion = 2;
  // }

  return migrated;
}

// Normalize config: apply defaults, strip unknown keys, ensure schemaVersion
// Fully defensive: never throws, always returns valid config
function normalizeConfig(input, opts = {}) {
  const { clientId = null, logEvents = true } = opts;

  try {
    // Handle null/undefined input
    if (input === null || input === undefined) {
      if (logEvents) {
        logSchemaEvent("warn", "config_normalization_null_input", {
          clientId: clientId,
          note: "Input is null/undefined, returning defaults",
        });
      }
      return getDefaultConfig(clientId);
    }

    // Ensure input is an object
    if (typeof input !== "object" || Array.isArray(input)) {
      if (logEvents) {
        logSchemaEvent("warn", "config_normalization_invalid_type", {
          clientId: clientId,
          inputType: typeof input,
          note: "Input is not an object, returning defaults",
        });
      }
      return getDefaultConfig(clientId);
    }

    // Defensively ensure nested objects exist before migration
    const safeInput = {
      ...input,
      colors: input.colors && typeof input.colors === "object" ? input.colors : {},
      widget: input.widget && typeof input.widget === "object" ? input.widget : {},
      entryScreen: input.entryScreen && typeof input.entryScreen === "object" ? input.entryScreen : {},
      support: input.support && typeof input.support === "object" ? input.support : {},
    };

    // Ensure arrays are arrays
    if (safeInput.entryScreen && !Array.isArray(safeInput.entryScreen.secondaryButtons)) {
      safeInput.entryScreen.secondaryButtons = [];
    }

    // Migrate to latest version first
    const migrated = migrateConfig(safeInput);

    // Parse with Zod schema (applies defaults, validates types)
    const parseResult = currentSchema.safeParse(migrated);

    if (!parseResult.success) {
      // Validation failed - log and return defaults
      if (logEvents) {
        const errors = Array.isArray(parseResult.error?.errors) 
          ? parseResult.error.errors.map(e => ({
              path: Array.isArray(e.path) ? e.path.join(".") : String(e.path),
              message: e.message || String(e),
            }))
          : [{ path: "root", message: "Validation failed" }];
        
        logSchemaEvent("error", "config_normalization_failed", {
          clientId: clientId,
          errors: errors,
        });
      }
      return getDefaultConfig(clientId);
    }

    // Extract known schema fields and preserve legacy fields
    const normalized = { ...parseResult.data };

    // Ensure all nested objects exist (defensive)
    if (!normalized.colors || typeof normalized.colors !== "object") {
      normalized.colors = getDefaultConfig(clientId).colors;
    }
    if (!normalized.widget || typeof normalized.widget !== "object") {
      normalized.widget = getDefaultConfig(clientId).widget;
    }
    if (!normalized.entryScreen || typeof normalized.entryScreen !== "object") {
      normalized.entryScreen = getDefaultConfig(clientId).entryScreen;
    }
    if (!normalized.support || typeof normalized.support !== "object") {
      normalized.support = getDefaultConfig(clientId).support;
    }

    // Ensure arrays are arrays
    if (!Array.isArray(normalized.entryScreen.secondaryButtons)) {
      normalized.entryScreen.secondaryButtons = [];
    }

    // Preserve legacy fields from input if they exist
    for (const field of LEGACY_FIELDS_TO_PRESERVE) {
      if (migrated && migrated[field] !== undefined) {
        normalized[field] = migrated[field];
      }
    }

    // Ensure schemaVersion is set
    if (!normalized.schemaVersion) {
      normalized.schemaVersion = DEFAULT_SCHEMA_VERSION;
    }

    if (logEvents) {
      logSchemaEvent("debug", "config_normalized", {
        clientId: clientId,
        schemaVersion: normalized.schemaVersion,
      });
    }

    return normalized;
  } catch (error) {
    // Catch any unexpected errors and return defaults
    if (logEvents) {
      logSchemaEvent("error", "config_normalization_error", {
        clientId: clientId,
        error: error?.message || String(error),
        stack: error?.stack ? String(error.stack).slice(0, 500) : null,
      });
    }
    return getDefaultConfig(clientId);
  }
}

// Validate config (returns { ok: true, value } or { ok: false, errors })
// Fully defensive: never throws
function validateConfig(input, opts = {}) {
  const { clientId = null, logEvents = true } = opts;

  try {
    // Handle null/undefined input
    if (input === null || input === undefined) {
      return {
        ok: false,
        errors: [{ path: "root", message: "Config is null or undefined" }],
      };
    }

    // Ensure input is an object
    if (typeof input !== "object" || Array.isArray(input)) {
      return {
        ok: false,
        errors: [{ path: "root", message: `Config must be an object, got ${typeof input}` }],
      };
    }

    // Defensively ensure nested objects exist
    const safeInput = {
      ...input,
      colors: input.colors && typeof input.colors === "object" ? input.colors : {},
      widget: input.widget && typeof input.widget === "object" ? input.widget : {},
      entryScreen: input.entryScreen && typeof input.entryScreen === "object" ? input.entryScreen : {},
      support: input.support && typeof input.support === "object" ? input.support : {},
    };

    // Ensure arrays are arrays
    if (safeInput.entryScreen && !Array.isArray(safeInput.entryScreen.secondaryButtons)) {
      safeInput.entryScreen.secondaryButtons = [];
    }

    // Migrate first
    const migrated = migrateConfig(safeInput);

    // Parse with schema
    const parseResult = currentSchema.safeParse(migrated);

    if (!parseResult.success) {
      const errors = Array.isArray(parseResult.error?.errors)
        ? parseResult.error.errors.map(e => ({
            path: Array.isArray(e.path) ? e.path.join(".") : String(e.path),
            message: e.message || String(e),
            code: e.code || "invalid_type",
          }))
        : [{ path: "root", message: "Validation failed", code: "unknown" }];

      if (logEvents) {
        logSchemaEvent("warn", "config_validation_failed", {
          clientId: clientId,
          errors: errors.map(e => `${e.path}: ${e.message}`),
        });
      }

      return {
        ok: false,
        errors: errors,
      };
    }

    return {
      ok: true,
      value: parseResult.data,
    };
  } catch (error) {
    if (logEvents) {
      logSchemaEvent("error", "config_validation_error", {
        clientId: clientId,
        error: error?.message || String(error),
        stack: error?.stack ? String(error.stack).slice(0, 500) : null,
      });
    }

    return {
      ok: false,
      errors: [{ path: "root", message: error?.message || String(error) }],
    };
  }
}

// Pick allowed fields from patch based on role
function pickAllowedConfigPatch(role, patch) {
  if (role === "super_admin") {
    // Super admin can update any schema-defined field
    // But we still validate against schema to prevent unknown keys
    return patch;
  }

  if (role === "client_admin") {
    // Client admin can only update allowed paths
    // Use simple object filtering based on allowed top-level keys
    const allowed = {};
    
    // Colors (all color fields are allowed)
    if (patch.colors && typeof patch.colors === "object") {
      allowed.colors = {};
      for (const key of ["primary", "accent", "background", "userBubble", "botBubble"]) {
        if (patch.colors[key] !== undefined) {
          allowed.colors[key] = patch.colors[key];
        }
      }
    }
    
    // Widget (title and greeting only)
    if (patch.widget && typeof patch.widget === "object") {
      allowed.widget = {};
      if (patch.widget.title !== undefined) allowed.widget.title = patch.widget.title;
      if (patch.widget.greeting !== undefined) allowed.widget.greeting = patch.widget.greeting;
    }
    
    // Logo URL
    if (patch.logoUrl !== undefined) {
      allowed.logoUrl = patch.logoUrl;
    }
    
    // Entry Screen
    if (patch.entryScreen && typeof patch.entryScreen === "object") {
      allowed.entryScreen = {};
      if (patch.entryScreen.enabled !== undefined) allowed.entryScreen.enabled = patch.entryScreen.enabled;
      if (patch.entryScreen.title !== undefined) allowed.entryScreen.title = patch.entryScreen.title;
      if (patch.entryScreen.disclaimer !== undefined) allowed.entryScreen.disclaimer = patch.entryScreen.disclaimer;
      
      // Primary Button (label only, not action)
      if (patch.entryScreen.primaryButton && typeof patch.entryScreen.primaryButton === "object") {
        allowed.entryScreen.primaryButton = {};
        if (patch.entryScreen.primaryButton.label !== undefined) {
          allowed.entryScreen.primaryButton.label = patch.entryScreen.primaryButton.label;
        }
      }
      
      // Secondary Buttons (entire array allowed)
      if (patch.entryScreen.secondaryButtons !== undefined) {
        allowed.entryScreen.secondaryButtons = patch.entryScreen.secondaryButtons;
      }
    }
    
    // Support
    if (patch.support && typeof patch.support === "object") {
      allowed.support = {};
      if (patch.support.email !== undefined) allowed.support.email = patch.support.email;
      if (patch.support.contactUrl !== undefined) allowed.support.contactUrl = patch.support.contactUrl;
      if (patch.support.contactUrlMessageParam !== undefined) {
        allowed.support.contactUrlMessageParam = patch.support.contactUrlMessageParam;
      }
    }
    
    return allowed;
  }

  // Unknown role - return empty patch (fail closed)
  return {};
}

// Apply patch to current config safely (with role-based restrictions)
function applyPatch(currentConfig, patch, role) {
  // Normalize current config first
  const normalizedCurrent = normalizeConfig(currentConfig, { logEvents: false });

  // Pick allowed fields from patch based on role
  const allowedPatch = pickAllowedConfigPatch(role, patch);

  // Deep merge patch into current config
  const merged = JSON.parse(JSON.stringify(normalizedCurrent));

  // Merge colors
  if (allowedPatch.colors) {
    merged.colors = { ...merged.colors, ...allowedPatch.colors };
  }

  // Merge widget
  if (allowedPatch.widget) {
    merged.widget = { ...merged.widget, ...allowedPatch.widget };
  }

  // Merge logoUrl
  if (allowedPatch.logoUrl !== undefined) {
    merged.logoUrl = allowedPatch.logoUrl;
  }

  // Merge entryScreen
  if (allowedPatch.entryScreen) {
    merged.entryScreen = { ...merged.entryScreen, ...allowedPatch.entryScreen };
    
    // Merge primaryButton
    if (allowedPatch.entryScreen.primaryButton) {
      merged.entryScreen.primaryButton = {
        ...merged.entryScreen.primaryButton,
        ...allowedPatch.entryScreen.primaryButton,
      };
      // Preserve action (system-managed)
      merged.entryScreen.primaryButton.action = normalizedCurrent.entryScreen.primaryButton.action || "openChat";
    }
    
    // Merge secondaryButtons (replace array)
    if (allowedPatch.entryScreen.secondaryButtons !== undefined) {
      // Defensively ensure it's an array
      const buttons = Array.isArray(allowedPatch.entryScreen.secondaryButtons)
        ? allowedPatch.entryScreen.secondaryButtons
        : [];
      merged.entryScreen.secondaryButtons = buttons.map(btn => ({
        ...btn,
        action: btn.action || "link", // Ensure action is set
      }));
    }
  }

  // Merge support
  if (allowedPatch.support) {
    merged.support = { ...merged.support, ...allowedPatch.support };
  }

  // Validate final merged config
  const validation = validateConfig(merged, { logEvents: true });

  if (!validation.ok) {
    return {
      ok: false,
      errors: validation.errors,
    };
  }

  return {
    ok: true,
    value: validation.value, // Normalized and validated
  };
}

module.exports = {
  DEFAULT_SCHEMA_VERSION,
  getDefaultConfig,
  normalizeConfig,
  validateConfig,
  migrateConfig,
  pickAllowedConfigPatch,
  applyPatch,
  isPathAllowedForRole,
  CLIENT_ADMIN_ALLOWED_PATHS,
  logSchemaEvent,
};

