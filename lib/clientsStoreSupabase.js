const { createClient } = require("@supabase/supabase-js");
const { normalizeConfig, validateConfig, getDefaultConfig } = require("./clientConfigSchema");
const { writeClientConfigAudit, readRawConfigForAudit } = require("./clientConfigAudit");

// Simple logging helper (matches existing pattern)
function logStoreEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "clients_store_supabase_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Initialize Supabase client (server-side only, uses service role key)
function getSupabaseClient() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    return null;
  }

  return createClient(supabaseUrl, supabaseKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

// Validate clientId format: 2-33 chars, starts with letter, only alphanumeric/underscore/hyphen
function validateClientId(clientId) {
  if (!clientId || typeof clientId !== "string") {
    return { valid: false, reason: "missing_or_invalid_type" };
  }
  const trimmed = clientId.trim();
  // Pattern: /^[A-Za-z0-9][A-Za-z0-9_-]{1,32}$/ means 2-33 chars total
  if (trimmed.length < 2 || trimmed.length > 33) {
    return { valid: false, reason: "invalid_length" };
  }
  if (!/^[A-Za-z]/.test(trimmed)) {
    return { valid: false, reason: "must_start_with_letter" };
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,32}$/.test(trimmed)) {
    return { valid: false, reason: "invalid_chars" };
  }
  return { valid: true, clientId: trimmed };
}

// Get client config path (Supabase doesn't use filesystem paths, but we return an object for compatibility)
function getClientConfigPath(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { valid: false, path: null, dir: null, reason: validation.reason };
  }
  // For Supabase, we don't have a filesystem path, but return structure for compatibility
  return { valid: true, path: `supabase://clients/${validation.clientId}`, dir: null, clientId: validation.clientId };
}

// List all client IDs from Supabase (direct query - Supabase is source of truth)
async function listClientIds() {
  const supabase = getSupabaseClient();
  if (!supabase) {
    logStoreEvent("warn", "clients_store_supabase_list_no_client", {
      reason: "supabase_client_not_available",
    });
    return [];
  }

  try {
    const { data, error } = await supabase
      .from("clients")
      .select("client_id")
      .order("client_id", { ascending: true });

    if (error) {
      logStoreEvent("error", "clients_store_supabase_list_error", {
        error: error?.message || String(error),
        errorCode: error?.code,
      });
      return [];
    }

    if (!data || data.length === 0) {
      logStoreEvent("debug", "clients_store_supabase_list_empty", {
        message: "No clients found in Supabase",
      });
      return [];
    }

    // Filter to only valid client IDs (safety check)
    const validClients = data
      .map(row => row.client_id)
      .filter(clientId => {
        if (!clientId) return false;
        const validation = validateClientId(clientId);
        return validation.valid;
      })
      .sort();

    logStoreEvent("info", "clients_store_supabase_list_success", {
      totalRows: data.length,
      validClients: validClients.length,
      clientIds: validClients,
    });

    return validClients;
  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_list_error", {
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 200) : null,
    });
    return [];
  }
}

// Read client config from Supabase (case-insensitive lookup, fail-safe)
// Always returns a valid normalized config (defaults if not found/invalid)
async function readClientConfig(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    // Invalid clientId - return defaults
    logStoreEvent("warn", "config_missing_in_storage", {
      clientId: clientId,
      reason: "invalid_client_id_format",
      fallbackToDefaults: true,
    });
    return normalizeConfig(null, { clientId: clientId, logEvents: true });
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    // Supabase not available - return defaults
    logStoreEvent("warn", "config_missing_in_storage", {
      clientId: validation.clientId,
      reason: "supabase_not_available",
      fallbackToDefaults: true,
    });
    return normalizeConfig(null, { clientId: validation.clientId, logEvents: true });
  }

  try {
    // Step 1: Try exact match first (most common case)
    const { data: exactMatch, error: exactError } = await supabase
      .from("clients")
      .select("client_id, config")
      .eq("client_id", validation.clientId)
      .maybeSingle();

    let matched = null;
    let caseMismatch = false;

    if (exactError) {
      logStoreEvent("error", "clients_store_supabase_read_error", {
        clientId: validation.clientId,
        error: exactError?.message || String(exactError),
      });
    } else if (exactMatch) {
      matched = exactMatch;
    } else {
      // Step 2: Try case-insensitive lookup (fetch all and filter)
      const { data: allClients, error: fetchError } = await supabase
        .from("clients")
        .select("client_id, config");

      if (fetchError) {
        logStoreEvent("error", "clients_store_supabase_read_error", {
          clientId: validation.clientId,
          error: fetchError?.message || String(fetchError),
        });
      } else if (allClients && allClients.length > 0) {
        // Find case-insensitive match
        const caseInsensitiveMatch = allClients.find(row => 
          row.client_id && row.client_id.toLowerCase() === validation.clientId.toLowerCase()
        );

        if (caseInsensitiveMatch) {
          matched = caseInsensitiveMatch;
          caseMismatch = true;
          
          // Log case mismatch warning
          logStoreEvent("warn", "client_id_case_mismatch", {
            requestedClientId: validation.clientId,
            resolvedClientId: caseInsensitiveMatch.client_id,
            note: "Case-insensitive lookup was needed",
          });
        }
      }
    }

    // Step 3: If not found, return defaults
    if (!matched) {
      logStoreEvent("warn", "config_missing_in_storage", {
        clientId: validation.clientId,
        reason: "no_row_found",
        fallbackToDefaults: true,
      });
      return normalizeConfig(null, { clientId: validation.clientId, logEvents: true });
    }

    // Step 4: Validate and normalize config
    // If config is null/invalid, normalizeConfig will return defaults
    const rawConfig = matched.config;
    
    if (rawConfig === null || rawConfig === undefined) {
      logStoreEvent("warn", "config_invalid_in_storage", {
        clientId: validation.clientId,
        resolvedClientId: matched.client_id,
        reason: "config_is_null",
        fallbackToDefaults: true,
      });
      return normalizeConfig(null, { clientId: validation.clientId, logEvents: true });
    }

    // Normalize config (defensive - will return defaults if invalid)
    const normalized = normalizeConfig(rawConfig, {
      clientId: validation.clientId,
      logEvents: true,
    });

    // Check if normalization returned defaults (indicating validation failed)
    // We can detect this by checking if the normalized config matches defaults
    // For now, we trust normalizeConfig's logging

    if (!caseMismatch) {
      logStoreEvent("debug", "clients_store_supabase_read", {
        clientId: validation.clientId,
        matchedClientId: matched.client_id,
        schemaVersion: normalized.schemaVersion,
      });
    }

    return normalized;

  } catch (error) {
    // Catch any unexpected errors and return defaults (fail-safe)
    logStoreEvent("error", "clients_store_supabase_read_error", {
      clientId: validation.clientId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
      fallbackToDefaults: true,
    });
    return normalizeConfig(null, { clientId: validation.clientId, logEvents: true });
  }
}

// Write client config atomically (upsert in Supabase)
// For case-insensitive lookup: check if client exists with different casing first
// Config is validated and normalized before storage
// Writes audit log after successful update
async function writeClientConfigAtomic(clientId, config, updatedBy = null, options = {}) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return { success: false, error: "Supabase client not available" };
  }

  // Extract actor info from options
  const actor = {
    userId: options.actorUserId || null,
    email: updatedBy || options.actorEmail || null,
    role: options.actorRole || null,
  };
  const requestId = options.requestId || null;
  const storeType = "supabase"; // This is the Supabase store

  try {
    // First, determine canonicalClientId (needed for both before_config read and final write)
    // Check if client exists with different casing
    const { data: existingClients } = await supabase
      .from("clients")
      .select("client_id");

    let canonicalClientId = validation.clientId;
    if (existingClients && existingClients.length > 0) {
      const matched = existingClients.find(row => 
        row.client_id && row.client_id.toLowerCase() === validation.clientId.toLowerCase()
      );
      if (matched) {
        canonicalClientId = matched.client_id; // Use existing casing
      }
    }

    // Read raw before_config for audit (before we validate/normalize)
    // This captures the exact state stored in DB (not normalized)
    // Use canonicalClientId to ensure we read the correct row
    const beforeConfig = await readRawConfigForAudit(canonicalClientId);

    // Validate config before writing (fail closed on invalid config)
    const validationResult = validateConfig(config, {
      clientId: validation.clientId,
      logEvents: true,
    });

    if (!validationResult.ok) {
      logStoreEvent("error", "clients_store_supabase_write_validation_failed", {
        clientId: validation.clientId,
        errors: validationResult.errors.map(e => `${e.path}: ${e.message}`),
      });
      return {
        success: false,
        error: "Config validation failed",
        validationErrors: validationResult.errors,
      };
    }

    // Normalize config (apply defaults, strip unknown keys)
    const normalized = normalizeConfig(validationResult.value, {
      clientId: validation.clientId,
      logEvents: true,
    });

    // canonicalClientId already determined above (before reading before_config)

    // Write config update
    const { error } = await supabase
      .from("clients")
      .upsert(
        {
          client_id: canonicalClientId,
          config: normalized, // Store normalized config
          updated_at: new Date().toISOString(),
          updated_by: updatedBy || null,
        },
        {
          onConflict: "client_id",
        }
      );

    if (error) {
      logStoreEvent("error", "clients_store_supabase_write_error", {
        clientId: validation.clientId,
        canonicalClientId: canonicalClientId,
        error: error?.message || String(error),
      });
      return { success: false, error: error?.message || String(error) };
    }

    // Write audit log after successful config update (fail-safe: don't fail config write if audit fails)
    const auditResult = await writeClientConfigAudit({
      clientId: canonicalClientId,
      actor: actor,
      beforeConfig: beforeConfig,
      afterConfig: normalized, // Use the exact config that was written
      storeType: storeType,
      requestId: requestId,
    });

    // Log audit result (success or failure) but don't fail the config update
    if (!auditResult.success && !auditResult.skipped) {
      logStoreEvent("warn", "clients_store_supabase_audit_failed", {
        clientId: validation.clientId,
        canonicalClientId: canonicalClientId,
        auditError: auditResult.error || "unknown",
        note: "Config update succeeded but audit write failed",
      });
    }

    logStoreEvent("info", "clients_store_supabase_write_success", {
      clientId: validation.clientId,
      canonicalClientId: canonicalClientId,
      updatedBy: updatedBy || null,
      schemaVersion: normalized.schemaVersion,
      auditWritten: auditResult.success,
    });

    return { success: true, path: `supabase://clients/${canonicalClientId}`, canonicalClientId };
  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_write_error", {
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// Delete client from Supabase (case-insensitive lookup)
async function deleteClient(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return { success: false, error: "Supabase client not available" };
  }

  try {
    // Case-insensitive lookup for deletion
    const { data: existingClients } = await supabase
      .from("clients")
      .select("client_id");

    let canonicalClientId = validation.clientId;
    if (existingClients && existingClients.length > 0) {
      const matched = existingClients.find(row => 
        row.client_id && row.client_id.toLowerCase() === validation.clientId.toLowerCase()
      );
      if (matched) {
        canonicalClientId = matched.client_id; // Use existing casing
      } else {
        // Client doesn't exist
        return { success: false, error: "Client does not exist" };
      }
    } else {
      return { success: false, error: "Client does not exist" };
    }

    const { error } = await supabase
      .from("clients")
      .delete()
      .eq("client_id", canonicalClientId);

    if (error) {
      logStoreEvent("error", "clients_store_supabase_delete_error", {
        clientId: validation.clientId,
        error: error?.message || String(error),
      });
      return { success: false, error: error?.message || String(error) };
    }

    return { success: true };
  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_delete_error", {
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// Get config stats (returns updated_at as mtime equivalent)
async function getClientConfigStats(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return null;
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return null;
  }

  try {
    const { data, error } = await supabase
      .from("clients")
      .select("updated_at")
      .eq("client_id", validation.clientId)
      .single();

  } catch (error) {
    return null;
  }
}

// Check if Supabase is available
function isSupabaseAvailable() {
  return !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY);
}

module.exports = {
  validateClientId,
  getClientConfigPath,
  listClientIds,
  readClientConfig,
  writeClientConfigAtomic,
  deleteClient,
  getClientConfigStats,
  isSupabaseAvailable,
};

