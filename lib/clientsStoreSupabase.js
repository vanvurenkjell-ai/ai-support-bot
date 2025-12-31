const { createClient } = require("@supabase/supabase-js");

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

// Read client config from Supabase (case-insensitive lookup)
async function readClientConfig(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return null;
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return null;
  }

  try {
    // Case-insensitive lookup: fetch all and filter in memory (Supabase doesn't support ILIKE on primary key)
    // For small client lists, this is acceptable
    const { data: allClients, error: fetchError } = await supabase
      .from("clients")
      .select("client_id, config");

    if (fetchError) {
      logStoreEvent("error", "clients_store_supabase_read_error", {
        clientId: validation.clientId,
        error: fetchError?.message || String(fetchError),
      });
      return null;
    }

    if (!allClients || allClients.length === 0) {
      return null;
    }

    // Find case-insensitive match, but preserve original client_id casing
    const matched = allClients.find(row => 
      row.client_id && row.client_id.toLowerCase() === validation.clientId.toLowerCase()
    );

    if (!matched) {
      return null;
    }

    logStoreEvent("debug", "clients_store_supabase_read", {
      clientId: validation.clientId,
      matchedClientId: matched.client_id, // Original casing from DB
    });

    return matched.config;

  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_read_error", {
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return null;
  }
}

// Write client config atomically (upsert in Supabase)
// For case-insensitive lookup: check if client exists with different casing first
async function writeClientConfigAtomic(clientId, config, updatedBy = null) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { success: false, error: `Invalid client ID: ${validation.reason}` };
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return { success: false, error: "Supabase client not available" };
  }

  try {
    // Check if client exists with different casing
    // If found, update that row; otherwise insert with validated client_id
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

    const { error } = await supabase
      .from("clients")
      .upsert(
        {
          client_id: canonicalClientId,
          config: config,
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

    logStoreEvent("info", "clients_store_supabase_write_success", {
      clientId: validation.clientId,
      canonicalClientId: canonicalClientId,
      updatedBy: updatedBy || null,
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

