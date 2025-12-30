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

// List all client IDs from Supabase
async function listClientIds() {
  const supabase = getSupabaseClient();
  if (!supabase) {
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
      });
      return [];
    }

    if (!data) {
      return [];
    }

    // Filter to only valid client IDs (safety check)
    return data
      .map(row => row.client_id)
      .filter(clientId => {
        const validation = validateClientId(clientId);
        return validation.valid;
      })
      .sort();
  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_list_error", {
      error: error?.message || String(error),
    });
    return [];
  }
}

// Read client config from Supabase
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
    const { data, error } = await supabase
      .from("clients")
      .select("config")
      .eq("client_id", validation.clientId)
      .single();

    if (error) {
      if (error.code === "PGRST116") {
        // No rows returned (expected for non-existent clients)
        return null;
      }
      logStoreEvent("error", "clients_store_supabase_read_error", {
        clientId: validation.clientId,
        error: error?.message || String(error),
      });
      return null;
    }

    if (!data || !data.config) {
      return null;
    }

    return data.config;
  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_read_error", {
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return null;
  }
}

// Write client config atomically (upsert in Supabase)
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
    const { error } = await supabase
      .from("clients")
      .upsert(
        {
          client_id: validation.clientId,
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
        error: error?.message || String(error),
      });
      return { success: false, error: error?.message || String(error) };
    }

    return { success: true, path: `supabase://clients/${validation.clientId}` };
  } catch (error) {
    logStoreEvent("error", "clients_store_supabase_write_error", {
      clientId: validation.clientId,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// Delete client from Supabase
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
    const { error } = await supabase
      .from("clients")
      .delete()
      .eq("client_id", validation.clientId);

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

    if (error || !data) {
      return null;
    }

    const updatedAt = data.updated_at ? new Date(data.updated_at) : null;
    return {
      mtime: updatedAt,
      mtimeISO: updatedAt ? updatedAt.toISOString() : null,
      path: `supabase://clients/${validation.clientId}`,
    };
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

