// Immutable audit log for client config changes
// Writes audit records to Supabase table public.client_config_audit

const { createClient } = require("@supabase/supabase-js");

// Simple logging helper
function logAuditEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "client_config_audit_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Get Supabase client for audit writes (uses service role key)
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

// Read raw config from Supabase (before normalization) for audit before_config
// Returns the exact JSON stored in DB, or {} if not found
async function readRawConfigForAudit(clientId) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return {};
  }

  try {
    // Case-insensitive lookup for before_config
    const { data: allClients } = await supabase
      .from("clients")
      .select("client_id, config");

    if (!allClients || allClients.length === 0) {
      return {};
    }

    const matched = allClients.find(row => 
      row.client_id && row.client_id.toLowerCase() === clientId.toLowerCase()
    );

    if (!matched || matched.config === null || matched.config === undefined) {
      return {};
    }

    // Return raw config as stored (no normalization)
    return matched.config;
  } catch (error) {
    logAuditEvent("error", "client_config_audit_read_before_error", {
      clientId: clientId,
      error: error?.message || String(error),
    });
    return {};
  }
}

// Write audit log entry for a config change
// This is fail-safe: if audit write fails, it doesn't fail the config update
async function writeClientConfigAudit({ clientId, actor, beforeConfig, afterConfig, storeType, requestId = null }) {
  // NO-OP if not using Supabase
  if (storeType !== "supabase") {
    return { success: true, skipped: true, reason: "filesystem_mode" };
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    logAuditEvent("warn", "client_config_audit_write_failed", {
      requestId: requestId,
      clientId: clientId,
      reason: "supabase_client_not_available",
      actorEmail: actor?.email || null,
    });
    return { success: false, skipped: false, reason: "supabase_not_available" };
  }

  try {
    // Ensure before_config is an object (table requires jsonb not null)
    const safeBeforeConfig = beforeConfig && typeof beforeConfig === "object" ? beforeConfig : {};
    // Ensure after_config is an object
    const safeAfterConfig = afterConfig && typeof afterConfig === "object" ? afterConfig : {};

    const { error } = await supabase
      .from("client_config_audit")
      .insert({
        client_id: clientId,
        actor_user_id: actor?.userId || null,
        actor_email: actor?.email || null,
        actor_role: actor?.role || null,
        before_config: safeBeforeConfig,
        after_config: safeAfterConfig,
        created_at: new Date().toISOString(),
      });

    if (error) {
      logAuditEvent("warn", "client_config_audit_write_failed", {
        requestId: requestId,
        clientId: clientId,
        actorEmail: actor?.email || null,
        actorRole: actor?.role || null,
        error: error?.message || String(error),
        errorCode: error?.code || null,
      });
      return { success: false, error: error?.message || String(error) };
    }

    logAuditEvent("info", "client_config_audit_written", {
      requestId: requestId,
      clientId: clientId,
      actorEmail: actor?.email || null,
      actorRole: actor?.role || null,
    });

    return { success: true };
  } catch (error) {
    logAuditEvent("warn", "client_config_audit_write_failed", {
      requestId: requestId,
      clientId: clientId,
      actorEmail: actor?.email || null,
      actorRole: actor?.role || null,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return { success: false, error: error?.message || String(error) };
  }
}

module.exports = {
  writeClientConfigAudit,
  readRawConfigForAudit,
  logAuditEvent,
};

