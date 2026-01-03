// Invitation audit logging
// Provides fail-safe audit logging for invitation state changes

const { createClient } = require("@supabase/supabase-js");

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

// Simple logging helper
function logAuditEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "invitation_audit_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Log invitation audit entry (fail-safe: audit failure must not block primary action)
// Returns: { logged: boolean, error?: string }
async function logInvitationAudit({
  invitationId,
  clientId,
  actorUserId = null,
  actorEmail = null,
  actorRole = null,
  action,
  beforeStatus = null,
  afterStatus = null,
  meta = null,
}) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    logAuditEvent("warn", "invitation_audit_supabase_unavailable", {
      invitationId: invitationId,
      action: action,
      note: "Supabase not available - audit entry not written",
    });
    return { logged: false, error: "Supabase not available" };
  }

  try {
    const { error } = await supabase.from("client_invitation_audit").insert({
      invitation_id: invitationId,
      client_id: clientId,
      actor_user_id: actorUserId,
      actor_email: actorEmail,
      actor_role: actorRole,
      action: action,
      before_status: beforeStatus,
      after_status: afterStatus,
      meta: meta,
      created_at: new Date().toISOString(),
    });

    if (error) {
      logAuditEvent("warn", "invitation_audit_insert_error", {
        invitationId: invitationId,
        action: action,
        error: error?.message || String(error),
        errorCode: error?.code || null,
        note: "Audit entry failed to write - primary action continues",
      });
      return { logged: false, error: error?.message || String(error) };
    }

    logAuditEvent("info", "invitation_audit_logged", {
      invitationId: invitationId,
      action: action,
      note: "Audit entry written successfully",
    });

    return { logged: true };
  } catch (error) {
    logAuditEvent("warn", "invitation_audit_exception", {
      invitationId: invitationId,
      action: action,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
      note: "Audit entry failed with exception - primary action continues",
    });
    return { logged: false, error: error?.message || String(error) };
  }
}

module.exports = {
  logInvitationAudit,
  logAuditEvent,
};

