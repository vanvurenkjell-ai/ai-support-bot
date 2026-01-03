// Client invitation management
// Handles creation and validation of invitation tokens for client_admin users

const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { createClient } = require("@supabase/supabase-js");
const { sendInvitationEmail } = require("./emailSender");
const { logInvitationAudit } = require("./invitationAudit");

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
function logInvitationEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "client_invitation_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Validate email format (basic RFC 5322 compliant check)
function isValidEmail(email) {
  if (!email || typeof email !== "string") {
    return false;
  }
  const trimmed = email.trim().toLowerCase();
  // Basic email regex (matches most valid emails)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmed)) {
    return false;
  }
  // Max length check (RFC 5321)
  if (trimmed.length > 254) {
    return false;
  }
  return true;
}

// Generate cryptographically secure random token
// Returns: { token: string, tokenHash: string }
async function generateInvitationToken() {
  try {
    // Generate 32 random bytes (256 bits) and convert to base64url
    const randomBytes = crypto.randomBytes(32);
    const token = randomBytes.toString("base64url");

    // Hash the token using bcrypt (constant-time comparison, secure storage)
    const saltRounds = 10;
    const tokenHash = await bcrypt.hash(token, saltRounds);

    return {
      token: token, // Return raw token (only at generation time, never stored)
      tokenHash: tokenHash, // Return hash for storage
    };
  } catch (error) {
    logInvitationEvent("error", "client_invitation_token_generation_error", {
      error: error?.message || String(error),
    });
    throw new Error("Failed to generate invitation token");
  }
}

// Check if client exists in Supabase
async function clientExists(clientId) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return false;
  }

  try {
    const { data, error } = await supabase
      .from("clients")
      .select("client_id")
      .eq("client_id", clientId)
      .maybeSingle();

    if (error) {
      logInvitationEvent("error", "client_invitation_check_client_error", {
        clientId: clientId,
        error: error?.message || String(error),
      });
      return false;
    }

    return !!data;
  } catch (error) {
    logInvitationEvent("error", "client_invitation_check_client_error", {
      clientId: clientId,
      error: error?.message || String(error),
    });
    return false;
  }
}

// Check if a pending invitation already exists for email + client
async function hasPendingInvitation(email, clientId) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return false;
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const { data, error } = await supabase
      .from("client_invitations")
      .select("id")
      .eq("email", normalizedEmail)
      .eq("client_id", clientId)
      .eq("status", "pending")
      .maybeSingle();

    if (error && error.code !== "PGRST116") {
      // PGRST116 = no rows returned (expected), other errors are real errors
      logInvitationEvent("error", "client_invitation_check_pending_error", {
        email: normalizedEmail,
        clientId: clientId,
        error: error?.message || String(error),
      });
      return false; // Fail closed: assume no pending invite on error
    }

    return !!data;
  } catch (error) {
    logInvitationEvent("error", "client_invitation_check_pending_error", {
      email: email,
      clientId: clientId,
      error: error?.message || String(error),
    });
    return false;
  }
}

// Create invitation in database
// Returns: { success: boolean, invitation?: object, error?: string }
// baseUrl: base URL for acceptance link in email (optional, falls back to env vars)
async function createInvitation(email, clientId, createdByUserId, requestId = null, baseUrl = null) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return { success: false, error: "Supabase client not available" };
  }

  try {
    // Validate email format
    if (!isValidEmail(email)) {
      return { success: false, error: "Invalid email format" };
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if client exists
    const clientExistsResult = await clientExists(clientId);
    if (!clientExistsResult) {
      // Do not leak whether client exists - return generic error
      return { success: false, error: "Invalid client or client not found" };
    }

    // Check for duplicate pending invitation
    const hasPending = await hasPendingInvitation(normalizedEmail, clientId);
    if (hasPending) {
      // Do not leak whether email already exists as user - return generic error
      return { success: false, error: "A pending invitation already exists for this email and client" };
    }

    // Generate token and hash
    // Note: raw token is returned here to be included in email - never stored in DB
    const { token, tokenHash } = await generateInvitationToken();

    // Set expiration (7 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Insert invitation
    const { data, error } = await supabase
      .from("client_invitations")
      .insert({
        email: normalizedEmail,
        client_id: clientId,
        role: "client_admin",
        token_hash: tokenHash,
        status: "pending",
        expires_at: expiresAt.toISOString(),
        created_by_user_id: createdByUserId,
        created_at: new Date().toISOString(),
      })
      .select("id, email, client_id, role, status, expires_at, created_at")
      .single();

    if (error) {
      logInvitationEvent("error", "client_invitation_create_error", {
        requestId: requestId,
        email: normalizedEmail,
        clientId: clientId,
        createdByUserId: createdByUserId,
        error: error?.message || String(error),
        errorCode: error?.code || null,
      });
      return { success: false, error: "Failed to create invitation" };
    }

    logInvitationEvent("info", "client_invitation_created", {
      requestId: requestId,
      invitationId: data.id,
      email: normalizedEmail,
      clientId: clientId,
      createdByUserId: createdByUserId,
      expiresAt: data.expires_at,
    });

    // Log audit entry for invitation creation (fail-safe)
    try {
      // Get actor details for audit (optional, best-effort)
      const supabaseForAudit = getSupabaseClient();
      let actorEmail = null;
      let actorRole = null;
      if (supabaseForAudit && createdByUserId) {
        try {
          const { data: actor } = await supabaseForAudit
            .from("users")
            .select("email, role")
            .eq("id", createdByUserId)
            .maybeSingle();
          if (actor) {
            actorEmail = actor.email;
            actorRole = actor.role;
          }
        } catch {
          // Ignore - actor lookup is optional for audit
        }
      }
      
      await logInvitationAudit({
        invitationId: data.id,
        clientId: clientId,
        actorUserId: createdByUserId,
        actorEmail: actorEmail,
        actorRole: actorRole,
        action: "created",
        beforeStatus: null,
        afterStatus: "pending",
        meta: { requestId: requestId, expiresAt: data.expires_at },
      });
    } catch (auditError) {
      // Audit failure must not block invitation creation
      logInvitationEvent("warn", "client_invitation_audit_failed", {
        requestId: requestId,
        invitationId: data.id,
        error: auditError?.message || String(auditError),
        note: "Invitation created but audit entry failed",
      });
    }

    // Send invitation email (non-blocking side effect)
    // Email failure does NOT rollback invitation creation
    // Include raw token in email for acceptance link (token is never stored, only hash)
    try {
      const emailResult = await sendInvitationEmail({
        to: normalizedEmail,
        client_id: clientId,
        invite_id: data.id,
        token: token, // Raw token for acceptance link (only used here, never stored)
        baseUrl: baseUrl, // Base URL for acceptance link
        requestId: requestId,
      });

      if (!emailResult.success) {
        logInvitationEvent("warn", "client_invitation_email_failed", {
          requestId: requestId,
          invitationId: data.id,
          email: normalizedEmail,
          clientId: clientId,
          emailError: emailResult.error || "unknown",
          note: "Invitation created in database, but email sending failed",
        });
      }
    } catch (emailError) {
      // Catch any unexpected errors from email sending - do not fail invitation creation
      logInvitationEvent("warn", "client_invitation_email_error", {
        requestId: requestId,
        invitationId: data.id,
        email: normalizedEmail,
        clientId: clientId,
        error: emailError?.message || String(emailError),
        note: "Invitation created in database, but email sending encountered an unexpected error",
      });
    }

    return {
      success: true,
      invitation: {
        id: data.id,
        email: data.email,
        client_id: data.client_id,
        role: data.role,
        status: data.status,
        expires_at: data.expires_at,
        created_at: data.created_at,
      },
    };
  } catch (error) {
    logInvitationEvent("error", "client_invitation_create_error", {
      requestId: requestId,
      email: email,
      clientId: clientId,
      createdByUserId: createdByUserId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return { success: false, error: "Failed to create invitation" };
  }
}

// List invitations for a specific client
async function listInvitationsForClient(clientId) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return [];
  }

  try {
    const { data, error } = await supabase
      .from("client_invitations")
      .select("id, email, status, expires_at, created_at, accepted_at")
      .eq("client_id", clientId)
      .order("created_at", { ascending: false });

    if (error) {
      logInvitationEvent("error", "client_invitation_list_error", {
        clientId: clientId,
        error: error?.message || String(error),
      });
      return [];
    }

    return data || [];
  } catch (error) {
    logInvitationEvent("error", "client_invitation_list_error", {
      clientId: clientId,
      error: error?.message || String(error),
    });
    return [];
  }
}

module.exports = {
  createInvitation,
  listInvitationsForClient,
  isValidEmail,
  clientExists,
  hasPendingInvitation,
  logInvitationEvent,
  generateInvitationToken,
  getSupabaseClient,
};

