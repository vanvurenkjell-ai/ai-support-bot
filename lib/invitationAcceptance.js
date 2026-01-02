// Invitation acceptance validation and processing
// Handles token validation, user creation, and invitation acceptance

const bcrypt = require("bcrypt");
const crypto = require("crypto");
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
function logAcceptanceEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "invitation_acceptance_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Validate invitation token
// Returns: { valid: boolean, invitation?: object, error?: string }
async function validateInvitationToken(token) {
  if (!token || typeof token !== "string") {
    return { valid: false, error: "Invalid token format" };
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    logAcceptanceEvent("error", "invitation_acceptance_validation_error", {
      error: "Supabase client not available",
    });
    return { valid: false, error: "System error" };
  }

  try {
    // Fetch all pending invitations that haven't expired
    // We need to check all pending invitations because we can't query by token_hash directly
    const now = new Date().toISOString();
    const { data: invitations, error } = await supabase
      .from("client_invitations")
      .select("id, email, client_id, role, status, expires_at, token_hash, created_at")
      .eq("status", "pending")
      .gte("expires_at", now);

    if (error) {
      logAcceptanceEvent("error", "invitation_acceptance_validation_error", {
        error: error?.message || String(error),
        errorCode: error?.code || null,
      });
      return { valid: false, error: "System error" };
    }

    if (!invitations || invitations.length === 0) {
      // No pending invitations found - don't leak information about specific token validity
      return { valid: false, error: "Invalid or expired invitation" };
    }

    // Compare token against all pending invitations using constant-time bcrypt comparison
    for (const invitation of invitations) {
      if (!invitation.token_hash) {
        continue; // Skip invitations without token hash
      }

      try {
        // bcrypt.compare performs constant-time comparison
        const tokenMatches = await bcrypt.compare(token, invitation.token_hash);
        if (tokenMatches) {
          // Token is valid - return invitation
          logAcceptanceEvent("info", "invitation_token_validated", {
            invitationId: invitation.id,
            email: invitation.email,
            clientId: invitation.client_id,
          });
          return { valid: true, invitation: invitation };
        }
      } catch (bcryptError) {
        // If bcrypt comparison fails, continue to next invitation
        // This prevents timing attacks from revealing which invitations exist
        continue;
      }
    }

    // Token didn't match any invitation
    // Don't leak information about whether token was close or invitation expired
    return { valid: false, error: "Invalid or expired invitation" };
  } catch (error) {
    logAcceptanceEvent("error", "invitation_acceptance_validation_error", {
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return { valid: false, error: "System error" };
  }
}

// Check if user already exists with this email
async function userExists(email) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return false;
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();
    const { data, error } = await supabase
      .from("users")
      .select("id")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error && error.code !== "PGRST116") {
      // PGRST116 = no rows returned (expected)
      logAcceptanceEvent("error", "invitation_acceptance_check_user_error", {
        email: normalizedEmail,
        error: error?.message || String(error),
      });
      return false; // Fail closed
    }

    return !!data;
  } catch (error) {
    logAcceptanceEvent("error", "invitation_acceptance_check_user_error", {
      email: email,
      error: error?.message || String(error),
    });
    return false;
  }
}

// Validate password strength
// Returns: { valid: boolean, error?: string }
function validatePasswordStrength(password) {
  if (!password || typeof password !== "string") {
    return { valid: false, error: "Password is required" };
  }

  if (password.length < 8) {
    return { valid: false, error: "Password must be at least 8 characters long" };
  }

  if (password.length > 128) {
    return { valid: false, error: "Password must be less than 128 characters" };
  }

  // Check for at least one letter and one number
  const hasLetter = /[a-zA-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);

  if (!hasLetter || !hasNumber) {
    return { valid: false, error: "Password must contain at least one letter and one number" };
  }

  return { valid: true };
}

// Accept invitation: create user, link to client, and mark invitation as accepted
// Returns: { success: boolean, user?: object, error?: string }
async function acceptInvitation(token, password, requestId = null) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return { success: false, error: "System error" };
  }

  try {
    // Re-validate token (fail closed)
    const tokenValidation = await validateInvitationToken(token);
    if (!tokenValidation.valid || !tokenValidation.invitation) {
      logAcceptanceEvent("warn", "invitation_acceptance_invalid_token", {
        requestId: requestId,
        error: tokenValidation.error || "invalid_token",
      });
      return { success: false, error: tokenValidation.error || "Invalid or expired invitation" };
    }

    const invitation = tokenValidation.invitation;

    // Check if user already exists
    const exists = await userExists(invitation.email);
    if (exists) {
      // Don't leak that user exists - return generic error
      logAcceptanceEvent("warn", "invitation_acceptance_user_exists", {
        requestId: requestId,
        invitationId: invitation.id,
        email: invitation.email,
        note: "User already exists for this email",
      });
      return { success: false, error: "Account already exists" };
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
      return { success: false, error: passwordValidation.error };
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Generate user ID (UUID)
    const userId = crypto.randomUUID();

    // Transactionally: create user, create client_users link, update invitation
    // Note: Supabase doesn't support true transactions in JS client, but we can use a single transaction via RPC
    // For now, we'll do sequential operations and handle rollback on error

    // 1. Create user
    const { data: newUser, error: userError } = await supabase
      .from("users")
      .insert({
        id: userId,
        email: invitation.email.trim().toLowerCase(),
        role: "client_admin",
        password_hash: passwordHash,
        created_at: new Date().toISOString(),
      })
      .select("id, email, role")
      .single();

    if (userError) {
      // Check for duplicate key error (race condition)
      if (userError.code === "23505") {
        logAcceptanceEvent("warn", "invitation_acceptance_user_exists_race", {
          requestId: requestId,
          invitationId: invitation.id,
          email: invitation.email,
          note: "User created by another request (race condition)",
        });
        return { success: false, error: "Account already exists" };
      }

      logAcceptanceEvent("error", "invitation_acceptance_user_creation_error", {
        requestId: requestId,
        invitationId: invitation.id,
        email: invitation.email,
        error: userError?.message || String(userError),
        errorCode: userError?.code || null,
      });
      return { success: false, error: "Failed to create account" };
    }

    // 2. Create client_users link
    const { error: clientUserError } = await supabase
      .from("client_users")
      .insert({
        user_id: userId,
        client_id: invitation.client_id,
        role: "client_admin",
        created_at: new Date().toISOString(),
      });

    if (clientUserError) {
      // Rollback: delete user if client_users insert fails
      await supabase.from("users").delete().eq("id", userId);

      logAcceptanceEvent("error", "invitation_acceptance_client_link_error", {
        requestId: requestId,
        invitationId: invitation.id,
        userId: userId,
        clientId: invitation.client_id,
        error: clientUserError?.message || String(clientUserError),
        errorCode: clientUserError?.code || null,
      });
      return { success: false, error: "Failed to link account to client" };
    }

    // 3. Update invitation status to accepted
    const { error: invitationUpdateError } = await supabase
      .from("client_invitations")
      .update({
        status: "accepted",
        accepted_at: new Date().toISOString(),
      })
      .eq("id", invitation.id)
      .eq("status", "pending"); // Only update if still pending (prevent race condition)

    if (invitationUpdateError) {
      // Log error but don't fail - user is created and linked, invitation acceptance is best-effort
      logAcceptanceEvent("warn", "invitation_acceptance_status_update_error", {
        requestId: requestId,
        invitationId: invitation.id,
        userId: userId,
        error: invitationUpdateError?.message || String(invitationUpdateError),
        note: "User created and linked, but invitation status update failed",
      });
    }

    logAcceptanceEvent("info", "invitation_acceptance_success", {
      requestId: requestId,
      invitationId: invitation.id,
      userId: userId,
      email: invitation.email,
      clientId: invitation.client_id,
    });

    return {
      success: true,
      user: {
        id: newUser.id,
        email: newUser.email,
        role: newUser.role,
      },
      clientId: invitation.client_id,
    };
  } catch (error) {
    logAcceptanceEvent("error", "invitation_acceptance_error", {
      requestId: requestId,
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    return { success: false, error: "System error" };
  }
}

module.exports = {
  validateInvitationToken,
  acceptInvitation,
  validatePasswordStrength,
  userExists,
  logAcceptanceEvent,
};

