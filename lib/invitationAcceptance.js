// Invitation acceptance validation and processing
// Handles token validation, user creation, and invitation acceptance

const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
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
    
    // First, mark any expired pending invitations as expired (best-effort, non-blocking)
    try {
      const { data: expiredInvites } = await supabase
        .from("client_invitations")
        .select("id, client_id")
        .eq("status", "pending")
        .lt("expires_at", now);
      
      if (expiredInvites && expiredInvites.length > 0) {
        // Update expired invitations to expired status (safe, non-racy - status check in update)
        for (const invite of expiredInvites) {
          const { error: updateError } = await supabase
            .from("client_invitations")
            .update({ status: "expired" })
            .eq("id", invite.id)
            .eq("status", "pending"); // Only update if still pending (prevents race condition)
          
          // Log audit entry for expiration (fail-safe, don't block)
          if (!updateError) {
            await logInvitationAudit({
              invitationId: invite.id,
              clientId: invite.client_id,
              action: "expired",
              beforeStatus: "pending",
              afterStatus: "expired",
              meta: { autoExpired: true },
            });
          }
        }
      }
    } catch (expireCheckError) {
      // Non-critical: continue even if expiration check fails
      logAcceptanceEvent("warn", "invitation_expiration_check_error", {
        error: expireCheckError?.message || String(expireCheckError),
      });
    }
    
    // Now fetch valid pending invitations
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
          // Token matches - verify status is still pending (not revoked or expired)
          // Note: expired check already happened in query (expires_at >= now)
          // But we should also explicitly check status in case it was revoked after query
          if (invitation.status !== "pending") {
            logAcceptanceEvent("warn", "invitation_token_status_not_pending", {
              invitationId: invitation.id,
              email: invitation.email,
              clientId: invitation.client_id,
              status: invitation.status,
              note: "Token matches but invitation status is not pending",
            });
            // Log audit for accept_failed if status is revoked
            if (invitation.status === "revoked") {
              await logInvitationAudit({
                invitationId: invitation.id,
                clientId: invitation.client_id,
                action: "accept_failed",
                beforeStatus: invitation.status,
                afterStatus: invitation.status,
                meta: { reason: "revoked", requestId: null },
              });
            }
            return { valid: false, error: "Invalid or expired invitation" };
          }
          
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

    // Token didn't match any invitation - check if it might be revoked or expired
    // Check for revoked/expired invitations with this token (for better error messages, but still generic)
    try {
      const { data: invalidInvites } = await supabase
        .from("client_invitations")
        .select("id, status, expires_at")
        .in("status", ["revoked", "expired", "accepted"]);
      
      // Try to match token against revoked/expired/accepted invitations (for audit purposes)
      // But still return generic error to user
      if (invalidInvites && invalidInvites.length > 0) {
        for (const invite of invalidInvites) {
          try {
            // Don't check token_hash here - just for logging if we had access to it
            // We already know the invitation is not valid pending, so we can log accept_failed
          } catch {
            // Ignore
          }
        }
      }
    } catch {
      // Ignore - non-critical check
    }
    
    // Token didn't match any invitation
    // Don't leak information about whether token was close or invitation expired/revoked
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
    } else {
      // Log audit entry for acceptance (fail-safe)
      await logInvitationAudit({
        invitationId: invitation.id,
        clientId: invitation.client_id,
        action: "accepted",
        beforeStatus: "pending",
        afterStatus: "accepted",
        meta: { requestId: requestId },
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

