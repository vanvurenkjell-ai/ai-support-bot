const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcrypt");

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
function logAuthzEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "admin_authz_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Verify password against pgcrypto-stored hash using bcrypt
// Compatible with pgcrypto's crypt() function when using bcrypt algorithm
async function verifyPassword(plaintextPassword, passwordHash) {
  if (!plaintextPassword || !passwordHash) {
    return false;
  }

  try {
    // Use bcrypt.compare() which is compatible with pgcrypto crypt() bcrypt hashes
    // This performs constant-time comparison to prevent timing attacks
    const isValid = await bcrypt.compare(plaintextPassword, passwordHash);
    return isValid;
  } catch (error) {
    // If verification fails (invalid hash format, etc.), fail closed
    logAuthzEvent("error", "admin_authz_password_verify_error", {
      error: error?.message || String(error),
      note: "Password verification failed",
    });
    return false;
  }
}

// Resolve user from Supabase by email and verify password
// Returns: { user: { id, email, role }, clientIds: [...] } or null
async function resolveUserFromSupabase(email, password) {
  // Fallback: If Supabase is not configured, use legacy env var auth
  // This maintains backward compatibility for super-admin
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

  // Legacy super-admin check (backward compatibility) - check FIRST before Supabase lookup
  if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
    logAuthzEvent("info", "admin_authz_legacy_superadmin", {
      email: email,
      note: "Using legacy env var authentication for super-admin",
    });
    return {
      user: {
        id: null, // Legacy user has no UUID
        email: email,
        role: "super_admin",
      },
      clientIds: null, // null means "all clients" for super_admin
    };
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    // No Supabase configured - deny access (fail closed)
    logAuthzEvent("warn", "admin_authz_no_supabase", {
      email: email,
      note: "Supabase not configured and not legacy super-admin",
    });
    return null;
  }

  try {
    // Look up user by email (include password_hash for verification)
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, email, role, password_hash")
      .eq("email", email.toLowerCase().trim())
      .single();

    if (userError || !user) {
      logAuthzEvent("warn", "admin_authz_user_not_found", {
        email: email,
        error: userError?.message || "user_not_found",
      });
      return null;
    }

    // Verify password against stored hash
    if (!user.password_hash) {
      logAuthzEvent("warn", "admin_authz_no_password_hash", {
        userId: user.id,
        email: user.email,
        note: "User found but password_hash is missing",
      });
      return null;
    }

    const passwordValid = await verifyPassword(password, user.password_hash);
    if (!passwordValid) {
      logAuthzEvent("warn", "admin_authz_invalid_password", {
        userId: user.id,
        email: user.email,
        role: user.role,
        note: "Password verification failed",
      });
      return null;
    }

    // Password is valid - return user with role
    logAuthzEvent("info", "admin_authz_password_verified", {
      userId: user.id,
      email: user.email,
      role: user.role,
      note: "Password verified successfully",
    });

    return {
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      clientIds: null, // Will be loaded separately if needed
    };
  } catch (error) {
    logAuthzEvent("error", "admin_authz_resolve_error", {
      email: email,
      error: error?.message || String(error),
    });
    return null;
  }
}

// Load user's authorized client IDs from Supabase
async function loadUserClientIds(userId) {
  if (!userId) {
    return null; // Legacy super-admin or invalid user
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    return null;
  }

  try {
    const { data: memberships, error } = await supabase
      .from("client_users")
      .select("client_id")
      .eq("user_id", userId);

    if (error) {
      logAuthzEvent("error", "admin_authz_load_client_ids_error", {
        userId: userId,
        error: error?.message || String(error),
      });
      return [];
    }

    const clientIds = (memberships || []).map(m => m.client_id).filter(Boolean);
    return clientIds;
  } catch (error) {
    logAuthzEvent("error", "admin_authz_load_client_ids_error", {
      userId: userId,
      error: error?.message || String(error),
    });
    return [];
  }
}

// Check if user is super admin
// Supports both legacy admin (ADMIN_EMAIL env var) and Supabase super_admin role
function isSuperAdmin(req) {
  if (!req.session || !req.session.admin) {
    return false;
  }
  
  // Check legacy admin (ADMIN_EMAIL match)
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
  const isLegacyAdmin = req.session.admin.email === ADMIN_EMAIL && ADMIN_EMAIL !== "";
  
  // Check Supabase role-based auth
  const authz = req.session.admin.authz;
  const isRoleBasedSuperAdmin = authz && authz.role === "super_admin";
  
  return isLegacyAdmin || isRoleBasedSuperAdmin;
}

// Check if user can access a specific client
// Supports both legacy admin (ADMIN_EMAIL env var) and role-based auth
function canAccessClient(req, clientId) {
  if (!req.session || !req.session.admin) {
    return false;
  }

  // Legacy admin (ADMIN_EMAIL) can access all clients
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
  const isLegacyAdmin = req.session.admin.email === ADMIN_EMAIL && ADMIN_EMAIL !== "";
  if (isLegacyAdmin) {
    return true;
  }

  const authz = req.session.admin.authz;
  if (!authz) {
    return false;
  }

  // Super admin can access all clients
  if (authz.role === "super_admin") {
    return true;
  }

  // Client admin can only access their assigned clients
  if (authz.role === "client_admin") {
    const allowedClients = authz.clientIds || [];
    return allowedClients.includes(clientId);
  }

  // Default: deny access (fail closed)
  return false;
}

// Get user's authorized client IDs (returns null for super_admin, array for client_admin)
// Supports both legacy admin (ADMIN_EMAIL env var) and role-based auth
function getAuthorizedClientIds(req) {
  if (!req.session || !req.session.admin) {
    return null;
  }

  // Legacy admin (ADMIN_EMAIL) has access to all clients
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
  const isLegacyAdmin = req.session.admin.email === ADMIN_EMAIL && ADMIN_EMAIL !== "";
  if (isLegacyAdmin) {
    return null; // null means "all clients"
  }

  const authz = req.session.admin.authz;
  if (!authz) {
    return null;
  }

  if (authz.role === "super_admin") {
    return null; // null means "all clients"
  }

  return authz.clientIds || [];
}

module.exports = {
  resolveUserFromSupabase,
  loadUserClientIds,
  isSuperAdmin,
  canAccessClient,
  getAuthorizedClientIds,
  verifyPassword,
  logAuthzEvent,
};

