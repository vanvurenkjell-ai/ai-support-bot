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

// Resolve user from Supabase by email and verify password
// Returns: { user: { id, email, role }, clientIds: [...] } or null
async function resolveUserFromSupabase(email, password) {
  // Fallback: If Supabase is not configured, use legacy env var auth
  // This maintains backward compatibility for super-admin
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

  // Legacy super-admin check (backward compatibility)
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
    // Look up user by email
    const { data: user, error: userError } = await supabase
      .from("users")
      .select("id, email, role")
      .eq("email", email.toLowerCase().trim())
      .single();

    if (userError || !user) {
      logAuthzEvent("warn", "admin_authz_user_not_found", {
        email: email,
        error: userError?.message || "user_not_found",
      });
      return null;
    }

    // For now, password is still validated via env var for legacy compatibility
    // In a full implementation, you'd store password hashes in Supabase
    // This is a transitional approach
    if (user.role === "super_admin" && email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      logAuthzEvent("info", "admin_authz_supabase_superadmin", {
        userId: user.id,
        email: user.email,
        role: user.role,
      });
      return {
        user: {
          id: user.id,
          email: user.email,
          role: user.role,
        },
        clientIds: null, // null means "all clients" for super_admin
      };
    }

    // For client_admin, we still need password validation
    // For now, use a simple approach: client_admin users need a separate password mechanism
    // This is a placeholder - in production, use proper password hashing in Supabase
    if (user.role === "client_admin") {
      // TODO: Implement proper password verification from Supabase
      // For now, deny if not legacy super-admin
      logAuthzEvent("warn", "admin_authz_client_admin_password_not_implemented", {
        userId: user.id,
        email: user.email,
        note: "Client admin password verification not yet implemented",
      });
      return null;
    }

    return null;
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
function isSuperAdmin(req) {
  if (!req.session || !req.session.admin) {
    return false;
  }
  const authz = req.session.admin.authz;
  return authz && authz.role === "super_admin";
}

// Check if user can access a specific client
function canAccessClient(req, clientId) {
  if (!req.session || !req.session.admin) {
    return false;
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
function getAuthorizedClientIds(req) {
  if (!req.session || !req.session.admin) {
    return null;
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
  logAuthzEvent,
};

