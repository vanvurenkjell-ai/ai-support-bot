// Legacy admin identity management
// Provides a stable, deterministic UUID for the legacy env-based super-admin
// This ensures legacy admin actions (invitations, audits, etc.) always have a valid actor_user_id

const crypto = require("crypto");

// Simple logging helper
function logIdentityEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "legacy_admin_identity_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Validate UUID format (RFC 4122)
function isValidUUID(uuid) {
  if (!uuid || typeof uuid !== "string") {
    return false;
  }
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

// Generate UUID v5 (deterministic) from namespace and name
// Uses RFC 4122 UUID v5 algorithm: SHA-1(namespace + name) -> UUID format
function uuidV5(namespace, name) {
  // Convert namespace UUID to bytes (remove dashes, convert to bytes)
  const namespaceBytes = Buffer.from(namespace.replace(/-/g, ""), "hex");
  
  // Combine namespace and name
  const input = Buffer.concat([namespaceBytes, Buffer.from(name, "utf8")]);
  
  // SHA-1 hash
  const hash = crypto.createHash("sha1").update(input).digest();
  
  // Convert to UUID v5 format
  // Set version (5) in byte 6 and variant (RFC 4122) in byte 8
  hash[6] = (hash[6] & 0x0f) | 0x50; // Version 5
  hash[8] = (hash[8] & 0x3f) | 0x80; // Variant RFC 4122
  
  // Format as UUID string
  const uuidParts = [
    hash.slice(0, 4).toString("hex"),
    hash.slice(4, 6).toString("hex"),
    hash.slice(6, 8).toString("hex"),
    hash.slice(8, 10).toString("hex"),
    hash.slice(10, 16).toString("hex"),
  ];
  
  return `${uuidParts[0]}-${uuidParts[1]}-${uuidParts[2]}-${uuidParts[3]}-${uuidParts[4]}`;
}

// Get stable UUID for legacy admin user
// Strategy:
// 1. Check LEGACY_ADMIN_USER_ID env var (must be valid UUID)
// 2. Otherwise, generate deterministic UUID v5 from ADMIN_EMAIL using DNS namespace
// Returns: { uuid: string, source: 'env' | 'generated' }
function getLegacyAdminUserId() {
  // Check for explicit env var first
  const envUserId = process.env.LEGACY_ADMIN_USER_ID;
  if (envUserId) {
    if (isValidUUID(envUserId)) {
      logIdentityEvent("info", "legacy_admin_identity_resolved", {
        source: "env",
        note: "Using LEGACY_ADMIN_USER_ID from environment",
      });
      return { uuid: envUserId.toLowerCase(), source: "env" };
    } else {
      logIdentityEvent("error", "legacy_admin_identity_invalid_env", {
        error: "LEGACY_ADMIN_USER_ID is not a valid UUID format",
        value: envUserId ? `${envUserId.slice(0, 10)}...` : "null",
      });
      // Fall through to generation if env var is invalid
    }
  }
  
  // Generate deterministic UUID v5 from ADMIN_EMAIL
  const adminEmail = process.env.ADMIN_EMAIL || "";
  if (!adminEmail) {
    logIdentityEvent("error", "legacy_admin_identity_no_email", {
      error: "ADMIN_EMAIL not set, cannot generate stable UUID",
    });
    throw new Error("ADMIN_EMAIL not configured - cannot resolve legacy admin identity");
  }
  
  // Use DNS namespace UUID (6ba7b810-9dad-11d1-80b4-00c04fd430c8) for UUID v5
  // This ensures same email always produces same UUID across deployments
  const dnsNamespace = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
  const normalizedEmail = adminEmail.trim().toLowerCase();
  const generatedUuid = uuidV5(dnsNamespace, normalizedEmail);
  
  logIdentityEvent("info", "legacy_admin_identity_resolved", {
    source: "generated",
    email: normalizedEmail,
    note: "Generated deterministic UUID v5 from ADMIN_EMAIL",
  });
  
  return { uuid: generatedUuid, source: "generated" };
}

// Get legacy admin user object (for session/user normalization)
// Returns: { id: uuid, email: string, role: 'super_admin', is_legacy_admin: true }
function getLegacyAdminUser() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL || "";
    if (!adminEmail) {
      throw new Error("ADMIN_EMAIL not configured");
    }
    
    const { uuid } = getLegacyAdminUserId();
    
    return {
      id: uuid,
      email: adminEmail.trim().toLowerCase(),
      role: "super_admin",
      is_legacy_admin: true,
    };
  } catch (error) {
    logIdentityEvent("error", "legacy_admin_identity_error", {
      error: error?.message || String(error),
      stack: error?.stack ? String(error.stack).slice(0, 500) : null,
    });
    throw error;
  }
}

module.exports = {
  getLegacyAdminUserId,
  getLegacyAdminUser,
  isValidUUID,
  logIdentityEvent,
};

