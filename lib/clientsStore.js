const fs = require("fs");
const path = require("path");

// Simple logging helper (matches existing pattern)
function logStoreEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "clients_store_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Get the clients root directory (from env var or default)
// In dev/local: defaults to process.cwd() + "Clients"
// In production: use CLIENTS_ROOT env var (e.g., /var/data/Clients for Render persistent disk)
function getClientsRoot() {
  if (process.env.CLIENTS_ROOT) {
    return path.resolve(process.env.CLIENTS_ROOT);
  }
  // Default: process.cwd() + Clients (works for dev/local)
  return path.resolve(process.cwd(), "Clients");
}

// Ensure the clients root directory exists (create if needed)
// Call this at startup to ensure the directory is ready
function ensureClientsRoot() {
  const root = getClientsRoot();
  if (!fs.existsSync(root)) {
    try {
      fs.mkdirSync(root, { recursive: true });
      logStoreEvent("info", "clients_root_created", {
        path: root,
        reason: "directory_did_not_exist",
      });
    } catch (error) {
      logStoreEvent("error", "clients_root_creation_failed", {
        path: root,
        error: error?.message || String(error),
      });
      throw error;
    }
  }
  return root;
}

// Validate clientId format: 2-33 chars total (pattern: /^[A-Za-z0-9][A-Za-z0-9_-]{1,32}$/), starts with letter, only alphanumeric/underscore/hyphen
function validateClientId(clientId) {
  if (!clientId || typeof clientId !== "string") {
    return { valid: false, reason: "missing_or_invalid_type" };
  }
  const trimmed = clientId.trim();
  // Pattern: /^[A-Za-z0-9][A-Za-z0-9_-]{1,32}$/ means 2-33 chars total, first char must be alphanumeric (we enforce letter)
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

// Get client config path with path traversal protection
function getClientConfigPath(clientId) {
  const validation = validateClientId(clientId);
  if (!validation.valid) {
    return { valid: false, path: null, dir: null, reason: validation.reason };
  }

  const clientsRoot = getClientsRoot();
  const clientDir = path.join(clientsRoot, validation.clientId);
  const configPath = path.join(clientDir, "client-config.json");

  // Resolve to absolute paths
  const resolvedPath = path.resolve(configPath);
  const resolvedDir = path.resolve(clientDir);
  const clientsRootNormalized = path.normalize(clientsRoot);
  const resolvedPathNormalized = path.normalize(resolvedPath);
  const resolvedDirNormalized = path.normalize(resolvedDir);

  // Enforce containment - paths must be within clientsRoot
  if (!resolvedPathNormalized.startsWith(clientsRootNormalized + path.sep) && resolvedPathNormalized !== clientsRootNormalized) {
    return { valid: false, path: null, dir: null, reason: "path_traversal_detected" };
  }
  if (!resolvedDirNormalized.startsWith(clientsRootNormalized + path.sep) && resolvedDirNormalized !== clientsRootNormalized) {
    return { valid: false, path: null, dir: null, reason: "path_traversal_detected" };
  }

  return { valid: true, path: resolvedPath, dir: resolvedDir, clientId: validation.clientId };
}

// Ensure client directory exists
function ensureClientDir(clientId) {
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid) {
    return { success: false, error: `Invalid client ID: ${pathResult.reason}` };
  }

  try {
    if (!fs.existsSync(pathResult.dir)) {
      fs.mkdirSync(pathResult.dir, { recursive: true });
    }
    return { success: true, dir: pathResult.dir };
  } catch (error) {
    logStoreEvent("error", "clients_store_dir_creation_failed", {
      clientId: pathResult.clientId,
      dir: pathResult.dir,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// Read client config from disk
function readClientConfig(clientId) {
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid || !fs.existsSync(pathResult.path)) {
    return null;
  }

  try {
    const configContent = fs.readFileSync(pathResult.path, "utf8");
    return JSON.parse(configContent);
  } catch (error) {
    logStoreEvent("error", "clients_store_read_error", {
      clientId: pathResult.clientId,
      path: pathResult.path,
      error: error?.message || String(error),
    });
    return null;
  }
}

// Write client config atomically (write to temp file then rename)
function writeClientConfigAtomic(clientId, config) {
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid) {
    return { success: false, error: `Invalid client ID: ${pathResult.reason}` };
  }

  try {
    // Ensure directory exists
    const dirResult = ensureClientDir(clientId);
    if (!dirResult.success) {
      return dirResult;
    }

    // Write to temp file first
    const tempPath = `${pathResult.path}.tmp`;
    const configJson = JSON.stringify(config, null, 2) + "\n";
    fs.writeFileSync(tempPath, configJson, "utf8");

    // Atomic rename
    fs.renameSync(tempPath, pathResult.path);

    return { success: true, path: pathResult.path };
  } catch (error) {
    logStoreEvent("error", "clients_store_write_error", {
      clientId: pathResult.clientId,
      path: pathResult.path,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// List all client IDs (directories only)
function listClientIds() {
  const clientsRoot = getClientsRoot();
  
  if (!fs.existsSync(clientsRoot)) {
    return [];
  }

  try {
    const entries = fs.readdirSync(clientsRoot, { withFileTypes: true });
    return entries
      .filter(entry => entry.isDirectory())
      .map(entry => entry.name)
      .filter(name => {
        const validation = validateClientId(name);
        return validation.valid;
      })
      .sort();
  } catch (error) {
    logStoreEvent("error", "clients_store_list_error", {
      root: clientsRoot,
      error: error?.message || String(error),
    });
    return [];
  }
}

// Delete client (remove directory recursively, but only if within clientsRoot)
function deleteClient(clientId) {
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid) {
    return { success: false, error: `Invalid client ID: ${pathResult.reason}` };
  }

  if (!fs.existsSync(pathResult.dir)) {
    return { success: false, error: "Client directory does not exist" };
  }

  try {
    // Double-check containment before deletion
    const clientsRootNormalized = path.normalize(getClientsRoot());
    const resolvedDirNormalized = path.normalize(path.resolve(pathResult.dir));
    
    if (!resolvedDirNormalized.startsWith(clientsRootNormalized + path.sep) && resolvedDirNormalized !== clientsRootNormalized) {
      return { success: false, error: "Path traversal detected" };
    }

    // Remove directory recursively
    fs.rmSync(pathResult.dir, { recursive: true, force: true });

    return { success: true };
  } catch (error) {
    logStoreEvent("error", "clients_store_delete_error", {
      clientId: pathResult.clientId,
      dir: pathResult.dir,
      error: error?.message || String(error),
    });
    return { success: false, error: error?.message || String(error) };
  }
}

// Get config file stats (for displaying last modified time)
function getClientConfigStats(clientId) {
  const pathResult = getClientConfigPath(clientId);
  if (!pathResult.valid || !fs.existsSync(pathResult.path)) {
    return null;
  }

  try {
    const stats = fs.statSync(pathResult.path);
    return {
      mtime: stats.mtime,
      mtimeISO: stats.mtime.toISOString(),
      size: stats.size,
      path: pathResult.path,
    };
  } catch (error) {
    return null;
  }
}

module.exports = {
  getClientsRoot,
  ensureClientsRoot,
  validateClientId,
  getClientConfigPath,
  ensureClientDir,
  readClientConfig,
  writeClientConfigAtomic,
  listClientIds,
  deleteClient,
  getClientConfigStats,
};

