// Client store adapter: chooses between Supabase (production) and filesystem (fallback)
// This provides a unified API for client config operations regardless of backend

const fsStore = require("./clientsStore");

// Lazy-load Supabase store (only if env vars are set, and module is available)
let supabaseStore = null;
let useSupabase = false;

try {
  // Only try to load Supabase store if env vars are present
  if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
    try {
      supabaseStore = require("./clientsStoreSupabase");
      useSupabase = supabaseStore.isSupabaseAvailable();
    } catch (requireError) {
      // @supabase/supabase-js not installed or other error - fall back to filesystem
      console.warn("[CLIENTS_STORE] Supabase env vars set but module not available, using filesystem fallback");
    }
  }
} catch (error) {
  // Fall back to filesystem
  console.warn("[CLIENTS_STORE] Error checking Supabase availability, using filesystem fallback");
}

const activeStore = useSupabase && supabaseStore ? supabaseStore : fsStore;

// Log which store is active at module load
const storeType = useSupabase ? "supabase" : "filesystem";
const storePath = useSupabase
  ? process.env.SUPABASE_URL
  : fsStore.getClientsRoot();

try {
  const logObj = {
    timestamp: new Date().toISOString(),
    level: "info",
    event: "clients_store_backend_selected",
    storeType: storeType,
    storePath: storePath,
    hasSupabaseEnv: !!(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY),
    useSupabase: useSupabase,
    message: useSupabase 
      ? "Supabase is the single source of truth. Filesystem clients will be ignored."
      : "Using filesystem storage (Supabase not configured).",
  };
  console.log(JSON.stringify(logObj));
} catch {
  console.log(`[CLIENTS_STORE] Active backend: ${storeType}`);
}

// Make all async functions handle both sync (filesystem) and async (Supabase) stores
// When Supabase is active, it is the ONLY source of truth (no filesystem fallback)
async function listClientIds() {
  if (useSupabase && supabaseStore) {
    // Supabase is active - use it exclusively
    return await supabaseStore.listClientIds();
  }
  // Filesystem fallback (only when Supabase is not available)
  return activeStore.listClientIds();
}

async function readClientConfig(clientId) {
  if (useSupabase && supabaseStore) {
    // Supabase is active - use it exclusively
    return await supabaseStore.readClientConfig(clientId);
  }
  // Filesystem fallback (only when Supabase is not available)
  return activeStore.readClientConfig(clientId);
}

async function writeClientConfigAtomic(clientId, config, updatedBy = null) {
  if (useSupabase && supabaseStore) {
    // Supabase is active - use it exclusively
    return await supabaseStore.writeClientConfigAtomic(clientId, config, updatedBy);
  }
  // Filesystem fallback (only when Supabase is not available)
  return activeStore.writeClientConfigAtomic(clientId, config);
}

async function deleteClient(clientId) {
  if (useSupabase && supabaseStore) {
    // Supabase is active - use it exclusively
    return await activeStore.deleteClient(clientId);
  }
  // Filesystem fallback (only when Supabase is not available)
  return activeStore.deleteClient(clientId);
}

async function getClientConfigStats(clientId) {
  if (useSupabase && supabaseStore) {
    // Supabase is active - use it exclusively
    return await activeStore.getClientConfigStats(clientId);
  }
  // Filesystem fallback (only when Supabase is not available)
  return activeStore.getClientConfigStats(clientId);
}

// Sync functions (available from both stores)
function validateClientId(clientId) {
  return activeStore.validateClientId(clientId);
}

function getClientConfigPath(clientId) {
  return activeStore.getClientConfigPath(clientId);
}

// Filesystem-only functions (only available when using filesystem store)
function getClientsRoot() {
  if (useSupabase) {
    return "supabase://clients";
  }
  return fsStore.getClientsRoot();
}

function ensureClientsRoot() {
  if (useSupabase) {
    // No-op for Supabase (no filesystem directory needed)
    return "supabase://clients";
  }
  return fsStore.ensureClientsRoot();
}

module.exports = {
  // Core async functions
  listClientIds,
  readClientConfig,
  writeClientConfigAtomic,
  deleteClient,
  getClientConfigStats,
  // Sync functions
  validateClientId,
  getClientConfigPath,
  getClientsRoot,
  ensureClientsRoot,
  // Metadata
  useSupabase: useSupabase,
  storeType: storeType,
};

