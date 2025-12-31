const fs = require("fs");
const path = require("path");

// Maximum file size to read (200KB per file)
const MAX_FILE_SIZE_BYTES = 200 * 1024;

// Base directory for client content (markdown files)
function getClientsContentRoot() {
  return path.resolve(process.cwd(), "Clients");
}

// Safe path resolution: ensures path is within Clients/ directory (prevents traversal)
function resolveClientFolder(clientId) {
  if (!clientId || typeof clientId !== "string") {
    return null;
  }

  const trimmed = clientId.trim();
  if (!trimmed || trimmed.length === 0 || trimmed.length > 100) {
    return null;
  }

  // Reject traversal patterns
  if (
    trimmed.includes("..") ||
    trimmed.includes("/") ||
    trimmed.includes("\\") ||
    trimmed.includes("\0") ||
    trimmed.includes("%2e") ||
    trimmed.includes("%2f") ||
    trimmed.includes("%5c")
  ) {
    return null;
  }

  // Basic character validation (alphanumeric, underscore, hyphen)
  if (!/^[A-Za-z0-9_-]+$/.test(trimmed)) {
    return null;
  }

  const clientsRoot = getClientsContentRoot();
  const candidatePath = path.join(clientsRoot, trimmed);
  const resolvedPath = path.resolve(candidatePath);
  const clientsRootNormalized = path.normalize(clientsRoot);

  // Ensure resolved path is within Clients/ directory
  if (!resolvedPath.startsWith(clientsRootNormalized + path.sep) && resolvedPath !== clientsRootNormalized) {
    return null;
  }

  return resolvedPath;
}

// Case-insensitive folder lookup (scans Clients/ directory once)
let folderCache = null;
let folderCacheTimestamp = 0;
const FOLDER_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function findClientFolderCaseInsensitive(clientId) {
  const now = Date.now();
  
  // Refresh cache if expired
  if (!folderCache || (now - folderCacheTimestamp) > FOLDER_CACHE_TTL_MS) {
    folderCache = new Map();
    folderCacheTimestamp = now;
    
    try {
      const clientsRoot = getClientsContentRoot();
      if (fs.existsSync(clientsRoot) && fs.statSync(clientsRoot).isDirectory()) {
        const entries = fs.readdirSync(clientsRoot, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory()) {
            const lowerName = entry.name.toLowerCase();
            folderCache.set(lowerName, entry.name); // Store original casing
          }
        }
      }
    } catch (e) {
      // If scan fails, return null (will fall back to exact match)
      return null;
    }
  }

  // Try exact match first
  const exactMatch = resolveClientFolder(clientId);
  if (exactMatch && fs.existsSync(exactMatch) && fs.statSync(exactMatch).isDirectory()) {
    return exactMatch;
  }

  // Try case-insensitive match
  const lowerClientId = clientId.toLowerCase();
  const matchedFolderName = folderCache.get(lowerClientId);
  if (matchedFolderName) {
    const matchedPath = resolveClientFolder(matchedFolderName);
    if (matchedPath && fs.existsSync(matchedPath) && fs.statSync(matchedPath).isDirectory()) {
      return matchedPath;
    }
  }

  return null;
}

// Safely read a markdown file with size limit
function readMarkdownFileSafe(filePath) {
  try {
    if (!fs.existsSync(filePath)) {
      return "";
    }

    const stats = fs.statSync(filePath);
    if (!stats.isFile()) {
      return "";
    }

    // Check file size
    if (stats.size > MAX_FILE_SIZE_BYTES) {
      console.warn(`[CLIENT_CONTENT_FS] File too large, skipping: ${filePath} (${stats.size} bytes)`);
      return "";
    }

    // Read file as UTF-8
    const content = fs.readFileSync(filePath, "utf8");
    return content || "";
  } catch (error) {
    // Silently return empty string on any error (file not found, permission, etc.)
    return "";
  }
}

// Load markdown content for a client from filesystem (read-only, non-fatal)
function loadClientMarkdown(clientId) {
  const result = {
    brandVoice: "",
    supportRules: "",
    chunks: [],
  };

  try {
    // Find client folder (case-insensitive fallback)
    const clientFolder = findClientFolderCaseInsensitive(clientId);
    if (!clientFolder || !fs.existsSync(clientFolder)) {
      // No folder found - return empty content (non-fatal)
      return result;
    }

    // Read required markdown files
    const brandVoicePath = path.join(clientFolder, "Brand voice.md");
    const supportRulesPath = path.join(clientFolder, "Customer support rules.md");
    
    result.brandVoice = readMarkdownFileSafe(brandVoicePath);
    result.supportRules = readMarkdownFileSafe(supportRulesPath);

    // Read optional knowledge files
    // Store raw content - chunking will be done by chunkMarkdown() in index.js
    const knowledgeFiles = [
      "FAQ.md",
      "Policies.md",
      "Products.md",
      "Company overview.md",
      "Legal.md",
      "Product tutorials.md",
      "Promotions & discounts.md",
      "Shipping matrix.md",
      "Troubleshooting.md",
    ];

    const loadedFiles = [];
    for (const filename of knowledgeFiles) {
      const filePath = path.join(clientFolder, filename);
      const content = readMarkdownFileSafe(filePath);
      if (content && content.trim()) {
        // Store raw markdown content - will be chunked properly by chunkMarkdown() in loadClient()
        result.chunks.push({
          source: filename,
          rawContent: content.trim(), // Raw markdown, not yet chunked
        });
        loadedFiles.push(filename);
      }
    }

    // Log what was loaded (for observability, but no file contents)
    if (loadedFiles.length > 0 || result.brandVoice || result.supportRules) {
      const logObj = {
        timestamp: new Date().toISOString(),
        level: "info",
        event: "client_markdown_loaded",
        clientId: clientId,
        clientFolder: clientFolder,
        loadedFiles: loadedFiles.length,
        hasBrandVoice: !!result.brandVoice,
        hasSupportRules: !!result.supportRules,
        knowledgeFileCount: result.chunks.length,
        loadedFileNames: loadedFiles, // List of filenames loaded
      };
      console.log(JSON.stringify(logObj));
    }

    return result;
  } catch (error) {
    // Log error but return empty result (non-fatal)
    const logObj = {
      timestamp: new Date().toISOString(),
      level: "error",
      event: "client_markdown_load_error",
      clientId: clientId,
      error: error?.message || String(error),
    };
    console.error(JSON.stringify(logObj));
    return result;
  }
}

module.exports = {
  getClientsContentRoot,
  resolveClientFolder,
  findClientFolderCaseInsensitive,
  readMarkdownFileSafe,
  loadClientMarkdown,
};

