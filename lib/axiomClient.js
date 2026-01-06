const axios = require("axios");

// Axiom API client for analytics queries
// Fail-safe: returns empty results on errors, logs warnings (never crashes portal)

const AXIOM_API_TOKEN = process.env.AXIOM_API_TOKEN || null;
const AXIOM_API_URL = process.env.AXIOM_API_URL || "https://api.axiom.co";
const AXIOM_DATASET = process.env.AXIOM_DATASET || "advantum-prod-log";
const AXIOM_QUERY_TIMEOUT_MS = 30000; // 30 seconds

// Normalize API URL (strip trailing slash, ensure base URL)
function normalizeApiUrl(baseUrl) {
  if (!baseUrl || typeof baseUrl !== "string") {
    return "https://api.axiom.co";
  }
  // Remove trailing slash
  let url = baseUrl.trim().replace(/\/+$/, "");
  return url;
}

const normalizedApiUrl = normalizeApiUrl(AXIOM_API_URL);

// Error log deduplication: track recent errors to avoid spam
const errorLogDedup = new Map();
const ERROR_LOG_DEDUP_WINDOW_MS = 60000; // 1 minute window

// Clean up old dedup entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamp] of errorLogDedup.entries()) {
    if (now - timestamp > ERROR_LOG_DEDUP_WINDOW_MS) {
      errorLogDedup.delete(key);
    }
  }
}, 30000); // Clean every 30 seconds

// Structured logging helper
function logAxiomEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "axiom_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

/**
 * Run an Axiom query via API
 * @param {object} options
 * @param {string} options.queryText - The APL query text
 * @param {object} options.params - Query parameters (e.g., { start_time: "...", end_time: "...", dataset?: "..." })
 * @param {string} options.dataset - Dataset name (defaults to AXIOM_DATASET env var)
 * @returns {Promise<Array>} Array of result rows (empty array on error)
 */
async function runQuery({ queryText, params = {}, dataset = null }) {
  if (!AXIOM_API_TOKEN) {
    logAxiomEvent("warn", "axiom_query_no_token", {
      note: "AXIOM_API_TOKEN not configured, returning empty results",
    });
    return [];
  }

  if (!queryText || typeof queryText !== "string") {
    logAxiomEvent("warn", "axiom_query_invalid_input", {
      error: "queryText must be a non-empty string",
    });
    return [];
  }

  // Use provided dataset or fall back to env var or default
  const targetDataset = dataset || params.dataset || AXIOM_DATASET;

  try {
    // Construct API endpoint - Axiom dataset-specific query endpoint
    // Use /v1/datasets/{dataset}/query for dataset-scoped queries
    const endpoint = `${normalizedApiUrl}/v1/datasets/${encodeURIComponent(targetDataset)}/query`;
    
    // Prepare request body
    // Axiom API format: { apl: "query text", startTime?: string, endTime?: string }
    const requestBody = {
      apl: queryText,
      ...(params.start_time ? { startTime: params.start_time } : {}),
      ...(params.end_time ? { endTime: params.end_time } : {}),
    };

    // Prepare headers
    const headers = {
      "Authorization": `Bearer ${AXIOM_API_TOKEN}`,
      "Content-Type": "application/json",
    };

    // Log request details (debug level, sanitized - no tokens)
    // Include first 120 chars of query text for debugging
    const queryTextSnippet = queryText.slice(0, 120);
    logAxiomEvent("debug", "axiom_query_request", {
      method: "POST",
      endpoint: endpoint,
      dataset: targetDataset,
      hasQueryText: !!queryText,
      queryTextLength: queryText.length,
      queryTextSnippet: queryTextSnippet,
      hasStartTime: !!params.start_time,
      startTime: params.start_time || null,
      hasEndTime: !!params.end_time,
      endTime: params.end_time || null,
    });

    // Make API request
    const response = await axios.post(
      endpoint,
      requestBody,
      {
        headers: headers,
        timeout: AXIOM_QUERY_TIMEOUT_MS,
      }
    );

    // Extract rows from response (tabular format: { tables: [{ rows: [...] }] })
    let rows = [];
    if (response.data) {
      if (response.data.tables && Array.isArray(response.data.tables) && response.data.tables.length > 0) {
        // Tabular format: extract rows from first table
        rows = response.data.tables[0].rows || [];
      } else if (response.data.matches && Array.isArray(response.data.matches)) {
        // Fallback: matches format (if API returns different structure)
        rows = response.data.matches;
      } else if (Array.isArray(response.data)) {
        // Fallback: direct array
        rows = response.data;
      } else if (response.data.data && Array.isArray(response.data.data)) {
        // Fallback: nested data
        rows = response.data.data;
      }
    }

    logAxiomEvent("info", "axiom_query_success", {
      rowsReturned: rows.length,
      statusCode: response.status,
      dataset: targetDataset,
      hasStartTime: !!params.start_time,
      hasEndTime: !!params.end_time,
      note: "Query executed successfully",
    });

    // If rowsReturned is 0, log diagnostic information
    if (rows.length === 0) {
      logAxiomEvent("warn", "axiom_query_zero_rows", {
        dataset: targetDataset,
        startTime: params.start_time || null,
        endTime: params.end_time || null,
        queryTextSnippet: queryTextSnippet,
        hint: "Check that _time field matches the time range and dataset contains data",
        note: "Query returned 0 rows - check timestamp field _time and dataset",
      });
    }

    return rows || [];
  } catch (error) {
    // Fail-safe: log error but return empty results
    const errorMessage = error?.response?.data?.message || error?.response?.data?.error || error?.message || String(error);
    const statusCode = error?.response?.status || null;
    const responseBody = error?.response?.data ? JSON.stringify(error.response.data).slice(0, 500) : null;
    
    // Deduplicate error logs to avoid spam (log same error type once per minute)
    const endpointPath = `${normalizedApiUrl}/v1/datasets/${encodeURIComponent(targetDataset)}/query`;
    const errorKey = `error_${statusCode || 'unknown'}`;
    const now = Date.now();
    const lastLogged = errorLogDedup.get(errorKey);
    
    if (!lastLogged || (now - lastLogged > ERROR_LOG_DEDUP_WINDOW_MS)) {
      // Log detailed error info (sanitized, no tokens)
      logAxiomEvent("warn", "axiom_query_error", {
        error: errorMessage,
        statusCode: statusCode,
        method: "POST",
        endpoint: endpointPath,
        dataset: targetDataset,
        startTime: params.start_time || null,
        endTime: params.end_time || null,
        responseBodySnippet: responseBody,
        note: "Query failed, returning empty results (fail-safe)",
      });
      
      errorLogDedup.set(errorKey, now);
    }

    return [];
  }
}

module.exports = {
  runQuery,
  logAxiomEvent,
};
