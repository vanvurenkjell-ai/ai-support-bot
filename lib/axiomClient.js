const axios = require("axios");

// Axiom API client for analytics queries
// Fail-safe: returns empty results on errors, logs warnings (never crashes portal)

const AXIOM_API_TOKEN = process.env.AXIOM_API_TOKEN || null;
const AXIOM_API_URL = process.env.AXIOM_API_URL || "https://api.axiom.co";
const AXIOM_ORG_ID = process.env.AXIOM_ORG_ID || null;
const AXIOM_QUERY_TIMEOUT_MS = 30000; // 30 seconds

// Normalize API URL (strip trailing slash, ensure base URL)
function normalizeApiUrl(baseUrl) {
  if (!baseUrl || typeof baseUrl !== "string") {
    return "https://api.axiom.co";
  }
  // Remove trailing slash
  let url = baseUrl.trim().replace(/\/+$/, "");
  // Ensure it doesn't already have /v1
  if (!url.endsWith("/v1")) {
    // Don't add /v1 here - we'll add it in the endpoint path
  }
  return url;
}

const normalizedApiUrl = normalizeApiUrl(AXIOM_API_URL);

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
 * @param {object} options.params - Query parameters (e.g., { client_filter: "Advantum", start_time: "...", end_time: "..." })
 * @returns {Promise<Array>} Array of result rows (empty array on error)
 */
async function runQuery({ queryText, params = {} }) {
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

  try {
    // Construct API endpoint - Axiom uses /v1/query for APL queries
    const endpoint = `${normalizedApiUrl}/v1/query`;
    
    // Prepare request body
    // Axiom API format: { apl: "query text", startTime?: string, endTime?: string }
    const requestBody = {
      apl: queryText,
      // Include startTime/endTime if provided in params (optional, queries can handle time filtering internally)
      ...(params.start_time ? { startTime: params.start_time } : {}),
      ...(params.end_time ? { endTime: params.end_time } : {}),
    };

    // Prepare headers
    const headers = {
      "Authorization": `Bearer ${AXIOM_API_TOKEN}`,
      "Content-Type": "application/json",
    };
    
    // Add org ID header if provided
    if (AXIOM_ORG_ID) {
      headers["X-Axiom-Org-Id"] = AXIOM_ORG_ID;
    }

    // Log request details (debug level, sanitized - no tokens)
    logAxiomEvent("debug", "axiom_query_request", {
      method: "POST",
      endpoint: endpoint,
      hasQueryText: !!queryText,
      queryTextLength: queryText.length,
      hasStartTime: !!params.start_time,
      hasEndTime: !!params.end_time,
      hasOrgId: !!AXIOM_ORG_ID,
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

    // Extract rows from response
    // Axiom API returns: { matches: [ ... ], buckets: { ... }, status: { ... } }
    // For query results, rows are in matches array
    let rows = [];
    if (response.data) {
      if (response.data.matches && Array.isArray(response.data.matches)) {
        rows = response.data.matches;
      } else if (response.data.status && response.data.status.rows && Array.isArray(response.data.status.rows)) {
        rows = response.data.status.rows;
      } else if (Array.isArray(response.data)) {
        rows = response.data;
      } else if (response.data.data && Array.isArray(response.data.data)) {
        rows = response.data.data;
      }
    }

    logAxiomEvent("info", "axiom_query_success", {
      rowsReturned: rows.length,
      statusCode: response.status,
      note: "Query executed successfully",
    });

    return rows || [];
  } catch (error) {
    // Fail-safe: log error but return empty results
    const errorMessage = error?.response?.data?.message || error?.response?.data?.error || error?.message || String(error);
    const statusCode = error?.response?.status || null;
    const responseBody = error?.response?.data ? JSON.stringify(error.response.data).slice(0, 500) : null;
    
    // Log detailed error info (sanitized, no tokens)
    logAxiomEvent("warn", "axiom_query_error", {
      error: errorMessage,
      statusCode: statusCode,
      method: "POST",
      endpoint: `${normalizedApiUrl}/v1/query`,
      responseBodySnippet: responseBody,
      note: "Query failed, returning empty results (fail-safe)",
    });

    return [];
  }
}

module.exports = {
  runQuery,
  logAxiomEvent,
};
