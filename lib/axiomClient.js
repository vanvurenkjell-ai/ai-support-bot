const axios = require("axios");

// Axiom API client for analytics queries
// Fail-safe: returns empty results on errors, logs warnings (never crashes portal)

const AXIOM_API_TOKEN = process.env.AXIOM_API_TOKEN || null;
const AXIOM_API_URL = process.env.AXIOM_API_URL || "https://api.axiom.co/v1";
const AXIOM_ORG_ID = process.env.AXIOM_ORG_ID || null;
const AXIOM_QUERY_TIMEOUT_MS = 30000; // 30 seconds

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
 * @param {string} options.queryText - The AQL query text
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
    // Construct API endpoint
    const endpoint = `${AXIOM_API_URL}/datasets/query`;
    
    // Prepare request body
    // Axiom API format: query text with parameters
    const requestBody = {
      apl: queryText, // APL (Axiom Processing Language) query
      ...(AXIOM_ORG_ID ? { organizationId: AXIOM_ORG_ID } : {}),
    };

    // Make API request
    const response = await axios.post(
      endpoint,
      requestBody,
      {
        headers: {
          "Authorization": `Bearer ${AXIOM_API_TOKEN}`,
          "Content-Type": "application/json",
        },
        timeout: AXIOM_QUERY_TIMEOUT_MS,
      }
    );

    // Extract rows from response
    // Axiom API typically returns: { status: { ... }, matches: [ ... ], buckets: { ... } }
    // For query results, rows are typically in matches or status.rows
    let rows = [];
    if (response.data && response.data.matches) {
      rows = response.data.matches;
    } else if (response.data && response.data.status && response.data.status.rows) {
      rows = response.data.status.rows;
    } else if (Array.isArray(response.data)) {
      rows = response.data;
    } else if (response.data && response.data.data) {
      rows = Array.isArray(response.data.data) ? response.data.data : [];
    }

    logAxiomEvent("info", "axiom_query_success", {
      rowsReturned: rows.length,
      note: "Query executed successfully",
    });

    return rows || [];
  } catch (error) {
    // Fail-safe: log error but return empty results
    const errorMessage = error?.response?.data?.message || error?.message || String(error);
    const statusCode = error?.response?.status || null;
    
    logAxiomEvent("warn", "axiom_query_error", {
      error: errorMessage,
      statusCode: statusCode,
      note: "Query failed, returning empty results (fail-safe)",
    });

    return [];
  }
}

module.exports = {
  runQuery,
  logAxiomEvent,
};

