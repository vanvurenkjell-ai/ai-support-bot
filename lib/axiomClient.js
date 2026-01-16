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
    // Construct API endpoint - dataset-specific query endpoint
    // This endpoint properly handles startTime/endTime for time filtering
    const endpoint = `${normalizedApiUrl}/v1/datasets/${targetDataset}/query`;

    // Time filtering via startTime/endTime in request body - REQUIRED, never null
    const now = new Date();
    const defaultStartTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days ago
    const defaultEndTime = now.toISOString();

    const startTime = params.start_time
      ? (typeof params.start_time === "string" ? params.start_time : new Date(params.start_time).toISOString())
      : defaultStartTime;
    const endTime = params.end_time
      ? (typeof params.end_time === "string" ? params.end_time : new Date(params.end_time).toISOString())
      : defaultEndTime;

    // Prepare request body - query (without dataset prefix) + time range params
    // Dataset is in the URL, NOT in the query text
    // startTime and endTime are REQUIRED by /query endpoint
    const requestBody = {
      query: queryText,
      startTime: startTime,
      endTime: endTime,
    };

    // Prepare headers
    const headers = {
      "Authorization": `Bearer ${AXIOM_API_TOKEN}`,
      "Content-Type": "application/json",
    };

    // Diagnostic logging: Log request body shape (safe, no secrets)
    const queryTextSnippet = queryText.slice(0, 150);
    const requestBodyKeys = Object.keys(requestBody);
    logAxiomEvent("info", "axiom_query_request", {
      method: "POST",
      endpoint: endpoint,
      dataset: targetDataset,
      requestBodyKeys: requestBodyKeys,
      requestBodyShape: {
        hasQuery: "query" in requestBody,
        hasStartTime: "startTime" in requestBody,
        hasEndTime: "endTime" in requestBody,
      },
      querySnippet: queryTextSnippet,
      queryLength: queryText.length,
      startTime: startTime || null,
      endTime: endTime || null,
      note: "Dataset in URL, time filtering via request body startTime/endTime",
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

    // Diagnostic logging: Log response shape
    const responseDataKeys = response.data ? Object.keys(response.data) : [];
    let firstRowKeys = null;
    // /query endpoint returns { matches: [], buckets: {}, fieldsMeta: [] }
    if (response.data && response.data.matches && Array.isArray(response.data.matches) && response.data.matches.length > 0) {
      firstRowKeys = Object.keys(response.data.matches[0]);
    }

    logAxiomEvent("debug", "axiom_query_response_shape", {
      responseDataKeys: responseDataKeys,
      firstRowKeys: firstRowKeys,
      hasMatches: response.data && "matches" in response.data,
      matchesLength: response.data && response.data.matches ? response.data.matches.length : 0,
    });

    // Extract rows from response
    // /query endpoint returns: { matches: [...], buckets: {}, fieldsMeta: [] }
    let rows = [];
    if (response.data) {
      if (response.data.matches && Array.isArray(response.data.matches)) {
        // Primary: /query endpoint returns matches array directly
        rows = response.data.matches;
      } else if (response.data.tables && Array.isArray(response.data.tables) && response.data.tables.length > 0) {
        // Fallback: _apl endpoint returns tabular format
        rows = response.data.tables[0].rows || [];
      } else if (Array.isArray(response.data)) {
        // Fallback: direct array
        rows = response.data;
      } else if (response.data.data && Array.isArray(response.data.data)) {
        // Fallback: nested data
        rows = response.data.data;
      }
    }

    // Contract validation: Detect if query wasn't actually executed
    // If query contains "take 1" or "limit 1" but returns exactly 1000 rows, API contract is wrong
    const hasTakeLimit = /take\s+\d+|limit\s+\d+/i.test(queryText);
    const takeLimitMatch = queryText.match(/(?:take|limit)\s+(\d+)/i);
    const expectedMaxRows = takeLimitMatch ? parseInt(takeLimitMatch[1], 10) : null;
    
    if (hasTakeLimit && rows.length === 1000 && expectedMaxRows && expectedMaxRows < 1000) {
      logAxiomEvent("warn", "axiom_query_contract_mismatch", {
        dataset: targetDataset,
        queryTextSnippet: queryTextSnippet,
        rowsReturned: rows.length,
        expectedMaxRows: expectedMaxRows,
        hasStartTime: !!startTime,
        hasEndTime: !!endTime,
        endpoint: endpoint,
        requestBodyKeys: requestBodyKeys,
        hint: "Query contains take/limit but returned 1000 rows - API contract may be incorrect, query may not be executing",
        note: "API may be returning default/unfiltered payload instead of executing APL",
      });
    }

    logAxiomEvent("info", "axiom_query_success", {
      rowsReturned: rows.length,
      statusCode: response.status,
      dataset: targetDataset,
      hasStartTime: !!startTime,
      hasEndTime: !!endTime,
      expectedMaxRows: expectedMaxRows || null,
      requestBodyKeys: requestBodyKeys,
      note: "Query executed successfully",
    });

    // If rowsReturned is 0, log diagnostic information
    if (rows.length === 0) {
      logAxiomEvent("warn", "axiom_query_zero_rows", {
        dataset: targetDataset,
        startTime: startTime || null,
        endTime: endTime || null,
        queryTextSnippet: queryTextSnippet,
        requestBodyKeys: requestBodyKeys,
        requestBodyShape: {
          hasQuery: "query" in requestBody,
          hasStartTime: "startTime" in requestBody,
          hasEndTime: "endTime" in requestBody,
        },
        hint: "Check that time range covers data and dataset contains matching records",
        note: "Query returned 0 rows - verify startTime/endTime range and filters",
      });
    }

    return rows || [];
  } catch (error) {
    // Fail-safe: log error but return empty results
    const errorMessage = error?.response?.data?.message || error?.response?.data?.error || error?.message || String(error);
    const statusCode = error?.response?.status || null;
    const responseBody = error?.response?.data ? JSON.stringify(error.response.data).slice(0, 500) : null;
    
    // Deduplicate error logs to avoid spam (log same error type once per minute)
    const endpointPath = `${normalizedApiUrl}/v1/datasets/${targetDataset}/query`;
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

/**
 * Diagnostic: Check which timestamp field exists in the dataset
 * Runs: | take 1 | project _time, timestamp
 * @returns {Promise<object>} { hasTime: boolean, hasTimestamp: boolean, sampleRow: object }
 */
async function diagnoseTimestampField() {
  const dataset = process.env.AXIOM_DATASET || "advantum-prod-log";
  // Query without dataset prefix (dataset is in URL)
  const diagnosticQuery = `| take 1 | project _time, timestamp`;

  // Default time range: last 30 days
  const now = new Date();
  const startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const endTime = now.toISOString();

  logAxiomEvent("info", "axiom_timestamp_diagnostic_start", {
    dataset: dataset,
    query: diagnosticQuery,
    startTime: startTime,
    endTime: endTime,
  });

  try {
    // Dataset-specific query endpoint
    const endpoint = `${normalizedApiUrl}/v1/datasets/${dataset}/query`;
    const headers = {
      "Authorization": `Bearer ${AXIOM_API_TOKEN}`,
      "Content-Type": "application/json",
    };

    const response = await axios.post(
      endpoint,
      { query: diagnosticQuery, startTime: startTime, endTime: endTime },
      { headers: headers, timeout: AXIOM_QUERY_TIMEOUT_MS }
    );

    // /query endpoint returns { matches: [], buckets: {}, fieldsMeta: [] }
    let rows = [];
    if (response.data && response.data.matches && Array.isArray(response.data.matches)) {
      rows = response.data.matches;
    }

    const sampleRow = rows[0] || {};
    const hasTime = "_time" in sampleRow && sampleRow._time !== null;
    const hasTimestamp = "timestamp" in sampleRow && sampleRow.timestamp !== null;

    logAxiomEvent("info", "axiom_timestamp_diagnostic_result", {
      dataset: dataset,
      hasTime: hasTime,
      hasTimestamp: hasTimestamp,
      sampleRow: JSON.stringify(sampleRow).slice(0, 500),
      recommendedField: hasTime ? "_time" : (hasTimestamp ? "timestamp" : "unknown"),
    });

    return { hasTime, hasTimestamp, sampleRow };
  } catch (error) {
    const errorMessage = error?.response?.data?.message || error?.message || String(error);
    logAxiomEvent("error", "axiom_timestamp_diagnostic_error", {
      dataset: dataset,
      error: errorMessage,
    });
    return { hasTime: false, hasTimestamp: false, sampleRow: {}, error: errorMessage };
  }
}

/**
 * Smoke test: Verify query endpoint with a simple query
 * Runs: | where event == "request_end" | take 1
 * @returns {Promise<object>} { success: boolean, rowsReturned: number, sampleRow: object }
 */
async function smokeTestQuery() {
  const dataset = process.env.AXIOM_DATASET || "advantum-prod-log";
  // Query without dataset prefix (dataset is in URL)
  const smokeQuery = `| where event == "request_end" | take 1`;

  // Default time range: last 30 days
  const now = new Date();
  const startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
  const endTime = now.toISOString();

  logAxiomEvent("info", "axiom_smoke_test_start", {
    dataset: dataset,
    query: smokeQuery,
    startTime: startTime,
    endTime: endTime,
  });

  try {
    // Dataset-specific query endpoint
    const endpoint = `${normalizedApiUrl}/v1/datasets/${dataset}/query`;
    const headers = {
      "Authorization": `Bearer ${AXIOM_API_TOKEN}`,
      "Content-Type": "application/json",
    };

    const response = await axios.post(
      endpoint,
      { query: smokeQuery, startTime: startTime, endTime: endTime },
      { headers: headers, timeout: AXIOM_QUERY_TIMEOUT_MS }
    );

    // /query endpoint returns { matches: [], buckets: {}, fieldsMeta: [] }
    let rows = [];
    if (response.data && response.data.matches && Array.isArray(response.data.matches)) {
      rows = response.data.matches;
    }

    const success = rows.length > 0;
    logAxiomEvent("info", "axiom_smoke_test_result", {
      dataset: dataset,
      success: success,
      rowsReturned: rows.length,
      sampleRowKeys: rows[0] ? Object.keys(rows[0]) : [],
    });

    return { success, rowsReturned: rows.length, sampleRow: rows[0] || {} };
  } catch (error) {
    const errorMessage = error?.response?.data?.message || error?.message || String(error);
    logAxiomEvent("error", "axiom_smoke_test_error", {
      dataset: dataset,
      error: errorMessage,
    });
    return { success: false, rowsReturned: 0, sampleRow: {}, error: errorMessage };
  }
}

module.exports = {
  runQuery,
  logAxiomEvent,
  diagnoseTimestampField,
  smokeTestQuery,
};
