const { runQuery } = require("./axiomClient");

// Analytics service for client-facing metrics
// Enforces date range limits, normalizes responses, computes derived metrics

// Query definitions map: queryName -> { defaultRangeDays, queryText, normalizeFn }
// Note: APL uses single pipe | not double pipe |
const QUERY_DEFINITIONS = {
  total_chats_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize totalChats = count()`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) || rows.length === 0) return { totalChats: 0 };
      const row = rows[0];
      return { totalChats: row.totalChats || 0 };
    },
  },

  bot_handled_pct_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize botHandledPct = round(100.0 * countif(routedTo == "bot") / count(), 2)`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) | rows.length === 0) return { botHandledPct: 0 };
      const row = rows[0];
      return { botHandledPct: row.botHandledPct || 0 };
    },
  },

  total_escalations_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize totalEscalations = countif(routedTo == "human")`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) | rows.length === 0) return { totalEscalations: 0 };
      const row = rows[0];
      return { totalEscalations: row.totalEscalations || 0 };
    },
  },

  money_saved_total_v1: {
    defaultRangeDays: 30,
    queryText: `let costPerHumanChat = 3.0;
['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize estimatedSavedEUR = round(costPerHumanChat * (count() - countif(routedTo == "human")), 2)`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) | rows.length === 0) return { estimatedSavedEUR: 0, estimatedSavedEURDisplay: "€0.00" };
      const row = rows[0];
      const value = row.estimatedSavedEUR || 0;
      return {
        estimatedSavedEUR: value,
        estimatedSavedEURDisplay: `€${value.toFixed(2)}`,
      };
    },
  },

  avg_response_time_by_day_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"
| where isnotnull(latencyMs)| summarize
    avgLatencyMs = round(avg(latencyMs), 0),
    chats = count()
  by bin(_time, 1d)
| where chats > 0
| project _time, avgLatencyMs, chats
| order by _time asc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows)) return { series: [], weightedAvg: 0 };
      const series = rows.map(row => ({
        date: row._time || null,
        avgLatencyMs: row.avgLatencyMs || 0,
        chats: row.chats || 0,
      }));
      
      // Compute weighted average: sum(avgLatencyMs * chats) / sum(chats)
      let totalWeighted = 0;
      let totalChats = 0;
      for (const item of series) {
        totalWeighted += item.avgLatencyMs * item.chats;
        totalChats += item.chats;
      }
      const weightedAvg = totalChats > 0 ? Math.round(totalWeighted / totalChats) : 0;
      
      return { series, weightedAvg };
    },
  },

  chats_per_day_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize chats = count() by bin(_time, 1d)
| order by _time asc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows)) return { series: [] };
      return {
        series: rows.map(row => ({
          date: row._time || null,
          chats: row.chats || 0,
        })),
      };
    },
  },

  bot_handling_over_time_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize
    totalChats = count(),
    escalatedChats = countif(routedTo == "human")
  by bin(_time, 1d)
| where totalChats > 0
| extend botHandledChats = totalChats - escalatedChats
| extend botHandlingRatePct = round(100.0 * botHandledChats / totalChats, 2)
| project _time, botHandlingRatePct, botHandledChats, escalatedChats, totalChats
| order by _time asc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) || rows.length === 0) return { series: [] };
      // Guard: only process rows that have expected fields, prevent infinite placeholder rows
      const validRows = rows.filter(row => row._time !== undefined);
      if (validRows.length === 0) return { series: [] };
      return {
        series: validRows.map(row => ({
          date: row._time || null,
          botHandlingRatePct: row.botHandlingRatePct || 0,
          botHandledChats: row.botHandledChats || 0,
          escalatedChats: row.escalatedChats || 0,
          totalChats: row.totalChats || 0,
        })),
      };
    },
  },

  escalations_per_day_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize escalations = countif(routedTo == "human") by bin(_time, 1d)
| order by _time asc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) || rows.length === 0) return { series: [] };
      // Guard: only process rows that have expected fields, prevent infinite placeholder rows
      const validRows = rows.filter(row => row._time !== undefined);
      if (validRows.length === 0) return { series: [] };
      return {
        series: validRows.map(row => ({
          date: row._time || null,
          escalations: row.escalations || 0,
        })),
      };
    },
  },

  money_saved_per_day_v1: {
    defaultRangeDays: 30,
    queryText: `let costPerHumanChat = 3.0;
['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize
    totalChats = count(),
    escalatedChats = countif(routedTo == "human")
  by bin(_time, 1d)
| extend botHandledChats = totalChats - escalatedChats
| extend estimatedSaved = round(botHandledChats * costPerHumanChat, 2)
| extend estimatedSavedEUR = strcat("€", tostring(estimatedSaved))
| project _time, botHandledChats, escalatedChats, totalChats, estimatedSavedEUR
| order by _time asc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows)) return { series: [] };
      return {
        series: rows.map(row => {
          // Parse numeric value from estimatedSavedEUR string (format: "€123.45")
          let estimatedSaved = 0;
          if (row.estimatedSavedEUR && typeof row.estimatedSavedEUR === "string") {
            const match = row.estimatedSavedEUR.match(/[\d.]+/);
            if (match) {
              estimatedSaved = parseFloat(match[0]) || 0;
            }
          } else if (typeof row.estimatedSaved === "number") {
            estimatedSaved = row.estimatedSaved;
          }
          
          return {
            date: row._time || null,
            estimatedSaved: estimatedSaved,
            estimatedSavedEUR: row.estimatedSavedEUR || `€${estimatedSaved.toFixed(2)}`,
            botHandledChats: row.botHandledChats || 0,
            escalatedChats: row.escalatedChats || 0,
            totalChats: row.totalChats || 0,
          };
        }),
      };
    },
  },

  escalation_rate_pct_v1: {
    defaultRangeDays: 30,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"| summarize escalationPercentage = round(100.0 * countif(routedTo == "human") / count(), 2)`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows) | rows.length === 0) return { escalationPercentage: 0 };
      const row = rows[0];
      return { escalationPercentage: row.escalationPercentage || 0 };
    },
  },

  escalation_reasons_breakdown_v1: {
    defaultRangeDays: 90,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"
| where routedTo == "human"| summarize escalations = count() by escalateReason
| order by escalations desc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows)) return { breakdown: [] };
      return {
        breakdown: rows.map(row => ({
          reason: row.escalateReason || "Unknown",
          escalations: row.escalations || 0,
        })),
      };
    },
  },

  top_intents_v1: {
    defaultRangeDays: 90,
    queryText: `['DATASET_PLACEHOLDER']
| where clientId == "clientID"
| where event == "request_end"
| where route == "/chat"
| where isnotempty(['intent.mainIntent'])| summarize chats = count() by mainIntent = tostring(['intent.mainIntent'])
| top 10 by chats desc`,
    normalizeFn: (rows) => {
      if (!Array.isArray(rows)) return { intents: [] };
      return {
        intents: rows.map(row => ({
          intent: row.mainIntent || "Unknown",
          chats: row.chats || 0,
        })),
      };
    },
  },
};

// Date range validation
const MIN_RANGE_DAYS = 7;
const MAX_RANGE_DAYS = 90;

/**
 * Validate date range
 * @param {Date} startDate
 * @param {Date} endDate
 * @returns {object} { valid: boolean, error?: string }
 */
function validateDateRange(startDate, endDate) {
  if (!startDate | !endDate) {
    return { valid: false, error: "Start date and end date are required" };
  }

  if (!(startDate instanceof Date) | !(endDate instanceof Date)) {
    return { valid: false, error: "Invalid date format" };
  }

  if (isNaN(startDate.getTime()) | isNaN(endDate.getTime())) {
    return { valid: false, error: "Invalid date values" };
  }

  if (startDate >= endDate) {
    return { valid: false, error: "Start date must be before end date" };
  }

  const diffDays = Math.ceil((endDate - startDate) / (1000 * 60 * 60 * 24));
  
  if (diffDays < MIN_RANGE_DAYS) {
    return { valid: false, error: `Date range must be at least ${MIN_RANGE_DAYS} days` };
  }
  
  if (diffDays > MAX_RANGE_DAYS) {
    return { valid: false, error: `Date range must not exceed ${MAX_RANGE_DAYS} days` };
  }

  return { valid: true };
}

/**
 * Get default date range for a query
 * @param {string} queryName
 * @returns {object} { startDate: Date, endDate: Date }
 */
function getDefaultDateRange(queryName) {
  const definition = QUERY_DEFINITIONS[queryName];
  if (!definition) {
    // Default to 30 days
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    return { startDate, endDate };
  }

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - definition.defaultRangeDays);
  return { startDate, endDate };
}

/**
 * Execute an analytics query
 * @param {string} queryName - Key in QUERY_DEFINITIONS
 * @param {string} clientId - Client ID filter (server-side, never user-controlled)
 * @param {Date} startDate - Start date
 * @param {Date} endDate - End date
 * @returns {Promise<object>} Normalized result
 */
async function executeQuery(queryName, clientId, startDate, endDate) {
  const definition = QUERY_DEFINITIONS[queryName];
  if (!definition) {
    throw new Error(`Unknown query: ${queryName}`);
  }

  // Validate date range
  const validation = validateDateRange(startDate, endDate);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  // Format dates for Axiom API (ISO 8601 / RFC3339)
  const now = new Date();

  // TEMPORARY TEST: Use 1-hour time range to diagnose time filtering issue
  // TODO: Remove this after confirming time range is the issue
  const TEST_MODE = false;
  let startTime, endTime;

  if (TEST_MODE) {
    // Test with last 1 hour
    const threeHoursAgo = new Date(now.getTime() - 3 * 60 * 60 * 1000);
    startTime = threeHoursAgo.toISOString();
    endTime = now.toISOString();
  } else {
    // Original logic
    const effectiveEndDate = endDate > now ? now : endDate;
    startTime = startDate.toISOString();
    endTime = effectiveEndDate.toISOString();
  }

  // Diagnostic logging for time range debugging
  console.log("[clientAnalytics] Time range diagnostics:", {
    queryName,
    clientId,
    serverTimeNow: now.toISOString(),
    inputStartDate: startDate?.toISOString(),
    inputEndDate: endDate?.toISOString(),
    calculatedStartTime: startTime,
    calculatedEndTime: endTime,
    timeDiffMs: new Date(endTime) - new Date(startTime),
    timeDiffHours: ((new Date(endTime) - new Date(startTime)) / (1000 * 60 * 60)).toFixed(2),
    testModeEnabled: TEST_MODE,
  });

  // Get dataset from env var (defaults to "advantum-prod-log" in axiomClient)
  const dataset = process.env.AXIOM_DATASET || "advantum-prod-log";

  // Prepare query text with parameters injected
  // Dataset is referenced in APL using ['dataset-name'] syntax
  let queryText = definition.queryText;
  queryText = queryText.replace(/DATASET_PLACEHOLDER/g, dataset);
  queryText = queryText.replace(/"clientID"/g, `"${clientId}"`);
  queryText = queryText.replace(/"start_time"/g, `"${startTime}"`);
  queryText = queryText.replace(/"end_time"/g, `"${endTime}"`);

  console.log("[clientAnalytics] Executing query:", { queryName, dataset, startTime, endTime });

  // Execute query with dataset explicitly passed
  const rows = await runQuery({
    queryText,
    params: {
      client_filter: clientId,
      start_time: startTime,
      end_time: endTime,
      dataset: dataset,
    },
    dataset: dataset,
  });

  // Normalize results
  return definition.normalizeFn(rows);
}

module.exports = {
  QUERY_DEFINITIONS,
  validateDateRange,
  getDefaultDateRange,
  executeQuery,
  MIN_RANGE_DAYS,
  MAX_RANGE_DAYS,
};
