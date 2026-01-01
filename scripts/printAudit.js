#!/usr/bin/env node
// Print audit log for a client config
// Usage: node scripts/printAudit.js <clientId> [limit]
//        node Backend/scripts/printAudit.js <clientId> [limit]

const path = require("path");
const { createClient } = require("@supabase/supabase-js");

// Resolve module paths - works from both repo root and Backend/ directory
const scriptDir = __dirname;
const backendRoot = scriptDir.endsWith("Backend") ? scriptDir : path.join(scriptDir, "..");

// Simple logging helper
function logEvent(level, event, fields) {
  try {
    const logObj = {
      timestamp: new Date().toISOString(),
      level: level || "info",
      event: event || "audit_print_log",
      ...(fields || {}),
    };
    console.log(JSON.stringify(logObj));
  } catch {
    console.log(String(fields));
  }
}

// Get Supabase client
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

// Count top-level keys that changed between before and after configs
function countChangedKeys(before, after) {
  if (!before || typeof before !== "object") before = {};
  if (!after || typeof after !== "object") after = {};

  const allKeys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const changed = [];

  for (const key of allKeys) {
    const beforeVal = before[key];
    const afterVal = after[key];
    
    // Compare JSON strings for deep equality
    const beforeStr = JSON.stringify(beforeVal);
    const afterStr = JSON.stringify(afterVal);
    
    if (beforeStr !== afterStr) {
      changed.push(key);
    }
  }

  return changed;
}

async function main() {
  const clientId = process.argv[2];
  const limit = parseInt(process.argv[3] || "10", 10);

  if (!clientId) {
    console.error("Usage: node scripts/printAudit.js <clientId> [limit]");
    console.error("       node Backend/scripts/printAudit.js <clientId> [limit]");
    process.exit(1);
  }

  const supabase = getSupabaseClient();
  if (!supabase) {
    console.error("Error: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set");
    process.exit(1);
  }

  try {
    console.log(`\nAudit log for client: ${clientId}\n`);
    console.log(`Limit: ${limit} most recent entries\n`);
    console.log("=".repeat(80));

    // Query audit log - fetch all and filter case-insensitively
    // (Supabase .eq() is case-sensitive, so we do case-insensitive match in memory)
    const { data: allEntries, error } = await supabase
      .from("client_config_audit")
      .select("id, client_id, actor_user_id, actor_email, actor_role, created_at, before_config, after_config")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("Error querying audit log:", error.message);
      process.exit(1);
    }

    if (!allEntries || allEntries.length === 0) {
      console.log("No audit entries found.\n");
      process.exit(0);
    }

    // Filter case-insensitively and limit
    const auditEntries = allEntries
      .filter(entry => entry.client_id && entry.client_id.toLowerCase() === clientId.toLowerCase())
      .slice(0, limit);

    if (error) {
      console.error("Error querying audit log:", error.message);
      process.exit(1);
    }

    if (!auditEntries || auditEntries.length === 0) {
      console.log("No audit entries found for this client.\n");
      process.exit(0);
    }

    console.log(`Found ${auditEntries.length} audit entries:\n`);

    auditEntries.forEach((entry, index) => {
      console.log(`Entry ${index + 1}:`);
      console.log(`  ID: ${entry.id}`);
      console.log(`  Created: ${entry.created_at}`);
      console.log(`  Actor: ${entry.actor_email || "N/A"} (${entry.actor_role || "N/A"})`);
      if (entry.actor_user_id) {
        console.log(`  Actor User ID: ${entry.actor_user_id}`);
      }

      // Count changed keys
      const changedKeys = countChangedKeys(entry.before_config, entry.after_config);
      console.log(`  Changed keys: ${changedKeys.length > 0 ? changedKeys.join(", ") : "none"}`);

      // Show schema version if present
      const beforeVersion = entry.before_config?.schemaVersion || null;
      const afterVersion = entry.after_config?.schemaVersion || null;
      if (beforeVersion || afterVersion) {
        console.log(`  Schema version: ${beforeVersion || "N/A"} → ${afterVersion || "N/A"}`);
      }

      // Show sample of top-level changes (no full configs to avoid data leakage)
      if (changedKeys.length > 0) {
        console.log(`  Sample changes:`);
        for (const key of changedKeys.slice(0, 5)) { // Show max 5 keys
          const beforeVal = entry.before_config?.[key];
          const afterVal = entry.after_config?.[key];
          
          // Show truncated preview
          const beforePreview = beforeVal !== undefined 
            ? (typeof beforeVal === "object" ? JSON.stringify(beforeVal).slice(0, 50) + "..." : String(beforeVal).slice(0, 50))
            : "null";
          const afterPreview = afterVal !== undefined
            ? (typeof afterVal === "object" ? JSON.stringify(afterVal).slice(0, 50) + "..." : String(afterVal).slice(0, 50))
            : "null";
          
          console.log(`    - ${key}: "${beforePreview}" → "${afterPreview}"`);
        }
        if (changedKeys.length > 5) {
          console.log(`    ... and ${changedKeys.length - 5} more`);
        }
      }

      console.log("");
    });

    console.log("=".repeat(80));
    console.log(`\n✅ Displayed ${auditEntries.length} audit entries\n`);

  } catch (error) {
    console.error("Error:", error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main();

