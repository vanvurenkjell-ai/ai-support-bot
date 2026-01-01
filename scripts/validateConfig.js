#!/usr/bin/env node
// Simple script to validate a client config
// Usage: node scripts/validateConfig.js <clientId>
//        node Backend/scripts/validateConfig.js <clientId>

const path = require("path");

// Resolve module paths - works from both repo root and Backend/ directory
const scriptDir = __dirname;
const backendRoot = scriptDir.endsWith("Backend") ? scriptDir : path.join(scriptDir, "..");

const { normalizeConfig, validateConfig, getDefaultConfig } = require(path.join(backendRoot, "lib", "clientConfigSchema"));
const clientsStore = require(path.join(backendRoot, "lib", "clientsStoreAdapter"));

async function main() {
  const clientId = process.argv[2];

  if (!clientId) {
    console.error("Usage: node scripts/validateConfig.js <clientId>");
    console.error("       node Backend/scripts/validateConfig.js <clientId>");
    process.exit(1);
  }

  try {
    console.log(`\nValidating config for client: ${clientId}\n`);
    console.log(`Store type: ${clientsStore.storeType}\n`);

    // Read config from store (uses case-insensitive lookup, returns defaults if not found)
    let config = null;
    let lookupInfo = { method: "unknown", found: false };
    
    try {
      config = await clientsStore.readClientConfig(clientId);
      
      // Check if we got defaults (config exists but might be using defaults due to validation failure)
      // We can't easily detect this, but we'll show what we got
      lookupInfo.found = config !== null;
      lookupInfo.method = "readClientConfig";
    } catch (readError) {
      console.log("⚠️  Error reading config:", readError.message);
      lookupInfo.found = false;
    }

    if (!config) {
      console.log("❌ Config not found in storage");
      console.log("\nLookup attempts:");
      console.log(`  - Exact match: ${clientId}`);
      console.log(`  - Case-insensitive: attempted`);
      console.log("\nUsing default config:");
      config = getDefaultConfig(clientId);
      console.log(JSON.stringify(config, null, 2));
      console.log("\n⚠️  This is a default config - no client-specific config was found.");
      process.exit(1);
    }

    console.log("Config from storage (after normalization):");
    console.log(JSON.stringify(config, null, 2));
    console.log("\n" + "=".repeat(60) + "\n");

    // Validate (config is already normalized, but validate again)
    const validation = validateConfig(config, { clientId, logEvents: false });

    if (!validation.ok) {
      console.log("❌ Validation failed:");
      validation.errors.forEach(err => {
        console.log(`  - ${err.path}: ${err.message}`);
      });
      console.log("\n⚠️  Config was normalized but validation still failed.");
      console.log("This should not happen - config should always be valid after normalization.");
      process.exit(1);
    }

    console.log("✅ Validation passed\n");

    console.log("Normalized config (final):");
    console.log(JSON.stringify(validation.value, null, 2));
    console.log("\n" + "=".repeat(60) + "\n");

    console.log(`Schema version: ${validation.value.schemaVersion || "not set"}`);
    console.log(`Store type: ${clientsStore.storeType}`);
    console.log(`Lookup method: ${lookupInfo.method}`);
    console.log("\n✅ Config is valid and normalized\n");

  } catch (error) {
    console.error("Error:", error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }
}

main();

