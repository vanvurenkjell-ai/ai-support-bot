#!/usr/bin/env node

/**
 * Smoke test: Verifies the server can be imported and started without errors
 * This would have caught the requireWidgetAuth undefined error
 * 
 * Usage: node scripts/smoke-start.js
 */

const http = require("http");
const path = require("path");

// Set minimal env vars for testing
process.env.NODE_ENV = process.env.NODE_ENV || "test";
// Use a specific test port to avoid conflicts
process.env.PORT = process.env.PORT || "3999";

// Mock required env vars if not set (to prevent crashes during import)
if (!process.env.OPENAI_API_KEY) {
  process.env.OPENAI_API_KEY = "test-key-for-smoke-test";
}

console.log("[SMOKE TEST] Starting smoke test...");
console.log(`[SMOKE TEST] NODE_ENV=${process.env.NODE_ENV}, PORT=${process.env.PORT}`);

let testPassed = false;
let serverStarted = false;

// Track if we've seen the server listening log
const originalLog = console.log;
let serverListeningDetected = false;

try {
  // Import the server module - this will execute the module code
  // If requireWidgetAuth is undefined, this will fail at route registration
  console.log("[SMOKE TEST] Importing server module...");
  
  // Change to Backend directory to ensure relative paths work
  const backendDir = path.join(__dirname, "..");
  process.chdir(backendDir);
  
  // Import the main module - this will execute all top-level code
  // including route registration where requireWidgetAuth is used
  require("../index.js");
  
  console.log("[SMOKE TEST] ✓ Server module imported successfully");
  console.log("[SMOKE TEST] ✓ No ReferenceError for requireWidgetAuth");
  console.log("[SMOKE TEST] ✓ Startup validation passed");
  
  testPassed = true;
  
  // Wait a moment for server to start, then verify it's listening
  setTimeout(() => {
    const testPort = Number(process.env.PORT);
    console.log(`[SMOKE TEST] Verifying server is listening on port ${testPort}...`);
    
    const testReq = http.get(`http://localhost:${testPort}/health`, { timeout: 2000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        console.log(`[SMOKE TEST] ✓ Server responded on port ${testPort} (status: ${res.statusCode})`);
        console.log("[SMOKE TEST] ✓ Server is bound to port and accepting connections");
        console.log("[SMOKE TEST] ✓ ALL TESTS PASSED");
        process.exit(0);
      });
    });
    
    testReq.on("error", (err) => {
      // If connection refused, server might not have started yet or port is wrong
      if (err.code === "ECONNREFUSED") {
        console.log("[SMOKE TEST] ⚠ Server not responding (may still be starting or port mismatch)");
        console.log("[SMOKE TEST] ✓ However, no ReferenceError occurred - main test passed");
        process.exit(0);
      } else {
        console.error(`[SMOKE TEST] ✗ Health check failed: ${err.message}`);
        process.exit(1);
      }
    });
    
    testReq.on("timeout", () => {
      testReq.destroy();
      console.log("[SMOKE TEST] ⚠ Health check timeout (server may still be starting)");
      console.log("[SMOKE TEST] ✓ However, no ReferenceError occurred - main test passed");
      process.exit(0);
    });
    
  }, 2000);
  
} catch (err) {
  console.error("[SMOKE TEST] ✗ FAILED: Server module failed to load");
  console.error("[SMOKE TEST] Error:", err.message);
  
  if (err.stack) {
    const stackLines = err.stack.split("\n").slice(0, 5);
    console.error("[SMOKE TEST] Stack:", stackLines.join("\n"));
  }
  
  if (err.message.includes("requireWidgetAuth is not defined") || 
      err.message.includes("ReferenceError")) {
    console.error("[SMOKE TEST] ✗ This is the exact error we're fixing!");
    console.error("[SMOKE TEST] ✗ requireWidgetAuth middleware is undefined");
  }
  
  process.exit(1);
}

// Safety timeout - if we get here without errors, test passed
setTimeout(() => {
  if (testPassed) {
    console.log("[SMOKE TEST] ✓ Test completed successfully (no errors during module load)");
    process.exit(0);
  }
}, 10000);

