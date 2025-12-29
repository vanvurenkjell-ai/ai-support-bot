const crypto = require("crypto");

// CSRF token generation
function generateCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Store CSRF token in session
function setCsrfToken(req, token) {
  if (!req.session) {
    req.session = {};
  }
  req.session.csrfToken = token;
}

// Get CSRF token from session
function getCsrfToken(req) {
  return req.session?.csrfToken || null;
}

// Verify CSRF token (double-submit cookie pattern)
// Token should be in both session and request body/cookie
function verifyCsrfToken(req, tokenFromRequest) {
  const sessionToken = getCsrfToken(req);
  if (!sessionToken || !tokenFromRequest) {
    return false;
  }
  // Constant-time comparison to prevent timing attacks
  return constantTimeCompare(sessionToken, tokenFromRequest);
}

// Constant-time string comparison
function constantTimeCompare(a, b) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// CSRF protection middleware for state-changing requests only
// GET, HEAD, and OPTIONS are safe methods and bypass CSRF validation
function requireCsrf(req, res, next) {
  // Skip CSRF validation for safe/read-only HTTP methods
  const safeMethods = ["GET", "HEAD", "OPTIONS"];
  if (safeMethods.includes(req.method)) {
    return next();
  }

  // Require CSRF token for state-changing methods (POST, PUT, DELETE, PATCH, etc.)
  const tokenFromRequest = req.body?.csrfToken || req.headers["x-csrf-token"];
  const sessionToken = getCsrfToken(req);

  if (!sessionToken || !verifyCsrfToken(req, tokenFromRequest)) {
    return res.status(403).json({
      error: "Forbidden",
      message: "Invalid CSRF token",
    });
  }

  next();
}

module.exports = {
  generateCsrfToken,
  setCsrfToken,
  getCsrfToken,
  verifyCsrfToken,
  requireCsrf,
};

