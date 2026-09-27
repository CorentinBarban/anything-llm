const { reqBody } = require("../http");

const WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX_FAILURES = 10;
const failures = new Map();

function maxFailures() {
  const max = Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS);
  return Number.isFinite(max) && max > 0 ? max : DEFAULT_MAX_FAILURES;
}

function attemptKey(request) {
  let username = "";
  try {
    username = String(reqBody(request)?.username || "").toLowerCase();
  } catch {}
  return `${request.ip || "unknown"}:${username}`;
}

function activeFailures(key, now = Date.now()) {
  const entry = failures.get(key);
  if (!entry) return 0;
  if (now - entry.firstFailureAt > WINDOW_MS) {
    failures.delete(key);
    return 0;
  }
  return entry.count;
}

function pruneExpired(now = Date.now()) {
  for (const [key, entry] of failures)
    if (now - entry.firstFailureAt > WINDOW_MS) failures.delete(key);
}

function recordFailure(key, now = Date.now()) {
  if (failures.size > 10_000) pruneExpired(now);
  const count = activeFailures(key, now);
  failures.set(key, {
    count: count + 1,
    firstFailureAt: count === 0 ? now : failures.get(key).firstFailureAt,
  });
}

/**
 * Limits failed login attempts per IP + username. Without this, brute forcing
 * through AnythingLLM could lock out directory (AD) accounts.
 * Only failed attempts (valid: false, non-5xx) are counted, a successful login resets the counter.
 * @param {import("express").Request} request
 * @param {import("express").Response} response
 * @param {import("express").NextFunction} next
 */
function loginRateLimit(request, response, next) {
  const key = attemptKey(request);
  if (activeFailures(key) >= maxFailures()) {
    response.status(429).json({
      user: null,
      valid: false,
      token: null,
      message: "[010] Too many failed login attempts. Try again later.",
    });
    return;
  }

  const json = response.json.bind(response);
  response.json = (body) => {
    if (body?.valid === true) failures.delete(key);
    else if (body?.valid === false && response.statusCode < 500)
      recordFailure(key);
    return json(body);
  };
  next();
}

module.exports = {
  loginRateLimit,
  _resetLoginRateLimit: () => failures.clear(),
};
