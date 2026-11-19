const config = require('../config');

const attempts = new Map();

function createLoginRateLimit() {
  const timer = setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of attempts.entries()) {
      if (now > record.resetAt) {
        attempts.delete(ip);
      }
    }
  }, config.rateLimit.cleanupIntervalMs);

  timer.unref();

  return function loginRateLimit(req, res, next) {
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    const record = attempts.get(ip);

    if (!record || now > record.resetAt) {
      attempts.set(ip, { count: 1, resetAt: now + config.rateLimit.windowMs });
      return next();
    }

    if (record.count >= config.rateLimit.maxAttempts) {
      const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);
      res.set('Retry-After', String(retryAfterSec));
      return res.status(429).json({ error: 'Too many login attempts, try again later' });
    }

    record.count += 1;
    return next();
  };
}

module.exports = { createLoginRateLimit };