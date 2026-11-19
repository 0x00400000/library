require('dotenv').config();

const port = Number(process.env.PORT) || 3000;
const tokenSecret = process.env.TOKEN_SECRET || process.env.tokenSecret;
const isProd = process.env.NODE_ENV === 'production';
const dbPath = process.env.DB_PATH || 'app.db';

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  throw new Error('Invalid PORT in environment variables');
}

if (!tokenSecret || tokenSecret.length < 32) {
  throw new Error('Missing or weak TOKEN_SECRET (use at least 32 random characters)');
}

module.exports = {
  port,
  tokenSecret,
  isProd,
  dbPath,
  argon2: {
    parallelism: 4,
    passes: 3,
    memory: 2 ** 16,
    tagLength: 32,
  },
  limits: {
    maxUsernameLen: 64,
    maxPasswordLen: 128,
    jsonBodyLimit: '16kb',
  },
  auth: {
    accessTtlSec: 15 * 60, // 15 min
    refreshTtlMs: 30 * 24 * 60 * 60 * 1000, // 30 d
    refreshCookieName: 'refresh_token',
    refreshCookiePath: '/auth',
    jwt: {
      algorithm: 'HS256',
      algorithms: ['HS256'],
      issuer: 'library-api',
      audience: 'library-client',
    },
  },
  rateLimit: {
    windowMs: 15 * 60 * 1000,
    maxAttempts: 10,
    cleanupIntervalMs: 60 * 1000,
  },
};