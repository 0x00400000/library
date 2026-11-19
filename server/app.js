require('dotenv').config();

const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const port = Number(process.env.PORT) || 3000;
const tokenSecret = process.env.TOKEN_SECRET || process.env.tokenSecret;

if (!Number.isInteger(port) || port <= 0 || port > 65535) {
  throw new Error('Invalid PORT in environment variables');
}

if (!tokenSecret || tokenSecret.length < 32) {
  throw new Error('Missing or weak TOKEN_SECRET (use at least 32 random characters)');
}

const ARGON2_PARAMS = {
  parallelism: 4,
  passes: 3,
  memory: 2 ** 16,
  tagLength: 32,
};

const MAX_USERNAME_LEN = 64;
const MAX_PASSWORD_LEN = 128;

const app = express();
app.disable('x-powered-by');

const db = new DatabaseSync('app.db');
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA busy_timeout = 5000;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);


const loginAttempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_ATTEMPTS = 10;

function loginRateLimit(req, res, next) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  const record = loginAttempts.get(ip);

  if (!record || now > record.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
    return next();
  }

  if (record.count >= MAX_ATTEMPTS) {
    const retryAfterSec = Math.ceil((record.resetAt - now) / 1000);
    res.set('Retry-After', String(retryAfterSec));
    return res.status(429).json({ error: 'Too many login attempts, try again later' });
  }

  record.count += 1;
  return next();
}


setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of loginAttempts.entries()) {
    if (now > record.resetAt) {
      loginAttempts.delete(ip);
    }
  }
}, 60 * 1000).unref();

function hashPassword(passwordString, existingSaltBuffer = null) {
  return new Promise((resolve, reject) => {
    const salt = existingSaltBuffer || crypto.randomBytes(16);

    crypto.argon2(
      'argon2id',
      {
        message: passwordString,
        nonce: salt,
        ...ARGON2_PARAMS,
      },
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve({
          hashBuffer: derivedKey,
          hash: derivedKey.toString('hex'),
          salt: salt.toString('hex'),
        });
      }
    );
  });
}

const findUserStmt = db.prepare(`
  SELECT id, username, password_hash, password_salt, is_active
  FROM users
  WHERE username = ?
`);


const DUMMY_SALT = crypto.randomBytes(16);
const DUMMY_HASH = crypto.randomBytes(ARGON2_PARAMS.tagLength);

async function validateUser(username, password) {
  const user = findUserStmt.get(username);

  if (!user) {
    await hashPassword(password, DUMMY_SALT).catch(() => {});
    crypto.timingSafeEqual(DUMMY_HASH, DUMMY_HASH);
    return null;
  }

  const storedSaltBuffer = Buffer.from(user.password_salt, 'hex');
  const storedHashBuffer = Buffer.from(user.password_hash, 'hex');

  const { hashBuffer } = await hashPassword(password, storedSaltBuffer);

  const hashMatches =
    hashBuffer.length === storedHashBuffer.length &&
    crypto.timingSafeEqual(hashBuffer, storedHashBuffer);

  if (!user.is_active || !hashMatches) {
    return null;
  }

  return { id: user.id, username: user.username };
}

function generateToken(user) {
  return jwt.sign(
    { sub: String(user.id), name: user.username },
    tokenSecret,
    {
      algorithm: 'HS256',
      expiresIn: '1h',
      issuer: 'library-api',
      audience: 'library-client',
    }
  );
}

app.use(express.json({ limit: '16kb' }));

app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('Cache-Control', 'no-store');
  next();
});

app.get('/', (req, res) => {
  return res.status(404).json({ error: 'Not found' });
});

app.post('/login', loginRateLimit, async (req, res) => {
  try {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request body' });
    }

    const { username, password } = body;

    if (
      typeof username !== 'string' ||
      typeof password !== 'string' ||
      username.length === 0 ||
      password.length === 0
    ) {
      return res.status(400).json({ error: 'Please specify valid username and password' });
    }

    if (username.length > MAX_USERNAME_LEN || password.length > MAX_PASSWORD_LEN) {
      return res.status(400).json({ error: 'Username or password exceeds maximum length' });
    }

    const validUser = await validateUser(username, password);
    if (!validUser) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = generateToken(validUser);
    return res.status(200).json({
      access_token: token,
      token_type: 'Bearer',
      expires_in: 3600,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});


app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON' });
  }
  return next(err);
});

app.use((req, res) => {
  return res.status(404).json({ error: 'Not found' });
});

const server = app.listen(port, () => {
  console.log(`Library server is listening on ${port}`);
});

function shutdown(signal) {
  console.log(`Received ${signal}, closing server...`);
  server.close(() => {
    try {
      db.close();
    } catch (err) {
      console.error('DB close error:', err);
    }
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));