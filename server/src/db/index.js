const { DatabaseSync } = require('node:sqlite');
const config = require('../config');

const db = new DatabaseSync(config.dbPath);

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

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TEXT,
    revoked_at TEXT,
    replaced_by TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family_id ON refresh_tokens(family_id);
`);

const statements = {
  findUserByUsername: db.prepare(`
    SELECT id, username, password_hash, password_salt, is_active
    FROM users
    WHERE username = ?
  `),
  findUserById: db.prepare(`
    SELECT id, username, is_active
    FROM users
    WHERE id = ?
  `),
  insertRefreshToken: db.prepare(`
    INSERT INTO refresh_tokens (user_id, family_id, token_hash, expires_at)
    VALUES (?, ?, ?, ?)
  `),
  findRefreshToken: db.prepare(`
    SELECT id, user_id, family_id, token_hash, expires_at, used_at, revoked_at
    FROM refresh_tokens
    WHERE token_hash = ?
  `),
  markRefreshTokenUsed: db.prepare(`
    UPDATE refresh_tokens
    SET used_at = CURRENT_TIMESTAMP, replaced_by = ?
    WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL
  `),
  revokeFamily: db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = CURRENT_TIMESTAMP
    WHERE family_id = ? AND revoked_at IS NULL
  `),
  revokeTokenByHash: db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = CURRENT_TIMESTAMP
    WHERE token_hash = ? AND revoked_at IS NULL
  `),
};

function runInTransaction(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {}
    throw err;
  }
}

module.exports = {
  db,
  statements,
  runInTransaction,
};