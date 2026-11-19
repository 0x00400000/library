const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');

const TEST_SECRET = '6CZkGexo+Sira2Rs5GhP7HJMntyVf/pkYKR80424dOU=';

function hashPasswordForSeed(passwordString) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.argon2(
      'argon2id',
      {
        message: passwordString,
        nonce: salt,
        parallelism: 4,
        passes: 3,
        memory: 2 ** 16,
        tagLength: 32,
      },
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve({
          hash: derivedKey.toString('hex'),
          salt: salt.toString('hex'),
        });
      }
    );
  });
}

function seedDatabase(dbPath, users) {
  const db = new DatabaseSync(dbPath);
  try {
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
    `);

    const insert = db.prepare(`
      INSERT INTO users (username, email, password_hash, password_salt, is_active)
      VALUES (?, ?, ?, ?, ?)
    `);

    for (const u of users) {
      insert.run(u.username, u.email, u.passwordHash, u.passwordSalt, u.isActive ?? 1);
    }
  } finally {
    db.close();
  }
}

function extractRefreshCookie(setCookieHeader) {
  if (!setCookieHeader) return null;
  const match = setCookieHeader.match(/(?:^|,\s*)refresh_token=([^;]+)/);
  return match ? match[1] : null;
}

async function startTestServer(dbPath, port = 18080 + Math.floor(Math.random() * 1000)) {
  const serverEntry = path.resolve(__dirname, '../src/server.js');
  const child = spawn(process.execPath, [serverEntry], {
    env: {
      ...process.env,
      NODE_ENV: 'test',
      PORT: String(port),
      TOKEN_SECRET: TEST_SECRET,
      DB_PATH: dbPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stderr = '';
  child.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
  });

  const baseUrl = `http://127.0.0.1:${port}`;

  // Ждём готовности сервера по /profile (ожидаем 401 как признак живого Express)
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`Server exited early with code ${child.exitCode}. stderr: ${stderr}`);
    }
    try {
      const res = await fetch(`${baseUrl}/profile`);
      if (res.status === 401 || res.status === 200) {
        return {
          baseUrl,
          stop: () =>
            new Promise((resolve) => {
              if (child.exitCode !== null) return resolve();
              child.once('exit', () => resolve());
              child.kill('SIGTERM');
            }),
        };
      }
    } catch {
      // Ещё не поднялся
    }
    await new Promise((r) => setTimeout(r, 50));
  }

  child.kill('SIGKILL');
  throw new Error(`Timed out waiting for server startup. stderr: ${stderr}`);
}

describe('Auth, refresh rotation, reuse detection, and requireAuth', () => {
  let tmpDir;
  let dbPath;
  let server;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-test-'));
    dbPath = path.join(tmpDir, 'test.db');

    const activeCreds = await hashPasswordForSeed('CorrectPass123!');
    const disabledCreds = await hashPasswordForSeed('DisabledPass123!');

    seedDatabase(dbPath, [
      {
        username: 'alice',
        email: 'alice@example.com',
        passwordHash: activeCreds.hash,
        passwordSalt: activeCreds.salt,
        isActive: 1,
      },
      {
        username: 'blocked',
        email: 'blocked@example.com',
        passwordHash: disabledCreds.hash,
        passwordSalt: disabledCreds.salt,
        isActive: 0,
      },
    ]);

    server = await startTestServer(dbPath);
  });

  afterEach(async () => {
    if (server) {
      await server.stop();
    }
    if (tmpDir && fs.existsSync(tmpDir)) {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('POST /login rejects invalid credentials, inactive user, and malformed payload', async () => {
    const badJson = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"username":',
    });
    assert.equal(badJson.status, 400);

    const wrongPass = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'WrongPassword!' }),
    });
    assert.equal(wrongPass.status, 401);

    const inactiveUser = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'blocked', password: 'DisabledPass123!' }),
    });
    assert.equal(inactiveUser.status, 401);
  });

  it('POST /login returns access_token and sets HttpOnly refresh_token cookie', async () => {
    const res = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'CorrectPass123!' }),
    });

    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(typeof body.access_token, 'string');
    assert.equal(body.token_type, 'Bearer');
    assert.ok(body.expires_in > 0);

    const setCookie = res.headers.get('set-cookie') || '';
    assert.match(setCookie, /refresh_token=[^;]+/);
    assert.match(setCookie, /HttpOnly/i);
    assert.match(setCookie, /SameSite=Strict/i);
  });

  it('GET /profile enforces requireAuth and accepts valid Bearer token', async () => {
    const noHeader = await fetch(`${server.baseUrl}/profile`);
    assert.equal(noHeader.status, 401);

    const badToken = await fetch(`${server.baseUrl}/profile`, {
      headers: { Authorization: 'Bearer invalid.jwt.token' },
    });
    assert.equal(badToken.status, 401);

    const loginRes = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'CorrectPass123!' }),
    });
    const { access_token: accessToken } = await loginRes.json();

    const okRes = await fetch(`${server.baseUrl}/profile`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    assert.equal(okRes.status, 200);
    const profileBody = await okRes.json();
    assert.equal(profileBody.user.username, 'alice');
    assert.equal(typeof profileBody.user.id, 'number');
  });

  it('POST /auth/refresh rotates refresh_token and revokes entire family on reuse', async () => {
    const loginRes = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'CorrectPass123!' }),
    });
    assert.equal(loginRes.status, 200);

    const firstRefreshCookie = extractRefreshCookie(loginRes.headers.get('set-cookie'));
    assert.ok(firstRefreshCookie, 'Expected initial refresh_token cookie');

    const refresh1Res = await fetch(`${server.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refresh_token=${firstRefreshCookie}` },
    });
    assert.equal(refresh1Res.status, 200);
    const refresh1Body = await refresh1Res.json();
    assert.equal(typeof refresh1Body.access_token, 'string');

    const secondRefreshCookie = extractRefreshCookie(refresh1Res.headers.get('set-cookie'));
    assert.ok(secondRefreshCookie, 'Expected rotated refresh_token cookie');
    assert.notEqual(secondRefreshCookie, firstRefreshCookie);

    const reuseRes = await fetch(`${server.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refresh_token=${firstRefreshCookie}` },
    });
    assert.equal(reuseRes.status, 401);

    const freshAfterReuseRes = await fetch(`${server.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refresh_token=${secondRefreshCookie}` },
    });
    assert.equal(freshAfterReuseRes.status, 401);
  });

  it('POST /auth/logout revokes refresh_token so it cannot be refreshed afterward', async () => {
    const loginRes = await fetch(`${server.baseUrl}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'CorrectPass123!' }),
    });
    const refreshCookie = extractRefreshCookie(loginRes.headers.get('set-cookie'));
    assert.ok(refreshCookie);

    const logoutRes = await fetch(`${server.baseUrl}/auth/logout`, {
      method: 'POST',
      headers: { Cookie: `refresh_token=${refreshCookie}` },
    });
    assert.equal(logoutRes.status, 200);

    const refreshAfterLogout = await fetch(`${server.baseUrl}/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: `refresh_token=${refreshCookie}` },
    });
    assert.equal(refreshAfterLogout.status, 401);
  });
});