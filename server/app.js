require('dotenv').config();

const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');

const port = process.env.PORT
const tokenSecret = process.env.tokenSecret

const app = express()
const db = new DatabaseSync('app.db');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`)

/*
db.exec(`
INSERT INTO users (username, email, password_hash, password_salt)
VALUES ('', '', '', '');
`)
*/

function hashPassword(passwordString, existingSaltBuffer = null) {
  return new Promise((resolve, reject) => {
    const salt = existingSaltBuffer || crypto.randomBytes(16);

    crypto.argon2('argon2id', {
      message: passwordString,
      nonce: salt,
      parallelism: 4,
      passes: 3,
      memory: 2 ** 16,
      tagLength: 32
    }, (err, derivedKey) => {
      if (err) return reject(err);
      resolve({
        hashBuffer: derivedKey,
        hash: derivedKey.toString('hex'),
        salt: salt.toString('hex')
      });
    });
  });
}

const findUserStmt = db.prepare(`
  SELECT id, username, password_hash, password_salt, is_active
  FROM users
  WHERE username = ?
`);

async function validateUser(username, password) {
  const user = findUserStmt.get(username);

  if (!user || !user.is_active) {
    return null;
  }

  const storedSaltBuffer = Buffer.from(user.password_salt, 'hex');
  const storedHashBuffer = Buffer.from(user.password_hash, 'hex');
  
  const { hashBuffer } = await hashPassword(password, storedSaltBuffer);

  if (
    hashBuffer.length !== storedHashBuffer.length ||
    !crypto.timingSafeEqual(hashBuffer, storedHashBuffer)
  ) {
    return null;
  }

  return { id: user.id, username: user.username };
}

function generateToken(user) {
  return jwt.sign(
    { sub: user.id, name: user.username },
    tokenSecret,
    { algorithm: 'HS256', expiresIn: '15m' }
  );
}

app.use(express.json())

app.get('/', (req, res) => {
  res.send('Hello World!')
})


app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Please specify username and password' });
    }

    const validUser = await validateUser(username, password);
    if (!validUser) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = generateToken(validUser);
    return res.status(200).json({ token });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Library server is listening on ${port}`);
});
