require('dotenv').config();

const express = require('express');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');

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

function stringToArgon(passwordString) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);

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
        hash: derivedKey.toString('hex'),
        salt: salt.toString('hex')
      });
    });
  });
}


function validateUser(username, password) {

}

function generateToken(data) {
  /*
  {
    sub: "1234567890",
    name: "John Doe", 
    admin: false, 
    "iat": 1516239022, 
    "exp": 1716666000 
  }
    */
  jwt.sign({
    data: data
  }, tokenSecret, { expiresIn: '1h' });
}

app.use(express.json())

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.post('/login', (req, res) => {
  const requestBody = req.body;
  const {username, password} = requestBody || {}
  if (!username || !password) {
    return res.statusCode(400).json({error: 'Please specify username and password'});
  }
  return res.status(200).json()
})

app.post('/refresh', (req, res) => {
  const requestBody = req.body;
  const {username, password} = requestBody || {}
  if (!username || !password) {
    return res.statusCode(400).json({error: 'Please specify username and password'});
  }
  return res.status(200).json()
})

app.listen(port, () => {
  console.log(`Library server is listening on ${port}`)
})