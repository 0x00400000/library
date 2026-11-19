const crypto = require('node:crypto');
const config = require('../config');

function hashPassword(passwordString, existingSaltBuffer = null) {
  return new Promise((resolve, reject) => {
    const salt = existingSaltBuffer || crypto.randomBytes(16);

    crypto.argon2(
      'argon2id',
      {
        message: passwordString,
        nonce: salt,
        ...config.argon2,
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

function hashRefreshToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

function generateRawRefreshToken() {
  return crypto.randomBytes(48).toString('base64url');
}

module.exports = {
  hashPassword,
  hashRefreshToken,
  generateRawRefreshToken,
};