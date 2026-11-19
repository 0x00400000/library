const crypto = require('node:crypto');
const config = require('../config');
const { statements } = require('../db');
const { hashPassword } = require('./crypto');
const { generateAccessToken, issueRefreshToken } = require('./tokens');

const DUMMY_SALT = crypto.randomBytes(16);
const DUMMY_HASH = crypto.randomBytes(config.argon2.tagLength);

async function validateUser(username, password) {
  const user = statements.findUserByUsername.get(username);

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

async function login(username, password) {
  const validUser = await validateUser(username, password);
  if (!validUser) {
    return null;
  }

  const accessToken = generateAccessToken(validUser);
  const refresh = issueRefreshToken(validUser.id);

  return {
    user: validUser,
    accessToken,
    refresh,
  };
}

module.exports = {
  validateUser,
  login,
};