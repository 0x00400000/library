const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const config = require('../config');
const { statements, runInTransaction } = require('../db');
const { hashRefreshToken, generateRawRefreshToken } = require('./crypto');

function generateAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id), name: user.username },
    config.tokenSecret,
    {
      algorithm: config.auth.jwt.algorithm,
      expiresIn: config.auth.accessTtlSec,
      issuer: config.auth.jwt.issuer,
      audience: config.auth.jwt.audience,
    }
  );
}

function verifyAccessToken(token) {
  return jwt.verify(token, config.tokenSecret, {
    algorithms: config.auth.jwt.algorithms,
    issuer: config.auth.jwt.issuer,
    audience: config.auth.jwt.audience,
  });
}

function issueRefreshToken(userId, familyId = crypto.randomUUID()) {
  const rawToken = generateRawRefreshToken();
  const tokenHash = hashRefreshToken(rawToken);
  const expiresAtMs = Date.now() + config.auth.refreshTtlMs;
  const expiresAtIso = new Date(expiresAtMs).toISOString();

  statements.insertRefreshToken.run(userId, familyId, tokenHash, expiresAtIso);

  return {
    rawToken,
    tokenHash,
    familyId,
    expiresAtMs,
  };
}

function rotateRefreshToken(rawRefreshToken) {
  const tokenHash = hashRefreshToken(rawRefreshToken);

  return runInTransaction(() => {
    const record = statements.findRefreshToken.get(tokenHash);

    if (!record) {
      return { ok: false, reason: 'not_found' };
    }

    if (record.used_at || record.revoked_at) {
      statements.revokeFamily.run(record.family_id);
      return { ok: false, reason: 'reuse_detected' };
    }

    const expiresAtMs = Date.parse(record.expires_at);
    if (!Number.isFinite(expiresAtMs) || Date.now() >= expiresAtMs) {
      statements.revokeFamily.run(record.family_id);
      return { ok: false, reason: 'expired' };
    }

    const user = statements.findUserById.get(record.user_id);
    if (!user || !user.is_active) {
      statements.revokeFamily.run(record.family_id);
      return { ok: false, reason: 'user_inactive' };
    }

    const nextRefresh = issueRefreshToken(user.id, record.family_id);
    const updated = statements.markRefreshTokenUsed.run(nextRefresh.tokenHash, record.id);

    if (updated.changes !== 1) {
      throw new Error('Refresh token rotation race conflict');
    }

    return {
      ok: true,
      user: { id: user.id, username: user.username },
      nextRefresh,
    };
  });
}

function revokeRefreshToken(rawRefreshToken) {
  if (!rawRefreshToken || typeof rawRefreshToken !== 'string') return;
  statements.revokeTokenByHash.run(hashRefreshToken(rawRefreshToken));
}

function setRefreshCookie(res, rawToken, expiresAtMs) {
  res.cookie(config.auth.refreshCookieName, rawToken, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: 'strict',
    path: config.auth.refreshCookiePath,
    expires: new Date(expiresAtMs),
  });
}

function clearRefreshCookie(res) {
  res.clearCookie(config.auth.refreshCookieName, {
    httpOnly: true,
    secure: config.isProd,
    sameSite: 'strict',
    path: config.auth.refreshCookiePath,
  });
}

function parseCookies(cookieHeader) {
  if (!cookieHeader || typeof cookieHeader !== 'string') return {};
  const result = {};
  for (const part of cookieHeader.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (key) {
      try {
        result[key] = decodeURIComponent(val);
      } catch {
        result[key] = val;
      }
    }
  }
  return result;
}

module.exports = {
  generateAccessToken,
  verifyAccessToken,
  issueRefreshToken,
  rotateRefreshToken,
  revokeRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  parseCookies,
};