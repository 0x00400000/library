const express = require('express');
const config = require('../config');
const { login } = require('../auth/service');
const {
  generateAccessToken,
  rotateRefreshToken,
  revokeRefreshToken,
  setRefreshCookie,
  clearRefreshCookie,
  parseCookies,
} = require('../auth/tokens');
const { createLoginRateLimit } = require('../middleware/rateLimit');

const router = express.Router();
const loginRateLimit = createLoginRateLimit();

router.post('/login', loginRateLimit, async (req, res) => {
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

    if (
      username.length > config.limits.maxUsernameLen ||
      password.length > config.limits.maxPasswordLen
    ) {
      return res.status(400).json({ error: 'Username or password exceeds maximum length' });
    }

    const session = await login(username, password);
    if (!session) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    setRefreshCookie(res, session.refresh.rawToken, session.refresh.expiresAtMs);

    return res.status(200).json({
      access_token: session.accessToken,
      token_type: 'Bearer',
      expires_in: config.auth.accessTtlSec,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/auth/refresh', (req, res) => {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const rawRefresh = cookies[config.auth.refreshCookieName];

    if (!rawRefresh || typeof rawRefresh !== 'string') {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Missing refresh token' });
    }

    const rotated = rotateRefreshToken(rawRefresh);
    if (!rotated.ok) {
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }

    const accessToken = generateAccessToken(rotated.user);
    setRefreshCookie(res, rotated.nextRefresh.rawToken, rotated.nextRefresh.expiresAtMs);

    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.auth.accessTtlSec,
    });
  } catch (err) {
    console.error('Refresh error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/auth/logout', (req, res) => {
  try {
    const cookies = parseCookies(req.headers.cookie);
    const rawRefresh = cookies[config.auth.refreshCookieName];

    revokeRefreshToken(rawRefresh);
    clearRefreshCookie(res);

    return res.status(200).json({ status: 'logged_out' });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;