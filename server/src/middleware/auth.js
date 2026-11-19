const { statements } = require('../db');
const { verifyAccessToken } = require('../auth/tokens');

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || typeof authHeader !== 'string') {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const [scheme, token] = authHeader.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Invalid Authorization format, expected Bearer <token>' });
  }

  try {
    const payload = verifyAccessToken(token);
    const userId = Number(payload.sub);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(401).json({ error: 'Invalid token subject' });
    }

    const user = statements.findUserById.get(userId);
    if (!user || !user.is_active) {
      return res.status(401).json({ error: 'User is inactive or not found' });
    }

    req.user = { id: user.id, username: user.username };
    return next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Access token expired' });
    }
    return res.status(401).json({ error: 'Invalid access token' });
  }
}

module.exports = { requireAuth };