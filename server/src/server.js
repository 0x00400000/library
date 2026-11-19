const express = require('express');
const config = require('./config');
const { db } = require('./db');
const { securityHeaders } = require('./middleware/security');
const { jsonSyntaxErrorHandler, notFoundHandler } = require('./middleware/errorHandler');
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');

const app = express();
app.disable('x-powered-by');
// app.set('trust proxy', 1);

app.use(express.json({ limit: config.limits.jsonBodyLimit }));
app.use(securityHeaders);

app.use(authRoutes);
app.use(userRoutes);

app.use(jsonSyntaxErrorHandler);
app.use(notFoundHandler);

const server = app.listen(config.port, () => {
  console.log(`Library server is listening on ${config.port}`);
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