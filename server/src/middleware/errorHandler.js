function jsonSyntaxErrorHandler(err, req, res, next) {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Malformed JSON' });
  }
  return next(err);
}

function notFoundHandler(req, res) {
  return res.status(404).json({ error: 'Not found' });
}

module.exports = {
  jsonSyntaxErrorHandler,
  notFoundHandler,
};