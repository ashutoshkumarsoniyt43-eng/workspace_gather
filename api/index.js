const { run } = require('../lib/supabase-api.cjs');

module.exports = (req, res) => {
  const requestUrl = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  const route = requestUrl.searchParams.get('route') || '';
  return run(req, res, `/${route}`);
};
