const { run } = require('../lib/supabase-api.cjs');
module.exports = (req, res) => run(req, res, '/avatar');
