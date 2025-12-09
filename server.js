
/**
 * server.js (SQLite edition)
 * Same API and behavior as before, but uses SQLite (database.sqlite) so you don't need MySQL credentials.
 *
 * Env variables used:
 *  - API_TOKEN (required for /api/*)
 *  - APP_SECRET (required for admin JWTs)
 *  - GOOGLE_API_KEY, GOOGLE_CX (optional for /api/search)
 *  - BLOCKLIST_URLS (optional)
 *  - PORT (optional)
 *
 * Note: SQLite file is stored in the service filesystem (database.sqlite). On Render this file can be lost on redeploy.
 */

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const fetch = require('node-fetch');
const rateLimit = require('express-rate-limit');
const { Sequelize, DataTypes, Op } = require('sequelize');
const multer = require('multer');
const csvParse = require('csv-parse/lib/sync');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cheerio = require('cheerio');
const { Blocker, ABPFilterParser } = require('@cliqz/adblocker');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(helmet());
app.use(cookieParser());

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.APP_SECRET || 'change-this-secret';
const JWT_EXP = '8h';
const SALT_ROUNDS = 12;
const BLOCKLIST_PATH = path.join(__dirname, 'blocklists.txt');
const UPLOAD_DIR = path.join(__dirname, 'tmp');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB

// --- Use SQLite via Sequelize
const SQLITE_FILE = path.join(__dirname, 'database.sqlite');
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: SQLITE_FILE,
  logging: false
});

// Models (same names/fields as previous)
const Admin = sequelize.define('Admin', {
  username: { type: DataTypes.STRING, unique: true, allowNull: false, defaultValue: 'admin' },
  password_hash: { type: DataTypes.STRING, allowNull: false },
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  last_login: DataTypes.DATE
}, { tableName: 'admins', timestamps: false });

const BlockedDomain = sequelize.define('BlockedDomain', {
  domain: { type: DataTypes.STRING(255), unique: true, allowNull: false },
  source: DataTypes.STRING(255),
  is_enabled: { type: DataTypes.BOOLEAN, defaultValue: true },
  added_by: DataTypes.STRING(100),
  added_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, { tableName: 'blocked_domains', timestamps: false });

const History = sequelize.define('History', {
  userId: { type: DataTypes.BIGINT, allowNull: true },
  url: { type: DataTypes.TEXT, allowNull: false },
  title: DataTypes.STRING(1024),
  snippet: DataTypes.TEXT,
  visitedAt: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
  isIncognito: { type: DataTypes.BOOLEAN, defaultValue: false },
  ip_addr: DataTypes.STRING(45)
}, { tableName: 'history', timestamps: false });

const AdminAudit = sequelize.define('AdminAudit', {
  admin_user: DataTypes.STRING(100),
  action: DataTypes.STRING(255),
  detail: DataTypes.TEXT,
  ip: DataTypes.STRING(45),
  created_at: { type: DataTypes.DATE, defaultValue: DataTypes.NOW }
}, { tableName: 'admin_audit', timestamps: false });

// Initialize DB (create file if missing)
(async () => {
  try {
    await sequelize.authenticate();
    await Admin.sync();
    await BlockedDomain.sync();
    await History.sync();
    await AdminAudit.sync();
    console.log('[DB] SQLite connected & synced at', SQLITE_FILE);
  } catch (e) {
    console.error('DB init error', e);
    process.exit(1);
  }
})();

// Rate limiter
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

// Blocker in-memory
let blocker = null;
function loadBlocklistsFromFile() {
  try {
    if (!fs.existsSync(BLOCKLIST_PATH)) {
      blocker = null;
      console.warn('[Blocker] no blocklist file found');
      return;
    }
    const txt = fs.readFileSync(BLOCKLIST_PATH, 'utf8');
    const lines = txt.split(/\r?\n/).filter(Boolean);
    const parser = new ABPFilterParser({ hideFilters: true });
    parser.add(lines.join('\n'));
    blocker = new Blocker(parser);
    console.log('[Blocker] loaded with rules:', lines.length);
  } catch (e) {
    console.error('[Blocker] load failed', e);
    blocker = null;
  }
}
loadBlocklistsFromFile();

// Utility normalize host
function normalizeHost(input) {
  if (!input || typeof input !== 'string') return null;
  try {
    let h = input.trim();
    if (h.startsWith('http://') || h.startsWith('https://')) h = new URL(h).hostname;
    h = h.replace(/^www\./, '').toLowerCase();
    if (!/^[a-z0-9\.\-]{1,255}$/.test(h)) return null;
    return h;
  } catch (e) { return null; }
}

// Check blocked by DB or ABP engine
async function isBlockedUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.replace(/^www\./, '').toLowerCase();
    const dbMatch = await BlockedDomain.findOne({ where: { domain: host, is_enabled: true } });
    if (dbMatch) return true;
    if (!blocker) return false;
    return blocker.matches(u.href, { elementType: 'other' });
  } catch (e) {
    return false;
  }
}

// Admin helpers
function signAdminJwt(admin) {
  return jwt.sign({ sub: admin.id, u: admin.username }, JWT_SECRET, { expiresIn: JWT_EXP });
}
function requireAdmin(req, res, next) {
  const token = req.cookies.admin_token || (req.header('authorization') || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'not logged in' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload;
    return next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}
async function audit(adminUser, action, detail, ip) {
  await AdminAudit.create({ admin_user: adminUser || null, action, detail, ip: ip || null }).catch(()=>{});
}

// Build blocklist file from DB + external lists
async function buildBlocklistFileFromDBAndSources() {
  const rows = await BlockedDomain.findAll({ where: { is_enabled: true } });
  const hostRules = rows.map(r => `||${r.domain}^`);
  const urls = (process.env.BLOCKLIST_URLS || '').split(',').map(s => s.trim()).filter(Boolean);
  for (const u of urls) {
    try {
      const r = await fetch(u);
      if (!r.ok) continue;
      const txt = await r.text();
      const lines = txt.split(/\r?\n/).filter(l => l && !l.startsWith('!'));
      hostRules.push(...lines);
    } catch (e) { /* ignore */ }
  }
  fs.writeFileSync(BLOCKLIST_PATH, hostRules.join('\n'), 'utf8');
}

// Reload blocker (call after DB changes)
async function reloadBlockerFromDB() {
  await buildBlocklistFileFromDBAndSources();
  loadBlocklistsFromFile();
}

// Simple API token middleware
function requireApiToken(req, res, next) {
  const token = req.header('x-api-token') || req.query.api_token;
  if (!token || token !== process.env.API_TOKEN) return res.status(401).json({ error: 'invalid api token' });
  next();
}

// --- Admin endpoints

app.get('/admin/exists', async (req, res) => {
  const c = await Admin.count();
  res.json({ exists: c > 0 });
});

app.post('/admin/setup', async (req, res) => {
  try {
    const cnt = await Admin.count();
    if (cnt > 0) return res.status(403).json({ error: 'admin exists' });
    const username = (req.body.username || 'admin').toString();
    const password = (req.body.password || '').toString();
    if (!password || password.length < 8) return res.status(400).json({ error: 'password min 8 chars' });
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const admin = await Admin.create({ username, password_hash: hash });
    await audit(username, 'initial_setup', 'created initial admin', req.ip);
    const token = signAdminJwt(admin);
    res.cookie('admin_token', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 8 * 3600 * 1000 });
    res.json({ ok: true });
  } catch (e) {
    console.error('setup err', e);
    res.status(500).json({ error: 'setup failed' });
  }
});

app.post('/admin/login', async (req, res) => {
  try {
    const username = (req.body.username || '').toString();
    const password = (req.body.password || '').toString();
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });
    const admin = await Admin.findOne({ where: { username } });
    if (!admin) {
      await audit(username, 'login_failed', 'no such admin', req.ip);
      return res.status(401).json({ error: 'invalid' });
    }
    const ok = await bcrypt.compare(password, admin.password_hash);
    if (!ok) {
      await audit(username, 'login_failed', 'bad password', req.ip);
      return res.status(401).json({ error: 'invalid' });
    }
    await admin.update({ last_login: new Date() });
    const token = signAdminJwt(admin);
    res.cookie('admin_token', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 8 * 3600 * 1000 });
    await audit(admin.username, 'login', 'admin logged in', req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('login err', e);
    res.status(500).json({ error: 'login failed' });
  }
});

app.post('/admin/logout', requireAdmin, async (req, res) => {
  res.clearCookie('admin_token');
  await audit(req.admin.u, 'logout', 'admin logged out', req.ip);
  res.json({ ok: true });
});

app.post('/admin/domains', requireAdmin, async (req, res) => {
  const domain = req.body.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const host = normalizeHost(domain);
  if (!host) return res.status(400).json({ error: 'invalid domain' });
  try {
    await BlockedDomain.upsert({ domain: host, source: req.body.source || 'manual', added_by: req.admin.u, is_enabled: true, added_at: new Date() });
    await audit(req.admin.u, 'add_domain', host, req.ip);
    await reloadBlockerFromDB();
    res.json({ ok: true, domain: host });
  } catch (e) {
    console.error('add domain err', e);
    res.status(500).json({ error: 'add failed' });
  }
});

app.get('/admin/domains', requireAdmin, async (req, res) => {
  const q = req.query.q || '';
  const enabled = req.query.enabled;
  const page = Math.max(1, parseInt(req.query.page || '1'));
  const limit = Math.min(500, parseInt(req.query.limit || '100'));
  const where = {};
  if (q) where.domain = { [Op.like]: `%${q}%` };
  if (enabled === '1' || enabled === '0') where.is_enabled = enabled === '1';
  const rows = await BlockedDomain.findAndCountAll({ where, limit, offset: (page - 1) * limit, order: [['domain', 'ASC']] });
  res.json({ total: rows.count, page, rows: rows.rows });
});

app.delete('/admin/domains/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const r = await BlockedDomain.findByPk(id);
  if (!r) return res.status(404).json({ error: 'not found' });
  await r.destroy();
  await audit(req.admin.u, 'delete_domain', r.domain, req.ip);
  await reloadBlockerFromDB();
  res.json({ ok: true });
});

app.post('/admin/domains/bulk-toggle', requireAdmin, async (req, res) => {
  const ids = req.body.ids || [];
  const enable = !!req.body.enable;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids required' });
  await BlockedDomain.update({ is_enabled: enable }, { where: { id: ids } });
  await audit(req.admin.u, 'bulk_toggle', `ids:${ids.length} enable:${enable}`, req.ip);
  await reloadBlockerFromDB();
  res.json({ ok: true });
});

app.post('/admin/domains/upload', requireAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'file required' });
    const content = fs.readFileSync(req.file.path, 'utf8');
    const records = csvParse(content, { relax_column_count: true, skip_empty_lines: true }).map(r => (Array.isArray(r) ? r[0] : r[0]));
    const results = { imported: 0, skipped: 0, errors: [] };
    for (const raw of records) {
      const host = normalizeHost(String(raw || ''));
      if (!host) { results.skipped++; continue; }
      try {
        await BlockedDomain.upsert({ domain: host, source: 'csv', added_by: req.admin.u, is_enabled: true, added_at: new Date() });
        results.imported++;
      } catch (e) {
        results.errors.push({ domain: host, error: e.message });
      }
    }
    fs.unlinkSync(req.file.path);
    await audit(req.admin.u, 'upload_csv', `imported:${results.imported} skipped:${results.skipped}`, req.ip);
    await reloadBlockerFromDB();
    res.json(results);
  } catch (e) {
    console.error('csv upload err', e);
    res.status(500).json({ error: 'upload failed' });
  }
});

app.get('/admin/domains/download', requireAdmin, async (req, res) => {
  const rows = await BlockedDomain.findAll({ order: [['domain', 'ASC']] });
  res.setHeader('Content-disposition', 'attachment; filename=blocked_domains.csv');
  res.setHeader('Content-type', 'text/csv');
  res.write('domain,source,is_enabled,added_by,added_at\n');
  for (const r of rows) {
    res.write(`${r.domain},${r.source||''},${r.is_enabled?1:0},${r.added_by||''},${r.added_at.toISOString()}\n`);
  }
  res.end();
});

app.post('/admin/blocklist/reload', requireAdmin, async (req, res) => {
  try {
    await reloadBlockerFromDB();
    await audit(req.admin.u, 'reload_blocklist', 'manual reload', req.ip);
    res.json({ ok: true });
  } catch (e) {
    console.error('reload err', e);
    res.status(500).json({ error: 'reload failed' });
  }
});

app.get('/admin/users', requireAdmin, async (req, res) => {
  const rows = await History.findAll({
    attributes: ['ip_addr', [sequelize.fn('max', sequelize.col('visitedAt')), 'last_seen']],
    group: ['ip_addr'],
    order: [[sequelize.literal('last_seen'), 'DESC']],
    limit: 200
  });
  res.json(rows);
});

app.get('/admin/audit', requireAdmin, async (req, res) => {
  const rows = await AdminAudit.findAll({ order: [['created_at', 'DESC']], limit: 500 });
  res.json(rows);
});

// Public API
app.get('/api/search', requireApiToken, async (req, res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ error: 'q required' });
  const key = process.env.GOOGLE_API_KEY;
  const cx = process.env.GOOGLE_CX;
  if (!key || !cx) return res.status(500).json({ error: 'search not configured' });
  const url = `https://www.googleapis.com/customsearch/v1?key=${encodeURIComponent(key)}&cx=${encodeURIComponent(cx)}&q=${encodeURIComponent(q)}`;
  try {
    const r = await fetch(url);
    if (!r.ok) return res.status(502).json({ error: 'search provider failed', status: r.status });
    const data = await r.json();
    if (data.items && Array.isArray(data.items)) {
      const filtered = [];
      for (const it of data.items) {
        const blocked = it.link ? await isBlockedUrl(it.link) : false;
        if (!blocked) filtered.push(it);
      }
      data.items = filtered;
    }
    if (req.query.incognito !== '1' && data.items && data.items[0]) {
      await History.create({ userId: null, url: data.items[0].link, title: data.items[0].title, snippet: data.items[0].snippet || null, visitedAt: new Date(), isIncognito: false, ip_addr: req.ip }).catch(()=>{});
    }
    res.json(data);
  } catch (e) {
    console.error('search error', e);
    res.status(500).json({ error: 'search failed' });
  }
});

app.get('/api/proxy', requireApiToken, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'url required' });
  try {
    if (await isBlockedUrl(target)) {
      await History.create({ url: target, isIncognito: false, ip_addr: req.ip }).catch(()=>{});
      return res.status(403).json({ blocked: true });
    }
    const r = await fetch(target, { headers: { 'User-Agent': 'RenderBrowserBackend/1.0' }, redirect: 'follow' });
    const ct = r.headers.get('content-type') || '';
    if (ct.includes('text/html') && req.query.sanitize === '1') {
      let html = await r.text();
      const $ = cheerio.load(html);
      $('script, iframe, link[rel="stylesheet"]').each((i, el) => {
        const src = $(el).attr('src') || $(el).attr('href') || '';
        if (src && isBlockedUrl(src)) $(el).remove();
      });
      $('[onclick],[onload],[onerror]').each((i, el) => {
        $(el).removeAttr('onclick').removeAttr('onload').removeAttr('onerror');
      });
      const out = $.html();
      res.type('text/html').send(out);
    } else {
      res.status(r.status);
      r.body.pipe(res);
    }
    if (req.query.incognito !== '1') {
      await History.create({ url: target, isIncognito: false, ip_addr: req.ip }).catch(()=>{});
    }
  } catch (e) {
    console.error('proxy fetch failed', e);
    res.status(502).json({ error: 'fetch failed' });
  }
});

app.get('/api/history', requireApiToken, async (req, res) => {
  const limit = Math.min(100, parseInt(req.query.limit || '50'));
  const rows = await History.findAll({ order: [['visitedAt', 'DESC']], limit });
  res.json(rows);
});
app.post('/api/history', requireApiToken, async (req, res) => {
  const { url, title, incognito } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });
  await History.create({ url, title: title||null, isIncognito: !!incognito, ip_addr: req.ip }).catch(e => console.warn(e));
  res.json({ ok: true });
});

app.get('/health', (req, res) => res.json({ ok: true }));

// Build and load blocklist immediate if possible
(async () => {
  try {
    await buildBlocklistFileFromDBAndSources();
    loadBlocklistsFromFile();
  } catch (e) { /* ignore */ }
})();

// Start server
app.listen(PORT, () => console.log(`server listening on ${PORT}`));