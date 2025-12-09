/**
 * server.js - Updated, robust backend (SQLite) with host-based blocklist parsing
 *
 * Features:
 * - SQLite (no external DB required)
 * - Admin setup/login (bcrypt + JWT in HTTP-only cookie)
 * - Admin endpoints: add domain, bulk toggle, delete, CSV upload/download, reload blocklists
 * - Public API: /api/search (Google CSE), /api/proxy (sanitized), /api/history
 * - Block decision uses:
 *     1) admin DB "blocked_domains" entries (exact host match or parent domain)
 *     2) parsed host rules from external blocklists (BLOCKLIST_URLS) and DB, loaded into an in-memory Set
 * - Simple, reliable parsing for ABP-style host rules (lines like "||example.com^") and hosts lists
 *
 * Notes:
 * - This intentionally avoids unreliable third-party adblock npm packages and uses deterministic host matching.
 * - To block more complex cases later, we can integrate a full ABP engine; for now this is fast and stable.
 *
 * Required env vars:
 * - API_TOKEN (required for /api/*)
 * - APP_SECRET (required for admin JWTs)
 * - GOOGLE_API_KEY, GOOGLE_CX (optional - /api/search)
 * - BLOCKLIST_URLS (optional - comma-separated list of external lists to fetch when reloading)
 * - PORT (optional)
 *
 * Run:
 *  npm install
 *  npm start
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

// ---------- SQLite (Sequelize) ----------
const SQLITE_FILE = path.join(__dirname, 'database.sqlite');
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: SQLITE_FILE,
  logging: false
});

// Models
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

// Initialize DB
(async () => {
  try {
    await sequelize.authenticate();
    await Admin.sync();
    await BlockedDomain.sync();
    await History.sync();
    await AdminAudit.sync();
    console.log('[DB] SQLite connected & models synced at', SQLITE_FILE);
  } catch (e) {
    console.error('DB init error', e);
    process.exit(1);
  }
})();

// Rate limiter
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));

// ---------- Blocklist in-memory structure (host-based) ----------
let hostBlockSet = new Set(); // contains normalized host strings to block (example.com, ads.example.org)

// parse a single line from ABP/hosts list into zero or more hostnames
function extractHostsFromRuleLine(line) {
  // Normalize
  line = (line || '').trim();
  if (!line || line.startsWith('!') || line.startsWith('[')) return [];
  // If it's a simple hosts file line: "0.0.0.0 domain" or "127.0.0.1 domain"
  const hosts = [];
  const hostMatch = line.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([^\s#]+)/);
  if (hostMatch) {
    hosts.push(hostMatch[1].replace(/^www\./, '').toLowerCase());
    return hosts;
  }
  // ABP simple rule: ||domain^
  const abpHostMatch = line.match(/^\|\|([^\/\^\$]+)\^?/);
  if (abpHostMatch) {
    hosts.push(abpHostMatch[1].replace(/^www\./, '').toLowerCase());
    return hosts;
  }
  // Domain-only lines (just a domain)
  if (/^[a-z0-9\.\-]+$/i.test(line)) {
    hosts.push(line.replace(/^www\./, '').toLowerCase());
    return hosts;
  }
  // Some rules may be urls: https?://domain/... -> extract host
  try {
    if (line.startsWith('http://') || line.startsWith('https://')) {
      const u = new URL(line);
      hosts.push(u.hostname.replace(/^www\./, '').toLowerCase());
      return hosts;
    }
  } catch (e) { /* ignore */ }
  return [];
}

// Load blocklist file into hostBlockSet
function loadBlocklistsFromFile() {
  hostBlockSet = new Set();
  try {
    if (!fs.existsSync(BLOCKLIST_PATH)) {
      console.warn('[Blocker] blocklist file not found:', BLOCKLIST_PATH);
      return;
    }
    const txt = fs.readFileSync(BLOCKLIST_PATH, 'utf8');
    const lines = txt.split(/\r?\n/);
    for (const line of lines) {
      const hs = extractHostsFromRuleLine(line);
      for (const h of hs) hostBlockSet.add(h);
    }
    console.log('[Blocker] loaded', hostBlockSet.size, 'host rules from', BLOCKLIST_PATH);
  } catch (e) {
    console.error('[Blocker] failed to load file', e);
    hostBlockSet = new Set();
  }
}

// Build blocklist file from DB + external lists (writes BLOCKLIST_PATH)
async function buildBlocklistFileFromDBAndSources() {
  const hostLines = [];
  // include admin DB domains
  try {
    const rows = await BlockedDomain.findAll({ where: { is_enabled: true } });
    for (const r of rows) {
      if (r.domain) hostLines.push(`||${r.domain}^   # source:${r.source || 'db'}`);
    }
  } catch (e) {
    console.warn('error reading DB blocked domains', e);
  }

  // fetch external lists (BLOCKLIST_URLS env)
  const urls = (process.env.BLOCKLIST_URLS || '').split(',').map(s => s.trim()).filter(Boolean);
  for (const u of urls) {
    try {
      const r = await fetch(u, { timeout: 20000 });
      if (!r.ok) {
        console.warn('failed fetching list', u, 'status', r.status);
        continue;
      }
      const txt = await r.text();
      const lines = txt.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      hostLines.push(...lines);
    } catch (e) {
      console.warn('error fetching list', u, e && e.message);
    }
  }

  // write merged file
  try {
    fs.writeFileSync(BLOCKLIST_PATH, hostLines.join('\n'), 'utf8');
    console.log('[Blocker] wrote blocklist file with', hostLines.length, 'lines');
  } catch (e) {
    console.error('[Blocker] failed to write blocklist file', e);
  }
}

// Helper: normalize host for matching
function normalizeHost(input) {
  if (!input || typeof input !== 'string') return null;
  try {
    let h = input.trim();
    if (h.startsWith('http://') || h.startsWith('https://')) h = new URL(h).hostname;
    h = h.replace(/^www\./, '').toLowerCase();
    if (!/^[a-z0-9\.\-]{1,255}$/.test(h)) return null;
    return h;
  } catch (e) {
    return null;
  }
}

// Blocking decision: check DB + hostBlockSet
async function isBlockedUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.replace(/^www\./, '').toLowerCase();

    // 1) DB exact/parent domain check (admin overrides)
    // check exact
    const dbExact = await BlockedDomain.findOne({ where: { domain: host, is_enabled: true } });
    if (dbExact) return true;
    // check parent domain matches (example.com matches sub.example.com)
    const parts = host.split('.');
    for (let i = 0; i <= parts.length - 2; i++) {
      const candidate = parts.slice(i).join('.');
      const db = await BlockedDomain.findOne({ where: { domain: candidate, is_enabled: true } });
      if (db) return true;
    }

    // 2) hostBlockSet (fast in-memory)
    // check exact and parent suffixes
    if (hostBlockSet.size > 0) {
      if (hostBlockSet.has(host)) return true;
      // check suffixes (block example.com should match sub.example.com)
      for (let i = 0; i <= parts.length - 2; i++) {
        const cand = parts.slice(i).join('.');
        if (hostBlockSet.has(cand)) return true;
      }
    }

    return false;
  } catch (e) {
    return false;
  }
}

// After DB or external change: rebuild file and reload in-memory set
async function reloadBlockerFromDB() {
  await buildBlocklistFileFromDBAndSources();
  loadBlocklistsFromFile();
}

// Initially try to build & load
(async () => {
  try {
    await buildBlocklistFileFromDBAndSources();
    loadBlocklistsFromFile();
  } catch (e) {
    console.warn('[Blocker] initial build/load failed', e);
  }
})();

// ---------- Admin helpers & auth ----------
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

// API token middleware
function requireApiToken(req, res, next) {
  const token = req.header('x-api-token') || req.query.api_token;
  if (!token || token !== process.env.API_TOKEN) return res.status(401).json({ error: 'invalid api token' });
  next();
}

// ---------- Admin endpoints ----------

// Check if an admin exists
app.get('/admin/exists', async (req, res) => {
  const c = await Admin.count();
  res.json({ exists: c > 0 });
});

// Setup first-time admin
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

// Login admin
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

// Logout
app.post('/admin/logout', requireAdmin, async (req, res) => {
  res.clearCookie('admin_token');
  await audit(req.admin.u, 'logout', 'admin logged out', req.ip);
  res.json({ ok: true });
});

// Add single domain
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

// List domains (paginated)
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

// Delete domain
app.delete('/admin/domains/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  const r = await BlockedDomain.findByPk(id);
  if (!r) return res.status(404).json({ error: 'not found' });
  await r.destroy();
  await audit(req.admin.u, 'delete_domain', r.domain, req.ip);
  await reloadBlockerFromDB();
  res.json({ ok: true });
});

// Bulk toggle
app.post('/admin/domains/bulk-toggle', requireAdmin, async (req, res) => {
  const ids = req.body.ids || [];
  const enable = !!req.body.enable;
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids required' });
  await BlockedDomain.update({ is_enabled: enable }, { where: { id: ids } });
  await audit(req.admin.u, 'bulk_toggle', `ids:${ids.length} enable:${enable}`, req.ip);
  await reloadBlockerFromDB();
  res.json({ ok: true });
});

// CSV upload
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

// Download CSV
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

// Force reload blocklists (DB + external)
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

// Admin: users (simple aggregated view)
app.get('/admin/users', requireAdmin, async (req, res) => {
  const rows = await History.findAll({
    attributes: ['ip_addr', [sequelize.fn('max', sequelize.col('visitedAt')), 'last_seen']],
    group: ['ip_addr'],
    order: [[sequelize.literal('last_seen'), 'DESC']],
    limit: 200
  });
  res.json(rows);
});

// Admin audit
app.get('/admin/audit', requireAdmin, async (req, res) => {
  const rows = await AdminAudit.findAll({ order: [['created_at', 'DESC']], limit: 500 });
  res.json(rows);
});

// ---------- Public API endpoints ----------

// Search (Google Custom Search) - requires API_TOKEN
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

// Proxy endpoint (authenticated) - sanitize removes blocked scripts/iframes/stylesheet links
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
        if (src) {
          // if the resource URL is blocked by our rules, remove the element
          (async () => {
            try {
              const blocked = await isBlockedUrl(src);
              if (blocked) $(el).remove();
            } catch (e) { /* ignore */ }
          })();
        }
      });
      // remove inline event handlers (basic)
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

// History endpoints
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

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

// Start server
app.listen(PORT, () => console.log(`server listening on ${PORT}`));