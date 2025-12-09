import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import axios from "axios";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection
const db = await mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASS,
  database: process.env.MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 10
});

// ------------------------------
// Utility: Clean tracking params
// ------------------------------
function cleanUrl(url) {
  try {
    const u = new URL(url);
    [...u.searchParams.keys()].forEach(k => {
      if (k.startsWith("utm_") || k === "fbclid" || k === "gclid") {
        u.searchParams.delete(k);
      }
    });
    return u.toString();
  } catch {
    return url;
  }
}

// ------------------------------
// USER INIT (Auto-create user)
// ------------------------------
app.get("/user/init", async (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.ip;

  const [rows] = await db.query("SELECT * FROM users WHERE ip = ? LIMIT 1", [ip]);
  if (rows.length) return res.json({ user: rows[0] });

  const [insert] = await db.query("INSERT INTO users (ip) VALUES (?)", [ip]);
  res.json({ user: { id: insert.insertId, ip } });
});

// ------------------------------
// SEARCH (Google API)
// ------------------------------
app.get("/search", async (req, res) => {
  const q = req.query.q;
  if (!q) return res.status(400).json({ error: "Missing query" });

  try {
    const googleURL =
      `https://www.googleapis.com/customsearch/v1?key=${process.env.GOOGLE_API_KEY}&cx=${process.env.GOOGLE_CX}&q=` +
      encodeURIComponent(q);

    const result = await axios.get(googleURL);
    const cleaned = (result.data.items || []).map(i => ({
      title: i.title,
      link: cleanUrl(i.link),
      snippet: i.snippet
    }));

    res.json({ results: cleaned });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Google API error" });
  }
});

// ------------------------------
// SAVE HISTORY
// ------------------------------
app.post("/history/add", async (req, res) => {
  const { userId, url, title } = req.body;
  if (!userId || !url) return res.status(400).json({ error: "Missing fields" });

  await db.query(
    "INSERT INTO history (user_id, url, title) VALUES (?, ?, ?)",
    [userId, url, title]
  );

  res.json({ ok: true });
});

// ------------------------------
// GET USER HISTORY
// ------------------------------
app.get("/history/user/:id", async (req, res) => {
  const id = req.params.id;
  const [rows] = await db.query(
    "SELECT * FROM history WHERE user_id = ? ORDER ORDER BY timestamp DESC",
    [id]
  );
  res.json(rows);
});

// ----------------------------------
// BASIC PROXY with Ad Removal
// ----------------------------------
app.get("/proxy/basic", async (req, res) => {
  let url = req.query.url;
  if (!url) return res.status(400).send("Missing URL");

  url = cleanUrl(url);

  try {
    // Load blocklist
    const [blocked] = await db.query("SELECT domain FROM blocklist");
    const blockedDomains = blocked.map(b => b.domain);

    const hostname = new URL(url).hostname;

    // If domain blocked → deny
    if (blockedDomains.includes(hostname)) {
      return res.status(403).send("This domain is blocked");
    }

    const response = await axios.get(url, {
      headers: { "User-Agent": "DeepBrowser/1.0" }
    });

    let html = response.data;

    // Remove ALL scripts
    html = html.replace(/<script[\s\S]*?<\/script>/gi, "");

    // Remove iframes (ads)
    html = html.replace(/<iframe[\s\S]*?<\/iframe>/gi, "");

    // Remove ad network URLs
    blockedDomains.forEach(domain => {
      const regex = new RegExp(domain, "gi");
      html = html.replace(regex, "");
    });

    res.send(html);
  } catch (err) {
    console.error(err);
    res.status(500).send("Proxy failed");
  }
});

// ----------------------------------
// ADMIN: AUTH
// ----------------------------------
app.post("/admin/auth", (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) return res.json({ ok: true });
  res.status(401).json({ ok: false });
});

// ----------------------------------
// ADMIN: USERS
// ----------------------------------
app.get("/admin/users", async (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD)
    return res.status(401).json({ ok: false });

  const [rows] = await db.query("SELECT * FROM users ORDER BY id DESC");
  res.json(rows);
});

// ----------------------------------
// ADMIN: FULL HISTORY
// ----------------------------------
app.get("/admin/history", async (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD)
    return res.status(401).json({ ok: false });

  const [rows] = await db.query(`
    SELECT h.*, u.ip
    FROM history h
    LEFT JOIN users u ON h.user_id = u.id
    ORDER BY h.timestamp DESC
  `);
  res.json(rows);
});

// ----------------------------------
// ADMIN: BLOCKLIST MANAGEMENT
// ----------------------------------

// Add domain
app.post("/admin/blocklist/add", async (req, res) => {
  const { domain, password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).send("Bad password");

  await db.query("INSERT INTO blocklist (domain) VALUES (?)", [domain]);
  res.json({ ok: true });
});

// Remove domain
app.post("/admin/blocklist/remove", async (req, res) => {
  const { domain, password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).send("Bad password");

  await db.query("DELETE FROM blocklist WHERE domain = ?", [domain]);
  res.json({ ok: true });
});

// List domains
app.get("/admin/blocklist/list", async (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD) return res.status(401).send("Bad password");

  const [rows] = await db.query("SELECT * FROM blocklist ORDER BY id DESC");
  res.json(rows);
});

// CSV upload
app.post("/admin/blocklist/upload", async (req, res) => {
  const { csv, password } = req.body;
  if (password !== process.env.ADMIN_PASSWORD) return res.status(401).send("Bad password");

  const domains = csv.split("\n").map(d => d.trim()).filter(Boolean);

  for (const domain of domains) {
    await db.query("INSERT INTO blocklist (domain) VALUES (?)", [domain]);
  }

  res.json({ ok: true });
});

// CSV download
app.get("/admin/blocklist/download", async (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD) return res.status(401).send("Bad password");

  const [rows] = await db.query("SELECT domain FROM blocklist");

  const csv = rows.map(r => r.domain).join("\n");

  res.header("Content-Type", "text/csv");
  res.attachment("blocklist.csv");
  res.send(csv);
});

// ----------------------------------
// ROOT
// ----------------------------------
app.get("/", (req, res) => {
  res.send("Deep Browser Backend Running — Proxy + Blocklist Enabled");
});

// ----------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on " + PORT));