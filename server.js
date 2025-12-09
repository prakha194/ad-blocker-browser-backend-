import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mysql from "mysql2/promise";
import axios from "axios";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MySQL connection pool
const db = await mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASS,
  database: process.env.MYSQL_DB,
  waitForConnections: true,
  connectionLimit: 10
});

// Utility: Remove tracking parameters
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

// -------------------------------------------
// AUTO-CREATE USER BY IP
// -------------------------------------------
app.get("/user/init", async (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.ip;

  const [rows] = await db.query("SELECT * FROM users WHERE ip = ? LIMIT 1", [ip]);
  if (rows.length) return res.json({ user: rows[0] });

  const [insert] = await db.query("INSERT INTO users (ip) VALUES (?)", [ip]);
  res.json({ user: { id: insert.insertId, ip } });
});

// -------------------------------------------
// SEARCH USING GOOGLE API (NO TOKEN NEEDED)
// -------------------------------------------
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

// -------------------------------------------
// SAVE HISTORY
// -------------------------------------------
app.post("/history/add", async (req, res) => {
  const { userId, url, title } = req.body;
  if (!userId || !url) return res.status(400).json({ error: "Missing fields" });

  await db.query(
    "INSERT INTO history (user_id, url, title) VALUES (?, ?, ?)",
    [userId, url, title]
  );

  res.json({ ok: true });
});

// -------------------------------------------
// GET USER HISTORY
// -------------------------------------------
app.get("/history/user/:id", async (req, res) => {
  const id = req.params.id;
  const [rows] = await db.query(
    "SELECT * FROM history WHERE user_id = ? ORDER BY timestamp DESC",
    [id]
  );
  res.json(rows);
});

// -------------------------------------------
// ADMIN AUTH
// -------------------------------------------
app.post("/admin/auth", (req, res) => {
  const { password } = req.body;
  if (password === process.env.ADMIN_PASSWORD) {
    return res.json({ ok: true });
  }
  res.status(401).json({ ok: false });
});

// -------------------------------------------
// ADMIN GET ALL USERS
// -------------------------------------------
app.get("/admin/users", async (req, res) => {
  if (req.query.password !== process.env.ADMIN_PASSWORD)
    return res.status(401).json({ ok: false });

  const [rows] = await db.query("SELECT * FROM users ORDER BY id DESC");
  res.json(rows);
});

// -------------------------------------------
// ADMIN GET FULL HISTORY
// -------------------------------------------
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

// -------------------------------------------
app.get("/", (req, res) => {
  res.send("Deep Browser Backend Running");
});

// -------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on " + PORT));