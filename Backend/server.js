const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");

const app = express();
const PORT = 3000;

/* ================= DATABASE ================= */

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Root", // 👈 put your MySQL password if any
  database: "cards_db",
});

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL connection failed:", err.message);
    process.exit(1);
  }
  console.log("✅ MySQL Connected");
});

/* ================= MIDDLEWARE ================= */

app.use(cors());
app.use(express.json());

/* ================= AUTH MIDDLEWARE ================= */

function checkAuth(req, res, next) {
  const token = req.headers.authorization;

  if (!token || token !== "Bearer soc-admin") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

/* ================= HELPERS ================= */

function getGeo(ip) {
  return ip.startsWith("192.") || ip.startsWith("10.")
    ? "Internal"
    : "External";
}

/* ================= ROUTES ================= */

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === "admin" && password === "admin") {
    return res.json({ token: "soc-admin" });
  }

  res.status(401).json({ error: "Invalid credentials" });
});

// Submit log
app.post("/submit-log", (req, res) => {
  const { username, ip, status } = req.body;

  if (!username || !ip || !status) {
    return res.status(400).json({ error: "Invalid data" });
  }

  const sql =
    "INSERT INTO logs (timestamp, sourceIP, username, eventType, status, geoLocation) VALUES (NOW(), ?, ?, 'AUTH', ?, ?)";

  db.query(sql, [ip, username, status, getGeo(ip)], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "DB error" });
    }

    res.json({ message: "Log stored" });
  });
});

// Get logs
app.get("/logs", checkAuth, (req, res) => {
  db.query("SELECT * FROM logs ORDER BY id DESC LIMIT 50", (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

// Get alerts
app.get("/alerts", checkAuth, (req, res) => {
  db.query("SELECT * FROM alerts ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

// Dashboard
app.get("/dashboard", checkAuth, (req, res) => {
  db.query("SELECT COUNT(*) AS c FROM logs", (e1, r1) => {
    db.query("SELECT COUNT(*) AS c FROM alerts", (e2, r2) => {
      if (e1 || e2) return res.status(500).json({ error: "DB error" });

      res.json({
        totalLogs: r1[0].c,
        totalAlerts: r2[0].c,
      });
    });
  });
});

/* ================= START SERVER ================= */

app.listen(PORT, () => {
  console.log(`🚀 Backend running on http://localhost:${PORT}`);
});
