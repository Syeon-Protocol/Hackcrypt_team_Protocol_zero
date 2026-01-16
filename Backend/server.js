/*
 * BACKEND SERVER (Node.js + Express + MySQL)
 * FINAL VERSION
 */

const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");

const app = express();
const PORT = 3000;

// ================== MYSQL CONNECTION ==================
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "root", // Make sure this matches your MySQL password
  database: "cards_db",
};

let pool;

async function initDB() {
  try {
    pool = mysql.createPool(dbConfig);
    console.log("✅ Connected to MySQL Database");
  } catch (error) {
    console.error("❌ MySQL Connection Failed:", error);
    process.exit(1);
  }
}

initDB();

// ================== MIDDLEWARE ==================
app.use(cors());
app.use(express.json());

// Simple Admin Auth Middleware
const checkAuth = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  // We check for the specific token "Bearer soc-admin"
  if (authHeader && authHeader === "Bearer soc-admin") {
    next();
  } else {
    res.status(401).json({ message: "Unauthorized: Please Login" });
  }
};

// ================== HELPERS ==================
function formatTime() {
  return new Date().toLocaleTimeString();
}

function getGeo(ip) {
  return ip.startsWith("192.") || ip.startsWith("10.") ? "Internal" : "Russia";
}

function calculateRiskScore(failCount, severity, successAfterFail) {
  let score = failCount * 10;
  if (severity === "Medium") score += 20;
  if (severity === "High") score += 40;
  if (severity === "Critical") score += 60;
  if (successAfterFail) score += 20;
  return Math.min(score, 100);
}

function generateSummary(ip, failCount, successAfterFail) {
  if (successAfterFail) {
    return `Multiple failed login attempts from IP ${ip} followed by a successful login. This matches a brute-force attack pattern. Immediate attention recommended.`;
  }
  return `Repeated failed login attempts detected from IP ${ip}. Monitoring advised.`;
}

// ================== CORE LOG PROCESSOR ==================
async function processLogin(username, ip, status) {
  const geo = getGeo(ip);
  const time = formatTime();

  // 1. Insert Log
  const insertLogQuery = `INSERT INTO logs (timestamp, sourceIP, username, eventType, status, geoLocation) VALUES (?, ?, ?, 'AUTH', ?, ?)`;
  await pool.execute(insertLogQuery, [time, ip, username, status, geo]);

  // 2. Check for Alert Logic
  const [failRows] = await pool.execute(
    `SELECT COUNT(*) as failCount FROM logs WHERE sourceIP = ? AND status = 'failed'`,
    [ip]
  );
  const failCount = failRows[0].failCount;

  const [successRows] = await pool.execute(
    `SELECT * FROM logs WHERE sourceIP = ? AND status = 'success' LIMIT 1`,
    [ip]
  );
  const successAfterFail = failCount >= 3 && successRows.length > 0;

  if (failCount >= 3) {
    let severity = "Low";
    if (successAfterFail) severity = "Critical";
    else if (failCount >= 6) severity = "High";
    else if (failCount >= 3) severity = "Medium";

    const riskScore = calculateRiskScore(failCount, severity, successAfterFail);
    const summary = generateSummary(ip, failCount, successAfterFail);

    const [existingAlerts] = await pool.execute(
      `SELECT * FROM alerts WHERE ip = ?`,
      [ip]
    );

    if (existingAlerts.length === 0) {
      await pool.execute(
        `INSERT INTO alerts (ip, severity, riskScore, summary, createdAt) VALUES (?, ?, ?, ?, ?)`,
        [ip, severity, riskScore, summary, time]
      );
      console.log(`🚨 NEW ALERT | ${ip} | ${severity} | Risk ${riskScore}`);
    } else {
      await pool.execute(
        `UPDATE alerts SET riskScore = ?, summary = ?, severity = ? WHERE ip = ?`,
        [riskScore, summary, severity, ip]
      );
    }
  }
}

// ================== ROUTES ==================

// 1. Auth Route (ONLY used for the Login Page)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "admin") {
    res.json({ token: "soc-admin", message: "Login Successful" });
  } else {
    res.status(401).json({ message: "Invalid Credentials" });
  }
});

// 2. Submit Log Route (Used by the Simulator Buttons)
// NOTE: I removed 'checkAuth' from here so the simulator works smoothly
app.post("/submit-log", async (req, res) => {
  const { username, ip, status } = req.body;
  if (!username || !ip || !status)
    return res.status(400).json({ message: "Invalid log data" });

  await processLogin(username, ip, status);
  res.json({ message: "Login event processed" });
});

// Simulated live attack (Requires Auth)
app.post("/simulate", checkAuth, async (req, res) => {
  const ip = "45.33.22.11";
  for (let i = 0; i < 5; i++) await processLogin("admin", ip, "failed");
  await processLogin("admin", ip, "success");
  res.json({ message: "Simulated attack logs generated" });
});

// SOC log table (Requires Auth)
app.get("/logs", checkAuth, async (req, res) => {
  const anonymize = req.query.anonymize === "true";
  const [rows] = await pool.execute(
    `SELECT timestamp as time, sourceIP as ip, username, eventType as event, status, geoLocation FROM logs ORDER BY id DESC LIMIT 50`
  );

  if (anonymize) {
    const anonymizedRows = rows.map((log) => ({
      ...log,
      ip: "192.168.X.X",
      username: "User_" + Math.floor(Math.random() * 1000),
      geoLocation: "Hidden",
    }));
    res.json(anonymizedRows);
  } else {
    res.json(rows);
  }
});

// Alerts (Requires Auth)
app.get("/alerts", checkAuth, async (req, res) => {
  const [rows] = await pool.execute(`SELECT * FROM alerts ORDER BY id DESC`);
  res.json(rows);
});

// Dashboard metrics (Requires Auth)
app.get("/dashboard", checkAuth, async (req, res) => {
  const [[logCount]] = await pool.execute(`SELECT COUNT(*) as count FROM logs`);
  const [[alertCount]] = await pool.execute(
    `SELECT COUNT(*) as count FROM alerts`
  );
  res.json({
    totalLogs: logCount.count,
    totalAlerts: alertCount.count,
    criticalAlerts: 0,
  });
});

// ================== START SERVER ==================
app.listen(PORT, () => {
  console.log(`✅ SOC Backend running on port ${PORT}`);
});
