const cors = require("cors");

app.use(cors());
app.use(express.json());

const express = require("express");
const app = express();
const PORT = 3000;

app.use(express.json());

// ================== IN-MEMORY STORAGE ==================
const logs = []; // normalized SOC logs
const alerts = []; // active alerts

// ================== HELPERS ==================
function formatTime() {
  return new Date().toLocaleTimeString();
}

function getGeo(ip) {
  return ip.startsWith("192.") || ip.startsWith("10.") ? "Internal" : "Russia";
}

function getSeverity(failCount, successAfterFail) {
  if (successAfterFail) return "Critical";
  if (failCount >= 6) return "High";
  if (failCount >= 3) return "Medium";
  return "Low";
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
function processLogin(username, ip, status) {
  // Normalized SOC log
  const log = {
    timestamp: formatTime(),
    sourceIP: ip,
    geoLocation: getGeo(ip),
    eventType: "AUTH",
    rawMessage:
      status === "failed"
        ? "Failed login attempt"
        : `Login SUCCESS: ${username}`,
    action: "Investigate",
    status,
  };

  logs.push(log);

  // ---- Detection logic ----
  const ipLogs = logs.filter((l) => l.sourceIP === ip);
  const failedLogs = ipLogs.filter((l) => l.status === "failed");
  const failCount = failedLogs.length;

  const successAfterFail = ipLogs.some((log, index) => {
    if (log.status !== "success") return false;
    const prevFails = ipLogs
      .slice(0, index)
      .filter((l) => l.status === "failed").length;
    return prevFails >= 3;
  });

  if (failCount >= 3) {
    const severity = getSeverity(failCount, successAfterFail);
    const riskScore = calculateRiskScore(failCount, severity, successAfterFail);

    let alert = alerts.find((a) => a.ip === ip);

    if (!alert) {
      alert = {
        id: alerts.length + 1,
        ip,
        severity,
        riskScore,
        rule: "Brute Force Detection Rule",
        reason: `${failCount} failed login attempts from same IP`,
        timeline: ipLogs,
        investigation: {
          country: getGeo(ip),
          reputation: "Suspicious",
          blacklisted: "Yes (Simulated)",
        },
        summary: generateSummary(ip, failCount, successAfterFail),
        createdAt: formatTime(),
      };
      alerts.push(alert);
    } else {
      // Update existing alert
      alert.severity = severity;
      alert.riskScore = riskScore;
      alert.reason = `${failCount} failed login attempts from same IP`;
      alert.timeline = ipLogs;
      alert.summary = generateSummary(ip, failCount, successAfterFail);
    }

    console.log(`🚨 ALERT | ${ip} | ${severity} | Risk ${riskScore}`);
  }
}

// ================== ROUTES ==================

// Manual login ingestion
app.post("/login", (req, res) => {
  const { username, ip, status } = req.body;

  if (!username || !ip || !status) {
    return res.status(400).json({ message: "Invalid login data" });
  }

  processLogin(username, ip, status);
  res.json({ message: "Login event processed" });
});

// Simulated live attack
app.post("/simulate", (req, res) => {
  const ip = "45.33.22.11";

  for (let i = 0; i < 5; i++) {
    processLogin("admin", ip, "failed");
  }

  processLogin("admin", ip, "success");

  res.json({ message: "Simulated attack logs generated" });
});

// SOC log table
app.get("/logs", (req, res) => {
  res.json(logs);
});

// Alerts
app.get("/alerts", (req, res) => {
  res.json(alerts);
});

// Dashboard metrics
app.get("/dashboard", (req, res) => {
  res.json({
    totalLogs: logs.length,
    totalAlerts: alerts.length,
    criticalAlerts: alerts.filter((a) => a.severity === "Critical").length,
  });
});

// ================== START SERVER ==================
app.listen(PORT, () => {
  console.log(`✅ SOC Backend running on port ${PORT}`);
});
