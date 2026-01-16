const mysql = require("mysql2");

const connection = mysql.createConnection({
  host: "localhost",
  user: "root@localhost",
  password: "Root",
  database: "cards_db",
});

connection.connect((err) => {
  if (err) {
    console.error("❌ MySQL connection failed:", err);
  } else {
    console.log("✅ MySQL connected");
  }
});

module.exports = connection;
