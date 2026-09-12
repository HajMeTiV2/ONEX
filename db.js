const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const db = new sqlite3.Database(path.join(__dirname, 'onex.db'));

// تبدیل توابع callback به Promise برای راحتی استفاده
db.runAsync = function(sql, params = []) {
  return new Promise((resolve, reject) => {
    this.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

db.getAsync = function(sql, params = []) {
  return new Promise((resolve, reject) => {
    this.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

db.allAsync = function(sql, params = []) {
  return new Promise((resolve, reject) => {
    this.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// ساخت جداول و دیتای اولیه
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    total_traffic_gb REAL DEFAULT 50,
    used_traffic_gb REAL DEFAULT 0,
    expire_date TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    upload_mb REAL DEFAULT 0,
    download_mb REAL DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    sni TEXT,
    protocols TEXT DEFAULT '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]'
  )`);

  // سرور پیش‌فرض
  db.get("SELECT COUNT(*) as c FROM servers", (err, row) => {
    if (!err && row.c === 0) {
      db.run(`INSERT INTO servers (id, name, host, port, sni, protocols) VALUES (?, ?, ?, ?, ?, ?)`,
        [uuidv4(), 'ONEX Core Server', 'server1.onexvpn.net', 443, 'server1.onexvpn.net', '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]']);
    }
  });

  // کاربر تست (admin/admin123)
  db.get("SELECT COUNT(*) as c FROM users", (err, row) => {
    if (!err && row.c === 0) {
      const uid = uuidv4();
      db.run(`INSERT INTO users (id, username, password, email, total_traffic_gb, used_traffic_gb, expire_date) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [uid, 'admin', 'admin123', 'info@onex.pro', 60, 14.8, '1404/05/20']);

      // داده‌های نمودار
      for (let i = 23; i >= 0; i--) {
        const t = new Date(Date.now() - i * 3600000).toISOString();
        db.run(`INSERT INTO traffic_logs (user_id, timestamp, upload_mb, download_mb) VALUES (?, ?, ?, ?)`,
          [uid, t, Math.floor(Math.random() * 45 + 5), Math.floor(Math.random() * 180 + 20)]);
      }
    }
  });
});

module.exports = db;
