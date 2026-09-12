
const Database = require('better-sqlite3');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const db = new Database(path.join(__dirname, 'onex.db'));
db.pragma('journal_mode = WAL');

// ساخت جداول
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
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
  );

  CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    upload_mb REAL DEFAULT 0,
    download_mb REAL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    sni TEXT,
    protocols TEXT DEFAULT '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]'
  );
`);

// ثبت سرور پیش‌فرض ONEX
const checkServer = db.prepare('SELECT COUNT(*) as c FROM servers').get();
if (checkServer.c === 0) {
  db.prepare(`INSERT INTO servers (id, name, host, port, sni, protocols) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(uuidv4(), 'ONEX Core Server', 'server1.onexvpn.net', 443, 'server1.onexvpn.net', '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]');
}

// ثبت کاربر تست اولیه (admin / admin123)
const checkUser = db.prepare('SELECT COUNT(*) as c FROM users').get();
if (checkUser.c === 0) {
  const uid = uuidv4();
  db.prepare(`INSERT INTO users (id, username, password, email, total_traffic_gb, used_traffic_gb, expire_date) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(uid, 'admin', 'admin123', 'info@onex.pro', 60, 14.8, '1404/05/20');

  // ساخت داده‌های نمونه برای نمودار
  const insertLog = db.prepare(`INSERT INTO traffic_logs (user_id, timestamp, upload_mb, download_mb) VALUES (?, ?, ?, ?)`);
  for (let i = 23; i >= 0; i--) {
    const t = new Date(Date.now() - i * 3600000).toISOString();
    insertLog.run(uid, t, Math.floor(Math.random() * 45 + 5), Math.floor(Math.random() * 180 + 20));
  }
}

module.exports = db;
