const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const db = new sqlite3.Database(path.join(__dirname, 'onex.db'));

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
    this.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
};
db.allAsync = function(sql, params = []) {
  return new Promise((resolve, reject) => {
    this.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
};

db.serialize(() => {
  // جدول ادمین‌ها و فروشنده‌ها
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'reseller',
    balance_gb REAL DEFAULT 0,
    max_users INTEGER DEFAULT 100,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  )`);

  // جدول کاربران نهایی (End Users) - هر کدام متعلق به یک ادمین
  db.run(`CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL,
    name TEXT NOT NULL,
    uuid TEXT UNIQUE NOT NULL,
    total_traffic_gb REAL DEFAULT 30,
    used_traffic_gb REAL DEFAULT 0,
    expire_date TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    protocols TEXT DEFAULT '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]',
    note TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`);

  // جدول سرورها
  db.run(`CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    sni TEXT,
    status TEXT DEFAULT 'active'
  )`);

  // جدول ترافیک برای نمودار
  db.run(`CREATE TABLE IF NOT EXISTS traffic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    upload_mb REAL DEFAULT 0,
    download_mb REAL DEFAULT 0
  )`);

  // ادمین اصلی پیش‌فرض
  db.get("SELECT COUNT(*) as c FROM admins", (err, row) => {
    if (!err && row.c === 0) {
      db.run(`INSERT INTO admins (id, username, password, role, balance_gb, max_users) VALUES (?, ?, ?, ?, ?, ?)`,
        [uuidv4(), 'admin', 'admin123', 'superadmin', 999999, 999999]);
      console.log('✅ Super Admin created: admin / admin123');
    }
  });

  // سرور پیش‌فرض
  db.get("SELECT COUNT(*) as c FROM servers", (err, row) => {
    if (!err && row.c === 0) {
      db.run(`INSERT INTO servers (id, name, host, port, sni) VALUES (?, ?, ?, ?, ?)`,
        [uuidv4(), 'ONEX Core Server', 'server1.onexvpn.net', 443, 'server1.onexvpn.net']);
    }
  });
});

module.exports = db;
