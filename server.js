const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// راه‌اندازی دیتابیس SQLite
const db = new sqlite3.Database('./onex.db');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT,
      total_gb INTEGER,
      used_gb REAL DEFAULT 0,
      uuid TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// تابع تولید انواع کانفیگ بر اساس دیتای سرور
function generateConfigs(user, host) {
  const remark = `ONEX-${user.username}`;
  
  // 1. VMess
  const vmessObj = {
    v: "2",
    ps: remark,
    add: host,
    port: "443",
    id: user.uuid,
    aid: "0",
    scy: "auto",
    net: "ws",
    type: "none",
    host: host,
    path: "/vmess",
    tls: "tls",
    sni: host
  };
  const vmessUri = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;

  // 2. VLESS
  const vlessUri = `vless://${user.uuid}@${host}:443?type=ws&security=tls&path=%2Fvless&sni=${host}#${encodeURIComponent(remark + '-Vless')}`;

  // 3. Trojan
  const trojanUri = `trojan://${user.uuid}@${host}:443?security=tls&type=ws&path=%2Ftrojan&sni=${host}#${encodeURIComponent(remark + '-Trojan')}`;

  // 4. Shadowsocks
  const ssCreds = Buffer.from(`chacha20-ietf-poly1305:${user.uuid}`).toString('base64');
  const ssUri = `ss://${ssCreds}@${host}:443#${encodeURIComponent(remark + '-SS')}`;

  return { vmessUri, vlessUri, trojanUri, ssUri };
}

// صفحه اصلی / داشبورد مدیریت
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// API دریافت لیست کاربران
app.get('/api/users', (req, res) => {
  db.all('SELECT * FROM users ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// ایجاد کاربر جدید
app.post('/api/users', (req, res) => {
  const { username, total_gb } = req.body;
  const id = uuidv4().substring(0, 8);
  const userUuid = uuidv4();

  db.run(
    'INSERT INTO users (id, username, total_gb, uuid) VALUES (?, ?, ?, ?)',
    [id, username || 'user', total_gb || 20, userUuid],
    function (err) {
      if (err) return res.status(500).send("خطا در ایجاد کاربر");
      res.redirect('/');
    }
  );
});

// حذف کاربر
app.get('/api/users/delete/:id', (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], (err) => {
    res.redirect('/');
  });
});

// لینک ساب‌اسکریپشن خام (مخصوص کلاینت‌ها مثل v2rayN / V2rayNG / Streisand)
app.get('/sub/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (err || !user) return res.status(404).send('کاربر یافت نشد');

    const cfgs = generateConfigs(user, host);
    const rawList = `${cfgs.vlessUri}\n${cfgs.vmessUri}\n${cfgs.trojanUri}\n${cfgs.ssUri}`;

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(Buffer.from(rawList).toString('base64'));
  });
});

// صفحه حرفه‌ای کاربر برای مشاهده و کپی لینک‌ها در مرورگر
app.get('/subpage/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'sub_page.html'));
});

// دیتای کانفیگ‌ها برای صفحه فرانت
app.get('/api/subinfo/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'کاربر پیدا نشد' });
    const configs = generateConfigs(user, host);
    res.json({ user, configs, subUrl: `https://${host}/sub/${user.id}` });
  });
});

app.listen(PORT, () => {
  console.log(`ONEX Panel is running on port ${PORT}`);
});
