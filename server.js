const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: 'onex-secret-key-987654',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

// راه‌اندازی دیتابیس
const db = new sqlite3.Database('./onex_pro.db');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT,
      total_gb INTEGER,
      expire_days INTEGER,
      uuid TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // ایجاد کاربر ادمین پیش‌فرض (admin / admin123)
  db.get('SELECT * FROM admins WHERE username = ?', ['admin'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.run('INSERT INTO admins (username, password) VALUES (?, ?)', ['admin', hash]);
    }
  });
});

// میان‌افزار احراز هویت
function checkAuth(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  res.redirect('/login');
}

// تولید کانفیگ‌ها
function generateConfigs(user, host) {
  const remark = `ONEX-${user.username}`;
  
  const vmessObj = {
    v: "2", ps: remark, add: host, port: "443", id: user.uuid,
    aid: "0", scy: "auto", net: "ws", type: "none", host: host,
    path: "/vmess", tls: "tls", sni: host
  };
  const vmessUri = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;
  const vlessUri = `vless://${user.uuid}@${host}:443?type=ws&security=tls&path=%2Fvless&sni=${host}#${encodeURIComponent(remark + '-VLESS')}`;
  const trojanUri = `trojan://${user.uuid}@${host}:443?security=tls&type=ws&path=%2Ftrojan&sni=${host}#${encodeURIComponent(remark + '-Trojan')}`;
  const ssCreds = Buffer.from(`chacha20-ietf-poly1305:${user.uuid}`).toString('base64');
  const ssUri = `ss://${ssCreds}@${host}:443#${encodeURIComponent(remark + '-SS')}`;

  return { vmessUri, vlessUri, trojanUri, ssUri };
}

// مسیرهای لاگین و احراز هویت
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM admins WHERE username = ?', [username], (err, admin) => {
    if (admin && bcrypt.compareSync(password, admin.password)) {
      req.session.isAdmin = true;
      return res.json({ success: true });
    }
    res.status(401).json({ success: false, message: 'نام کاربری یا رمز عبور اشتباه است.' });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// داشبورد اصلی
app.get('/', checkAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// آمار داشبورد
app.get('/api/stats', checkAuth, (req, res) => {
  db.all('SELECT total_gb FROM users', [], (err, rows) => {
    const totalUsers = rows.length;
    const totalAllocatedGb = rows.reduce((acc, r) => acc + (r.total_gb || 0), 0);
    res.json({ totalUsers, totalAllocatedGb });
  });
});

// دریافت لیست کاربران
app.get('/api/users', checkAuth, (req, res) => {
  db.all('SELECT * FROM users ORDER BY created_at DESC', [], (err, rows) => {
    res.json(rows);
  });
});

// ساخت کانفیگ
app.post('/api/users', checkAuth, (req, res) => {
  const { username, total_gb, expire_days } = req.body;
  const id = uuidv4().substring(0, 8);
  const userUuid = uuidv4();

  db.run(
    'INSERT INTO users (id, username, total_gb, expire_days, uuid) VALUES (?, ?, ?, ?, ?)',
    [id, username, parseInt(total_gb) || 20, parseInt(expire_days) || 30, userUuid],
    () => res.json({ success: true })
  );
});

// حذف کاربر
app.delete('/api/users/:id', checkAuth, (req, res) => {
  db.run('DELETE FROM users WHERE id = ?', [req.params.id], () => {
    res.json({ success: true });
  });
});

// صفحه کلاینت و ساب‌اسکریپشن
app.get('/sub/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (!user) return res.status(404).send('اشتراک پیدا نشد');
    const cfgs = generateConfigs(user, host);
    const rawList = `${cfgs.vlessUri}\n${cfgs.vmessUri}\n${cfgs.trojanUri}\n${cfgs.ssUri}`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(Buffer.from(rawList).toString('base64'));
  });
});

app.get('/subpage/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'sub_page.html'));
});

app.get('/api/subinfo/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM users WHERE id = ?', [req.params.id], (err, user) => {
    if (!user) return res.status(404).json({ error: 'کاربر پیدا نشد' });
    const configs = generateConfigs(user, host);
    res.json({ user, configs, subUrl: `https://${host}/sub/${user.id}` });
  });
});

app.listen(PORT, () => console.log(`ONEX Running on port ${PORT}`));
