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
  secret: 'onex-enterprise-token-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database('./onex_enterprise.db');

db.serialize(() => {
  // کاربران و اعتبار
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      phone TEXT,
      password TEXT,
      balance INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // کانفیگ‌ها و اشتراک‌ها
  db.run(`
    CREATE TABLE IF NOT EXISTS configs (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      name TEXT,
      protocol TEXT,
      server TEXT,
      total_gb REAL,
      used_gb REAL DEFAULT 0,
      expire_days INTEGER,
      expire_date DATETIME,
      uuid TEXT,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // تراکنش‌ها
  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      title TEXT,
      type TEXT,
      amount TEXT,
      status TEXT DEFAULT 'success',
      date TEXT
    )
  `);

  // کاربر پیش‌فرض دمو
  db.get('SELECT * FROM users WHERE username = ?', ['Mehtif'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('123456', 10);
      db.run('INSERT INTO users (username, email, phone, password, balance) VALUES (?, ?, ?, ?, ?)',
        ['Mehtif', 'user@example.com', '09120000000', hash, 50000]);
    }
  });
});

function auth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

function generateConfigs(cfg, host) {
  const remark = `ONEX-${cfg.name}`;
  const vmessObj = {
    v: "2", ps: remark, add: host, port: "443", id: cfg.uuid,
    aid: "0", scy: "auto", net: "ws", type: "none", host: host,
    path: "/vmess", tls: "tls", sni: host
  };
  const vmessUri = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;
  const vlessUri = `vless://${cfg.uuid}@${host}:443?type=ws&security=tls&path=%2Fvless&sni=${host}#${encodeURIComponent(remark)}`;
  const trojanUri = `trojan://${cfg.uuid}@${host}:443?security=tls&type=ws&path=%2Ftrojan&sni=${host}#${encodeURIComponent(remark)}`;
  const ssCreds = Buffer.from(`chacha20-ietf-poly1305:${cfg.uuid}`).toString('base64');
  const ssUri = `ss://${ssCreds}@${host}:443#${encodeURIComponent(remark)}`;
  return { vmessUri, vlessUri, trojanUri, ssUri };
}

// صفحات وب
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));

// API احراز هویت
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, username], (err, user) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      req.session.username = user.username;
      return res.json({ success: true });
    }
    res.status(401).json({ error: 'اطلاعات ورود نامعتبر است' });
  });
});

app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], function(err) {
    if (err) return res.status(400).json({ error: 'نام کاربری یا ایمیل تکراری است' });
    req.session.userId = this.lastID;
    req.session.username = username;
    res.json({ success: true });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// API اطلاعات داشبورد
app.get('/api/dashboard', auth, (req, res) => {
  const uid = req.session.userId;
  db.get('SELECT * FROM users WHERE id = ?', [uid], (err, user) => {
    db.all('SELECT * FROM configs WHERE user_id = ? ORDER BY created_at DESC', [uid], (err, cfgs) => {
      const activeCount = cfgs.filter(c => c.status === 'active').length;
      const totalAllocated = cfgs.reduce((acc, c) => acc + (c.total_gb || 0), 0);
      const totalUsed = cfgs.reduce((acc, c) => acc + (c.used_gb || 0), 0);
      res.json({
        user: { username: user.username, email: user.email, balance: user.balance },
        activeCount,
        totalAllocated,
        totalUsed: totalUsed.toFixed(1),
        configs: cfgs
      });
    });
  });
});

// ساخت کانفیگ
app.post('/api/configs', auth, (req, res) => {
  const uid = req.session.userId;
  const { name, protocol, server, total_gb, duration_days } = req.body;
  const id = uuidv4().substring(0, 8);
  const cfgUuid = uuidv4();
  const days = parseInt(duration_days) || 30;
  const exp = new Date();
  exp.setDate(exp.getDate() + days);

  db.run(
    `INSERT INTO configs (id, user_id, name, protocol, server, total_gb, expire_days, expire_date, uuid)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, uid, name || 'Config', protocol || 'V2Ray', server || 'Germany (DE)', parseFloat(total_gb) || 20, days, exp.toISOString(), cfgUuid],
    function(err) {
      if (err) return res.status(500).json({ error: 'خطا در ثبت کانفیگ' });
      res.json({ success: true, id });
    }
  );
});

// حذف کانفیگ
app.delete('/api/configs/:id', auth, (req, res) => {
  db.run('DELETE FROM configs WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], () => {
    res.json({ success: true });
  });
});

// لینک ساب کلاینت خام
app.get('/sub/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).send('Config not found');
    const cfgs = generateConfigs(cfg, host);
    const raw = `${cfgs.vlessUri}\n${cfgs.vmessUri}\n${cfgs.trojanUri}\n${cfgs.ssUri}`;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(Buffer.from(raw).toString('base64'));
  });
});

app.listen(PORT, () => console.log(`ONEX Server running on port ${PORT}`));
