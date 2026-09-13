const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const http = require('http');
const httpProxy = require('http-proxy');

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

// دیتابیس
const db = new sqlite3.Database('./onex_enterprise.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT,
      password TEXT,
      balance INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

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

  // کاربر پیش فرض
  db.get('SELECT * FROM users WHERE username = ?', ['Mehtif'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('123456', 10);
      db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', ['Mehtif', 'user@example.com', hash]);
    }
  });
});

// اجرای هسته پروکسی Xray در پس‌زمینه
function startXray() {
  const xrayConfig = {
    log: { loglevel: "warning" },
    inbounds: [
      {
        port: 8080,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: {
          clients: [
            { id: "b831381d-6324-4d53-ad4f-8cda48b30811" }
          ],
          decryption: "none"
        },
        streamSettings: {
          network: "ws",
          wsSettings: { path: "/vless" }
        }
      }
    ],
    outbounds: [{ protocol: "freedom" }]
  };

  fs.writeFileSync('/app/xray_run.json', JSON.stringify(xrayConfig, null, 2));

  if (fs.existsSync('/app/xray-bin/xray')) {
    const xrayProc = spawn('/app/xray-bin/xray', ['run', '-c', '/app/xray_run.json']);
    xrayProc.stdout.on('data', d => console.log(`[XRAY]: ${d}`));
    xrayProc.stderr.on('data', d => console.error(`[XRAY ERR]: ${d}`));
  }
}

startXray();

// تولید لینک استاندارد VLESS
function generateConfigs(cfg, host) {
  const remark = `ONEX-${cfg.name}`;
  const fixedUuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
  
  // لینک اتصال واقعی VLESS با مسیر وب‌سوکت
  const vlessUri = `vless://${fixedUuid}@${host}:443?path=%2Fvless&security=tls&encryption=none&type=ws&sni=${host}#${encodeURIComponent(remark)}`;
  return { vlessUri };
}

function auth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));

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
    if (err) return res.status(400).json({ error: 'نام کاربری تکراری است' });
    req.session.userId = this.lastID;
    req.session.username = username;
    res.json({ success: true });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.get('/api/dashboard', auth, (req, res) => {
  const uid = req.session.userId;
  db.get('SELECT * FROM users WHERE id = ?', [uid], (err, user) => {
    db.all('SELECT * FROM configs WHERE user_id = ? ORDER BY created_at DESC', [uid], (err, cfgs) => {
      const activeCount = cfgs.filter(c => c.status === 'active').length;
      const totalAllocated = cfgs.reduce((acc, c) => acc + (c.total_gb || 0), 0);
      const totalUsed = cfgs.reduce((acc, c) => acc + (c.used_gb || 0), 0);
      res.json({
        user: { username: user ? user.username : 'Mehtif', email: user ? user.email : '' },
        activeCount,
        totalAllocated,
        totalUsed: totalUsed.toFixed(1),
        configs: cfgs
      });
    });
  });
});

app.post('/api/configs', auth, (req, res) => {
  const uid = req.session.userId;
  const { name, protocol, server, total_gb, duration_days } = req.body;
  const id = uuidv4().substring(0, 8);
  const cfgUuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
  const days = parseInt(duration_days) || 30;
  const exp = new Date();
  exp.setDate(exp.getDate() + days);

  db.run(
    `INSERT INTO configs (id, user_id, name, protocol, server, total_gb, expire_days, expire_date, uuid)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, uid, name || 'Config', protocol || 'V2Ray', server || 'Germany (DE)', parseFloat(total_gb) || 30, days, exp.toISOString(), cfgUuid],
    function(err) {
      if (err) return res.status(500).json({ error: 'خطا در ثبت کانفیگ' });
      res.json({ success: true, id });
    }
  );
});

app.delete('/api/configs/:id', auth, (req, res) => {
  db.run('DELETE FROM configs WHERE id = ? AND user_id = ?', [req.params.id, req.session.userId], () => {
    res.json({ success: true });
  });
});

// ساب‌لینک برای v2rayNG
app.get('/sub/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).send('Not Found');
    const { vlessUri } = generateConfigs(cfg, host);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(Buffer.from(vlessUri).toString('base64'));
  });
});

// پروکسی مستقیم وب‌سوکت فیلترشکن به هسته Xray داخلی
const proxy = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8080', ws: true });
const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/vless')) {
    proxy.ws(req, socket, head);
  }
});

server.listen(PORT, () => {
  console.log(`ONEX Server with Xray running on port ${PORT}`);
});
