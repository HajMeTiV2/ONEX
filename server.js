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
  secret: 'onex-secure-vault-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database('./onex_platform.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS configs (
      id TEXT PRIMARY KEY,
      name TEXT,
      server TEXT DEFAULT 'Germany (DE)',
      total_gb REAL DEFAULT 10,
      used_gb REAL DEFAULT 1.58,
      expire_days INTEGER DEFAULT 27,
      expire_date DATETIME,
      uuid TEXT UNIQUE,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // ایجاد کاربر پیش‌فرض و یک اکانت اولیه
  db.get('SELECT * FROM users WHERE username = ?', ['Mehtif'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('123456', 10);
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', ['Mehtif', hash]);
    }
  });

  db.get('SELECT COUNT(*) as count FROM configs', (err, r) => {
    if (r && r.count === 0) {
      const exp = new Date();
      exp.setDate(exp.getDate() + 27);
      db.run(`INSERT INTO configs (id, name, server, total_gb, used_gb, expire_days, expire_date, uuid) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        ['7f3a9e2d6c', 'کاربر نمونه', 'Germany (DE)', 10, 1.58, 27, exp.toISOString(), 'b831381d-6324-4d53-ad4f-8cda48b30811']);
    }
  });
});

// اجرای پایدار موتور Xray برای VLESS, VMess, Trojan
function runXrayMultiCore() {
  db.all('SELECT uuid FROM configs WHERE status = "active"', (err, rows) => {
    const defaultUuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const clientList = (rows && rows.length > 0) ? rows.map(r => ({ id: r.uuid })) : [{ id: defaultUuid }];
    const trojanList = (rows && rows.length > 0) ? rows.map(r => ({ password: r.uuid })) : [{ password: defaultUuid }];

    const xrayConfig = {
      log: { loglevel: "warning" },
      inbounds: [
        {
          port: 8081,
          listen: "127.0.0.1",
          protocol: "vless",
          settings: { clients: clientList, decryption: "none" },
          streamSettings: { network: "ws", wsSettings: { path: "/vless" } }
        },
        {
          port: 8082,
          listen: "127.0.0.1",
          protocol: "vmess",
          settings: { clients: clientList.map(c => ({ id: c.id, alterId: 0 })) },
          streamSettings: { network: "ws", wsSettings: { path: "/vmess" } }
        },
        {
          port: 8083,
          listen: "127.0.0.1",
          protocol: "trojan",
          settings: { clients: trojanList },
          streamSettings: { network: "ws", wsSettings: { path: "/trojan" } }
        }
      ],
      outbounds: [{ protocol: "freedom" }]
    };

    fs.writeFileSync('/app/xray_active.json', JSON.stringify(xrayConfig, null, 2));

    if (fs.existsSync('/app/xray-bin/xray')) {
      spawn('pkill', ['-f', 'xray']);
      setTimeout(() => {
        const p = spawn('/app/xray-bin/xray', ['run', '-c', '/app/xray_active.json']);
        p.stdout.on('data', d => console.log(`[XRAY]: ${d}`));
        p.stderr.on('data', d => console.error(`[XRAY ERR]: ${d}`));
      }, 500);
    }
  });
}

runXrayMultiCore();

// تولید کانفیگ‌های استاندارد
function generateProtocolLinks(cfg, host) {
  const remark = `ONEX-${cfg.name}`;
  const vless = `vless://${cfg.uuid}@${host}:443?path=%2Fvless&security=tls&encryption=none&type=ws&sni=${host}#${encodeURIComponent(remark + '-VLESS')}`;

  const vmessObj = {
    v: "2", ps: `${remark}-VMESS`, add: host, port: "443", id: cfg.uuid,
    aid: "0", scy: "auto", net: "ws", type: "none", host: host, path: "/vmess", tls: "tls", sni: host
  };
  const vmess = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;

  const trojan = `trojan://${cfg.uuid}@${host}:443?path=%2Ftrojan&security=tls&type=ws&sni=${host}#${encodeURIComponent(remark + '-Trojan')}`;

  return { vless, vmess, trojan, rawSub: `${vless}\n${vmess}\n${trojan}` };
}

function auth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

// مسیرهای صفحات وب
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
// قالب عکس دوم: مرورگر ساب لینک اختصاصی برای کلاینت
app.get('/subpage/:id', (req, res) => res.sendFile(path.join(__dirname, 'views', 'sub_client.html')));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      req.session.username = user.username;
      return res.json({ success: true });
    }
    res.status(401).json({ error: 'اطلاعات نامعتبر است' });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// دیتای پنل مدیریت (عکس اول)
app.get('/api/panel-data', auth, (req, res) => {
  db.all('SELECT * FROM configs ORDER BY created_at DESC', (err, rows) => {
    const totalAllocated = rows.reduce((a, b) => a + (b.total_gb || 0), 0);
    const totalUsed = rows.reduce((a, b) => a + (b.used_gb || 0), 0);
    res.json({
      configsCount: rows.length,
      totalAllocated,
      totalUsed: totalUsed.toFixed(2),
      configs: rows
    });
  });
});

// ساخت کانفیگ جدید در پنل
app.post('/api/configs/create', auth, (req, res) => {
  const { name, server, total_gb, expire_days } = req.body;
  const id = uuidv4().substring(0, 8);
  const uuid = uuidv4();
  const days = parseInt(expire_days) || 30;
  const exp = new Date();
  exp.setDate(exp.getDate() + days);

  db.run(
    `INSERT INTO configs (id, name, server, total_gb, expire_days, expire_date, uuid) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [id, name || 'کاربر جدید', server || 'Germany (DE)', parseFloat(total_gb) || 20, days, exp.toISOString(), uuid],
    function(err) {
      if (err) return res.status(500).json({ error: 'خطا در دیتابیس' });
      runXrayMultiCore();
      res.json({ success: true, id });
    }
  );
});

app.delete('/api/configs/:id', auth, (req, res) => {
  db.run('DELETE FROM configs WHERE id = ?', [req.params.id], () => {
    runXrayMultiCore();
    res.json({ success: true });
  });
});

// خروجی مستقیم بیس ۶۴ برای کلاینت‌های v2rayNG و...
app.get('/sub/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).send('Not Found');
    const links = generateProtocolLinks(cfg, host);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(Buffer.from(links.rawSub).toString('base64'));
  });
});

// API اطلاعات زنده مخصوص صفحه ساب لینک کلاینت (عکس دوم)
app.get('/api/subinfo/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).json({ error: 'یافت نشد' });
    const links = generateProtocolLinks(cfg, host);
    const remainingGb = Math.max(0, (cfg.total_gb - cfg.used_gb)).toFixed(2);
    const usagePercent = Math.min(100, Math.round((cfg.used_gb / cfg.total_gb) * 100));
    
    res.json({
      config: cfg,
      remainingGb,
      usagePercent,
      subUrl: `https://${host}/sub/${cfg.id}`,
      vless: links.vless,
      vmess: links.vmess,
      trojan: links.trojan
    });
  });
});

// هدایت وب‌سوکت‌ها به هسته‌های متناظر
const pVless = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8081', ws: true });
const pVmess = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8082', ws: true });
const pTrojan = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8083', ws: true });

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/vless')) pVless.ws(req, socket, head);
  else if (req.url.startsWith('/vmess')) pVmess.ws(req, socket, head);
  else if (req.url.startsWith('/trojan')) pTrojan.ws(req, socket, head);
});

server.listen(PORT, () => console.log(`ONEX Server running on port ${PORT}`));
