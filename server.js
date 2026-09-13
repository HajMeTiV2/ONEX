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
  secret: 'onex-zeus-core-token-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 14 * 24 * 60 * 60 * 1000 }
}));

const db = new sqlite3.Database('./onex_zeus.db');

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
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      uuid TEXT UNIQUE,
      total_gb REAL DEFAULT 30,
      used_gb REAL DEFAULT 0,
      duration_days INTEGER DEFAULT 30,
      expire_date DATETIME,
      requests_count INTEGER DEFAULT 0,
      online_users INTEGER DEFAULT 1,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // ایجاد کاربر ادمین و یک کلاینت پیش‌فرض
  db.get('SELECT * FROM users WHERE username = ?', ['Mehtif'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('123456', 10);
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', ['Mehtif', hash]);
    }
  });

  db.get('SELECT COUNT(*) as count FROM clients', (err, r) => {
    if (r && r.count === 0) {
      const exp = new Date();
      exp.setDate(exp.getDate() + 30);
      db.run(`INSERT INTO clients (id, username, uuid, total_gb, used_gb, duration_days, expire_date, requests_count) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
              ['ONEX-DEMO', 'ONEX-USER-01', 'b831381d-6324-4d53-ad4f-8cda48b30811', 30, 2.4, 30, exp.toISOString(), 1420]);
    }
  });
});

// بازسازی و اجرای کانفیگ جامع هسته Xray برای ۳ پروتکل واقعی
function startXrayMultiCore() {
  db.all('SELECT uuid FROM clients WHERE status = "active"', (err, rows) => {
    const defaultUuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const clientList = (rows && rows.length > 0) ? rows.map(r => ({ id: r.uuid })) : [{ id: defaultUuid }];
    const trojanList = (rows && rows.length > 0) ? rows.map(r => ({ password: r.uuid })) : [{ password: defaultUuid }];

    const xrayConfig = {
      log: { loglevel: "warning" },
      inbounds: [
        // 1. VLESS WS
        {
          port: 8081,
          listen: "127.0.0.1",
          protocol: "vless",
          settings: { clients: clientList, decryption: "none" },
          streamSettings: { network: "ws", wsSettings: { path: "/vless" } }
        },
        // 2. VMESS WS
        {
          port: 8082,
          listen: "127.0.0.1",
          protocol: "vmess",
          settings: { clients: clientList.map(c => ({ id: c.id, alterId: 0 })) },
          streamSettings: { network: "ws", wsSettings: { path: "/vmess" } }
        },
        // 3. TROJAN WS
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

    fs.writeFileSync('/app/xray_multi.json', JSON.stringify(xrayConfig, null, 2));

    if (fs.existsSync('/app/xray-bin/xray')) {
      spawn('pkill', ['-f', 'xray']); // ریستارت در صورت وجود نمونه قبلی
      setTimeout(() => {
        const proc = spawn('/app/xray-bin/xray', ['run', '-c', '/app/xray_multi.json']);
        proc.stdout.on('data', d => console.log(`[XRAY]: ${d}`));
        proc.stderr.on('data', d => console.error(`[XRAY ERR]: ${d}`));
      }, 500);
    }
  });
}

startXrayMultiCore();

// تولید تمام فرمت‌های پروتکل‌ها
function makeClientLinks(client, host) {
  const remark = `ONEX-${client.username}`;
  
  // VLESS WebSocket TLS
  const vless = `vless://${client.uuid}@${host}:443?path=%2Fvless&security=tls&encryption=none&type=ws&sni=${host}#${encodeURIComponent(remark + '-VLESS')}`;

  // VMess WebSocket TLS
  const vmessObj = {
    v: "2", ps: `${remark}-VMESS`, add: host, port: "443", id: client.uuid,
    aid: "0", scy: "auto", net: "ws", type: "none", host: host, path: "/vmess", tls: "tls", sni: host
  };
  const vmess = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;

  // Trojan WebSocket TLS
  const trojan = `trojan://${client.uuid}@${host}:443?path=%2Ftrojan&security=tls&type=ws&sni=${host}#${encodeURIComponent(remark + '-Trojan')}`;

  return { vless, vmess, trojan, rawSub: `${vless}\n${vmess}\n${trojan}` };
}

function auth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      req.session.username = user.username;
      return res.json({ success: true });
    }
    res.status(401).json({ error: 'نام کاربری یا رمز عبور نامعتبر است' });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// آمار کلی سیستم مانند Zeus Panel
app.get('/api/panel-stats', auth, (req, res) => {
  db.all('SELECT * FROM clients ORDER BY created_at DESC', (err, rows) => {
    const totalUsers = rows.length;
    const activeUsers = rows.filter(r => r.status === 'active').length;
    const totalTrafficUsed = rows.reduce((s, r) => s + (r.used_gb || 0), 0);
    const totalRequests = rows.reduce((s, r) => s + (r.requests_count || 0), 0);

    res.json({
      totalUsers,
      activeUsers,
      totalTrafficUsed: totalTrafficUsed.toFixed(2),
      totalRequests,
      clients: rows
    });
  });
});

// ساخت کاربر/کانفیگ جدید در پنل
app.post('/api/clients/add', auth, (req, res) => {
  const { username, total_gb, duration_days } = req.body;
  const id = 'ONEX-' + Math.random().toString(36).substring(2, 7).toUpperCase();
  const uuid = uuidv4();
  const days = parseInt(duration_days) || 30;
  const exp = new Date();
  exp.setDate(exp.getDate() + days);

  db.run(
    `INSERT INTO clients (id, username, uuid, total_gb, duration_days, expire_date) VALUES (?, ?, ?, ?, ?, ?)`,
    [id, username || id, uuid, parseFloat(total_gb) || 30, days, exp.toISOString()],
    function(err) {
      if (err) return res.status(400).json({ error: 'نام کاربری تکراری است.' });
      startXrayMultiCore(); // ریلود لایو هسته Xray
      res.json({ success: true, id, uuid });
    }
  );
});

// حذف کاربر
app.delete('/api/clients/:id', auth, (req, res) => {
  db.run('DELETE FROM clients WHERE id = ?', [req.params.id], () => {
    startXrayMultiCore();
    res.json({ success: true });
  });
});

// ساب‌اسکریپشن کامل کاربر
app.get('/sub/:id', (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM clients WHERE id = ? OR username = ?', [req.params.id, req.params.id], (err, client) => {
    if (!client) return res.status(404).send('Client Not Found');
    const links = makeClientLinks(client, host);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(Buffer.from(links.rawSub).toString('base64'));
  });
});

// دریافت تک‌لینک‌های کانفیگ
app.get('/api/client-links/:id', auth, (req, res) => {
  const host = req.headers.host;
  db.get('SELECT * FROM clients WHERE id = ?', [req.params.id], (err, client) => {
    if (!client) return res.status(404).json({ error: 'Not Found' });
    const links = makeClientLinks(client, host);
    res.json({ ...links, subUrl: `https://${host}/sub/${client.id}` });
  });
});

// سوئیچ ترافیک ورودی وب‌سوکت به هسته‌های Xray
const proxyVless = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8081', ws: true });
const proxyVmess = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8082', ws: true });
const proxyTrojan = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8083', ws: true });

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/vless')) {
    proxyVless.ws(req, socket, head);
  } else if (req.url.startsWith('/vmess')) {
    proxyVmess.ws(req, socket, head);
  } else if (req.url.startsWith('/trojan')) {
    proxyTrojan.ws(req, socket, head);
  }
});

server.listen(PORT, () => {
  console.log(`ONEX Zeus Engine running on port ${PORT}`);
});
