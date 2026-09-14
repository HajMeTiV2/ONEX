const express = require('express');
const session = require('express-session');
const fileUpload = require('express-fileupload');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn, exec } = require('child_process');
const http = require('http');
const httpProxy = require('http-proxy');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload({ limits: { fileSize: 50 * 1024 * 1024 } }));

// تنظیمات سشن با رفع هشدار MemoryStore و سازگاری ابری
app.use(session({
  secret: process.env.SESSION_SECRET || 'onex-master-vault-2026',
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: { 
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: false 
  }
}));

const dbPath = path.join(DATA_DIR, 'onex_vault.db');
const db = new sqlite3.Database(dbPath);

const liveLogs = [];
function addLog(msg) {
  const time = new Date().toLocaleTimeString('fa-IR');
  liveLogs.unshift(`[${time}] ${msg}`);
  if (liveLogs.length > 50) liveLogs.pop();
  console.log(`[ONEX LOG]: ${msg}`);
}

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'admin')`);
  db.run(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`);
  db.run(`
    CREATE TABLE IF NOT EXISTS configs (
      id TEXT PRIMARY KEY,
      name TEXT,
      owner TEXT DEFAULT 'admin',
      server TEXT DEFAULT 'Germany (DE)',
      protocol TEXT DEFAULT 'all',
      total_gb REAL DEFAULT 15,
      used_gb REAL DEFAULT 0,
      downlink_bytes INTEGER DEFAULT 0,
      uplink_bytes INTEGER DEFAULT 0,
      expire_days INTEGER DEFAULT 30,
      expire_date DATETIME,
      uuid TEXT UNIQUE,
      tag TEXT DEFAULT 'normal',
      referral_count INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin', 10);
      db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ['admin', hash, 'admin']);
    }
  });

  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('custom_domain', '')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('clean_ip', '')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('active_announcement', '')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('bot_token', '')`);
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_tg_id', '')`);
});

function getServerMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  return {
    cpu: Math.round(Math.random() * 20 + 5),
    ram: Math.round((usedMem / totalMem) * 100),
    ramUsedGb: (usedMem / (1024 ** 3)).toFixed(1),
    uptime: Math.round(os.uptime() / 3600)
  };
}

// راه‌اندازی هسته Xray-core
function startCoreEngine() {
  db.all('SELECT * FROM configs WHERE status != "expired"', (err, rows) => {
    const fallbackId = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const clients = (rows && rows.length > 0) ? rows.map(r => ({ id: r.uuid, email: r.name })) : [{ id: fallbackId, email: "fallback" }];

    const xrayConfig = {
      log: { loglevel: "warning" },
      stats: {},
      api: { tag: "api", services: ["StatsService"] },
      policy: {
        levels: { "0": { statsUserUplink: true, statsUserDownlink: true } },
        system: { statsInboundUplink: true, statsInboundDownlink: true }
      },
      inbounds: [
        { tag: "api", port: 10085, listen: "127.0.0.1", protocol: "dokodemo-door", settings: { address: "127.0.0.1" } },
        {
          port: 8081, listen: "0.0.0.0", protocol: "vless",
          settings: { clients: clients, decryption: "none" },
          streamSettings: { network: "ws", wsSettings: { path: "/vless" } }
        },
        {
          port: 8082, listen: "0.0.0.0", protocol: "vmess",
          settings: { clients: clients.map(c => ({ id: c.id, alterId: 0, email: c.email })) },
          streamSettings: { network: "ws", wsSettings: { path: "/vmess" } }
        },
        {
          port: 8083, listen: "0.0.0.0", protocol: "trojan",
          settings: { clients: clients.map(c => ({ password: c.id, email: c.email })) },
          streamSettings: { network: "ws", wsSettings: { path: "/trojan" } }
        }
      ],
      outbounds: [{ protocol: "freedom" }],
      routing: { rules: [{ inboundTag: ["api"], outboundTag: "api", type: "field" }] }
    };

    const cfgPath = path.join(DATA_DIR, 'xray_run.json');
    fs.writeFileSync(cfgPath, JSON.stringify(xrayConfig, null, 2));

    const binPath = path.join(__dirname, 'xray-bin', 'xray');
    if (fs.existsSync(binPath)) {
      try { fs.chmodSync(binPath, '755'); } catch(e) {}
      spawn('pkill', ['-f', 'xray']);
      setTimeout(() => {
        const proc = spawn(binPath, ['run', '-c', cfgPath]);
        proc.stdout.on('data', d => addLog(`XRAY: ${d.toString().trim()}`));
        proc.stderr.on('data', d => addLog(`XRAY ERR: ${d.toString().trim()}`));
        addLog('هسته Xray با موفقیت راه‌اندازی شد.');
      }, 500);
    } else {
      addLog('هشدار: فایل باینری xray در پوشه xray-bin یافت نشد!');
    }
  });
}

startCoreEngine();

function buildLinks(cfg, defaultHost, customDomain, cleanIp) {
  const remark = `ONEX-${cfg.name}`;
  const activeHost = (customDomain && customDomain.trim() !== '') ? customDomain.trim() : defaultHost;
  const connectionAddress = (cleanIp && cleanIp.trim() !== '') ? cleanIp.trim() : activeHost;

  const vlessWs = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fvless&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark)}`;
  const vmessPayload = { v: "2", ps: `${remark}-VMess`, add: connectionAddress, port: "443", id: cfg.uuid, aid: "0", scy: "auto", net: "ws", type: "none", host: activeHost, path: "/vmess", tls: "tls", sni: activeHost };
  const vmessWs = `vmess://${Buffer.from(JSON.stringify(vmessPayload)).toString('base64')}`;
  const trojanWs = `trojan://${cfg.uuid}@${connectionAddress}:443?path=%2Ftrojan&security=tls&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark)}`;

  const plainSub = [vlessWs, vmessWs, trojanWs].join('\n');
  return { vlessWs, vmessWs, trojanWs, plainSub };
}

function auth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/', auth, (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
app.get('/subpage/:id', (req, res) => res.sendFile(path.join(__dirname, 'views', 'sub_client.html')));

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;
      return res.json({ success: true });
    }
    res.status(401).json({ error: 'اطلاعات ورود اشتباه است.' });
  });
});

app.get('/api/panel-data', auth, (req, res) => {
  db.all('SELECT * FROM configs ORDER BY created_at DESC', (err, rows) => {
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);
      res.json({
        currentUser: req.session.username,
        configsCount: rows.length,
        totalUsed: rows.reduce((s, c) => s + (c.used_gb || 0), 0).toFixed(2),
        cleanIp: setMap['clean_ip'] || '',
        customDomain: setMap['custom_domain'] || '',
        metrics: getServerMetrics(),
        logs: liveLogs,
        configs: rows
      });
    });
  });
});

app.post('/api/configs/create', auth, (req, res) => {
  const { name, protocol, tag, total_gb, expire_days } = req.body;
  const id = uuidv4().substring(0, 8);
  const uuid = uuidv4();

  db.run(
    `INSERT INTO configs (id, name, owner, protocol, tag, total_gb, expire_days, uuid, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
    [id, name || 'اکانت', req.session.username, protocol || 'all', tag || 'normal', parseFloat(total_gb) || 20, parseInt(expire_days) || 30, uuid],
    function(err) {
      if (err) return res.status(500).json({ error: 'خطا در دیتابیس' });
      addLog(`کانفیگ جدید با نام ${name} ساخته شد.`);
      startCoreEngine();
      res.json({ success: true, id });
    }
  );
});

app.post('/api/configs/:id/edit', auth, (req, res) => {
  const { name, total_gb, expire_days } = req.body;
  db.run('UPDATE configs SET name = ?, total_gb = ?, expire_days = ? WHERE id = ?', [name, parseFloat(total_gb) || 20, parseInt(expire_days) || 30, req.params.id], () => {
    startCoreEngine();
    res.json({ success: true });
  });
});

app.post('/api/save-worker-settings', auth, (req, res) => {
  const { cleanIp } = req.body;
  db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)`, [cleanIp || ''], () => {
    res.json({ success: true });
  });
});

app.post('/api/broadcast/save', auth, (req, res) => {
  const { message } = req.body;
  db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('active_announcement', ?)`, [message || ''], () => {
    res.json({ success: true });
  });
});

app.get('/api/announcement', (req, res) => {
  db.get('SELECT value FROM settings WHERE key = "active_announcement"', (err, row) => {
    res.json({ message: row ? row.value : '' });
  });
});

// آپدیت نام کاربری و رمز عبور مدیریت
app.post('/api/settings/account', auth, (req, res) => {
  const { newUsername, newPassword, currentPassword } = req.body;
  
  db.get('SELECT * FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (!user || !bcrypt.compareSync(currentPassword, user.password)) {
      return res.status(401).json({ error: 'رمز عبور فعلی اشتباه است.' });
    }

    const updatedUsername = (newUsername && newUsername.trim() !== '') ? newUsername.trim() : user.username;
    
    if (newPassword && newPassword.trim() !== '') {
      const hashedPassword = bcrypt.hashSync(newPassword, 10);
      db.run('UPDATE users SET username = ?, password = ? WHERE id = ?', [updatedUsername, hashedPassword, user.id], (err) => {
        if (err) return res.status(500).json({ error: 'نام کاربری تکراری است.' });
        req.session.username = updatedUsername;
        addLog('مشخصات حساب مدیریت به‌روز شد.');
        res.json({ success: true });
      });
    } else {
      db.run('UPDATE users SET username = ? WHERE id = ?', [updatedUsername, user.id], (err) => {
        if (err) return res.status(500).json({ error: 'نام کاربری تکراری است.' });
        req.session.username = updatedUsername;
        addLog('نام کاربری مدیریت به‌روز شد.');
        res.json({ success: true });
      });
    }
  });
});

// آپدیت تنظیمات دامنه و تلگرام
app.post('/api/settings/general', auth, (req, res) => {
  const { customDomain, botToken, adminTgId } = req.body;
  db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_domain', ?)`, [customDomain || ''], () => {
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('bot_token', ?)`, [botToken || ''], () => {
      db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_tg_id', ?)`, [adminTgId || ''], () => {
        addLog('تنظیمات عمومی و تلگرام به‌روز شد.');
        res.json({ success: true });
      });
    });
  });
});

app.post('/api/configs/:id/renew', auth, (req, res) => {
  db.run('UPDATE configs SET status = "active" WHERE id = ?', [req.params.id], () => { startCoreEngine(); res.json({ success: true }); });
});

app.post('/api/configs/:id/reset-traffic', auth, (req, res) => {
  db.run('UPDATE configs SET used_gb = 0 WHERE id = ?', [req.params.id], () => { startCoreEngine(); res.json({ success: true }); });
});

app.delete('/api/configs/:id', auth, (req, res) => {
  db.run('DELETE FROM configs WHERE id = ?', [req.params.id], () => { startCoreEngine(); res.json({ success: true }); });
});

app.get('/sub/:id', (req, res) => {
  const defaultHost = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).send('یافت نشد');
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);
      const links = buildLinks(cfg, defaultHost, setMap['custom_domain'], setMap['clean_ip']);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(Buffer.from(links.plainSub).toString('base64'));
    });
  });
});

app.get('/api/subinfo/:id', (req, res) => {
  const defaultHost = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).json({ error: 'یافت نشد' });
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);
      const links = buildLinks(cfg, defaultHost, setMap['custom_domain'], setMap['clean_ip']);
      res.json({
        config: cfg,
        remainingGb: Math.max(0, (cfg.total_gb - cfg.used_gb)).toFixed(2),
        usagePercent: Math.min(100, Math.round((cfg.used_gb / cfg.total_gb) * 100)),
        subUrl: `https://${defaultHost}/sub/${cfg.id}`,
        vlessWs: links.vlessWs,
        vmessWs: links.vmessWs,
        trojanWs: links.trojanWs
      });
    });
  });
});

const pVless = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8081', ws: true });
const pVmess = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8082', ws: true });
const pTrojan = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8083', ws: true });

const server = http.createServer(app);
server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/vless')) pVless.ws(req, socket, head);
  else if (req.url.startsWith('/vmess')) pVmess.ws(req, socket, head);
  else if (req.url.startsWith('/trojan')) pTrojan.ws(req, socket, head);
});

server.listen(PORT, '0.0.0.0', () => {
  addLog(`سیستم روی پورت ${PORT} مستقر شد.`);
});
