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
const { WebSocketServer } = require('ws');
const httpProxy = require('http-proxy');

const app = express();
const server = http.createServer(app);
const proxy = httpProxy.createProxyServer({ ws: true });

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// راه‌اندازی پروکسی وب‌سکت برای اتصال کلاینت‌ها به هسته داخلی Xray جهت برقراری پینگ
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const urlPath = req.url || '';
  let targetPort = 8081; // پورت پیش‌فرض VLESS-WS
  
  if (urlPath.includes('vmess')) targetPort = 8082;
  else if (urlPath.includes('trojan')) targetPort = 8083;
  else if (urlPath.includes('xhttp')) targetPort = 8084;
  else if (urlPath.includes('grpc')) targetPort = 8085;

  proxy.ws(req, ws, { target: `ws://127.0.0.1:${targetPort}` }, (err) => {
    if (err) {
      ws.close();
    }
  });
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(fileUpload({ limits: { fileSize: 50 * 1024 * 1024 } }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'onex-master-vault-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

const dbPath = path.join(DATA_DIR, 'onex_vault.db');
const db = new sqlite3.Database(dbPath);

const liveLogs = [];
function addLog(msg) {
  const time = new Date().toLocaleTimeString('fa-IR');
  liveLogs.unshift(`[${time}] ${msg}`);
  if (liveLogs.length > 100) liveLogs.pop();
}

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'admin',
      credit_gb REAL DEFAULT 1000,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

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
      referred_by TEXT,
      referral_count INTEGER DEFAULT 0,
      ip_limit INTEGER DEFAULT 2,
      status TEXT DEFAULT 'pending',
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
});

function getServerMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memPercent = Math.round((usedMem / totalMem) * 100);
  const cpus = os.cpus();
  let user = 0, sys = 0, idle = 0;
  for (const cpu of cpus) {
    user += cpu.times.user;
    sys += cpu.times.sys;
    idle += cpu.times.idle;
  }
  const total = user + sys + idle;
  const cpuPercent = total > 0 ? Math.round(((total - idle) / total) * 100) : 0;
  return { cpu: cpuPercent, ram: memPercent, uptime: Math.round(os.uptime() / 3600) };
}

function startCoreEngine() {
  db.all('SELECT * FROM configs WHERE status != "expired"', (err, rows) => {
    const fallbackId = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const vClients = (rows && rows.length > 0) ? rows.map(r => ({ id: r.uuid, email: r.uuid })) : [{ id: fallbackId, email: fallbackId }];
    const tClients = (rows && rows.length > 0) ? rows.map(r => ({ password: r.uuid, email: r.uuid })) : [{ password: fallbackId, email: fallbackId }];

    const inbounds = [
      { tag: "api", port: 10085, listen: "127.0.0.1", protocol: "dokodemo-door", settings: { address: "127.0.0.1" } },
      { port: 8081, listen: "127.0.0.1", protocol: "vless", settings: { clients: vClients, decryption: "none" }, streamSettings: { network: "ws", wsSettings: { path: "/vless" } } },
      { port: 8082, listen: "127.0.0.1", protocol: "vmess", settings: { clients: vClients.map(c => ({ id: c.id, alterId: 0, email: c.email })) }, streamSettings: { network: "ws", wsSettings: { path: "/vmess" } } },
      { port: 8083, listen: "127.0.0.1", protocol: "trojan", settings: { clients: tClients }, streamSettings: { network: "ws", wsSettings: { path: "/trojan" } } },
      { port: 8084, listen: "127.0.0.1", protocol: "vless", settings: { clients: vClients, decryption: "none" }, streamSettings: { network: "ws", wsSettings: { path: "/xhttp" } } },
      { port: 8085, listen: "127.0.0.1", protocol: "vless", settings: { clients: vClients, decryption: "none" }, streamSettings: { network: "ws", wsSettings: { path: "/grpc" } } }
    ];

    const xrayConfig = {
      log: { loglevel: "error" },
      stats: {},
      api: { tag: "api", services: ["StatsService"] },
      policy: { levels: { "0": { statsUserUplink: true, statsUserDownlink: true } }, system: { statsInboundUplink: true, statsInboundDownlink: true } },
      inbounds: inbounds,
      outbounds: [{ protocol: "freedom" }],
      routing: { rules: [{ inboundTag: ["api"], outboundTag: "api", type: "field" }] }
    };

    const cfgPath = path.join(DATA_DIR, 'xray_run.json');
    fs.writeFileSync(cfgPath, JSON.stringify(xrayConfig, null, 2));

    const binPath = path.join(__dirname, 'xray-bin', 'xray');
    if (fs.existsSync(binPath)) {
      spawn('pkill', ['-f', 'xray']);
      setTimeout(() => {
        const proc = spawn(binPath, ['run', '-c', cfgPath]);
        proc.stdout.on('data', d => process.stdout.write(`[XRAY]: ${d}`));
      }, 400);
    }
  });
}

function syncUserTrafficFromCore() {
  const binPath = path.join(__dirname, 'xray-bin', 'xray');
  if (!fs.existsSync(binPath)) return;
  exec(`${binPath} api statsquery -server 127.0.0.1:10085 -reset true`, (error, stdout) => {
    if (error || !stdout) return;
    try {
      const statsObj = JSON.parse(stdout);
      if (!statsObj.stat || !Array.isArray(statsObj.stat)) return;
      statsObj.stat.forEach(item => {
        const parts = item.name.split('>>>');
        if (parts[0] === 'user' && parts[2] === 'traffic') {
          const uuid = parts[1];
          const direction = parts[3];
          const bytes = parseInt(item.value, 10) || 0;
          if (bytes > 0) {
            const addedGb = bytes / (1024 * 1024 * 1024);
            const column = direction === 'downlink' ? 'downlink_bytes' : 'uplink_bytes';
            db.get('SELECT id, status, expire_days FROM configs WHERE uuid = ?', [uuid], (err, cfg) => {
              if (cfg) {
                if (cfg.status === 'pending') {
                  const exp = new Date();
                  exp.setDate(exp.getDate() + cfg.expire_days);
                  db.run('UPDATE configs SET status = "active", expire_date = ? WHERE id = ?', [exp.toISOString(), cfg.id]);
                }
                db.run(`UPDATE configs SET used_gb = used_gb + ?, ${column} = ${column} + ? WHERE uuid = ?`, [addedGb, bytes, uuid]);
              }
            });
          }
        }
      });
    } catch (e) {}
  });
}

setInterval(syncUserTrafficFromCore, 10000);
startCoreEngine();

// ساخت لینک‌های کامل با دامنه رایلی و تگ اختصاصی شما
function buildLinks(cfg, defaultHost, customDomain, cleanIp) {
  const remark = `NEXO-${cfg.name} | @V2rayTun0`;
  const activeHost = (customDomain && customDomain.trim() !== '') ? customDomain.trim() : defaultHost;
  const connectionAddress = (cleanIp && cleanIp.trim() !== '') ? cleanIp.trim() : activeHost;

  const vlessWs = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fvless&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark)}`;
  const vmessPayload = { v: "2", ps: `${remark}-VMess`, add: connectionAddress, port: "443", id: cfg.uuid, aid: "0", scy: "auto", net: "ws", type: "none", host: activeHost, path: "/vmess", tls: "tls", sni: activeHost };
  const vmessWs = `vmess://${Buffer.from(JSON.stringify(vmessPayload)).toString('base64')}`;
  const trojanWs = `trojan://${cfg.uuid}@${connectionAddress}:443?path=%2Ftrojan&security=tls&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark)}`;
  const vlessXhttp = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fxhttp&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark)}`;
  const vlessGrpc = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fgrpc&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark)}`;

  const plainSub = [vlessWs, vmessWs, trojanWs, vlessXhttp, vlessGrpc].join('\n');
  return { plainSub };
}

function auth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

app.use(express.static(path.join(__dirname, 'views')));
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
        customDomain: setMap['custom_domain'] || '',
        cleanIp: setMap['clean_ip'] || '',
        metrics: getServerMetrics(),
        logs: liveLogs,
        configs: rows
      });
    });
  });
});

app.post('/api/configs/create', auth, (req, res) => {
  const { name, server, protocol, tag, total_gb, expire_days } = req.body;
  const id = uuidv4().substring(0, 8);
  const uuid = uuidv4();
  const gb = parseFloat(total_gb) || 20;

  db.run(
    `INSERT INTO configs (id, name, owner, server, protocol, tag, total_gb, expire_days, uuid, status) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
    [id, name || 'اکانت', req.session.username, server || 'Germany', protocol || 'all', tag || 'normal', gb, parseInt(expire_days) || 30, uuid],
    function(err) {
      if (err) return res.status(500).json({ error: 'خطا در ساخت کانفیگ' });
      startCoreEngine();
      addLog(`کانفیگ جدید با نام "${name || 'اکانت'}" و حجم ${gb}GB ساخته شد.`);
      res.json({ success: true, id });
    }
  );
});

app.post('/api/configs/:id/edit', auth, (req, res) => {
  const { name, total_gb, expire_days } = req.body;
  db.run('UPDATE configs SET name = ?, total_gb = ?, expire_days = ? WHERE id = ?', [name, parseFloat(total_gb), parseInt(expire_days), req.params.id], () => {
    addLog(`کانفیگ ${req.params.id} ویرایش شد.`);
    res.json({ success: true });
  });
});

app.post('/api/save-worker-settings', auth, (req, res) => {
  const { cleanIp } = req.body;
  db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)`, [cleanIp || ''], () => {
    addLog(`آی‌پی تمیز ذخیره شد: ${cleanIp}`);
    res.json({ success: true });
  });
});

app.get('/api/announcement', (req, res) => {
  db.get('SELECT value FROM settings WHERE key = "active_announcement"', (err, row) => {
    res.json({ message: row ? row.value : '' });
  });
});

app.get('/api/subinfo/:id', (req, res) => {
  const queryId = req.params.id;
  db.get('SELECT * FROM configs WHERE id = ? OR uuid = ?', [queryId, queryId], (err, cfg) => {
    if (!cfg) return res.status(404).json({ error: 'Config not found' });
    
    const total = cfg.total_gb || 20;
    const used = cfg.used_gb || 0;
    const remaining = Math.max(0, total - used).toFixed(2);
    const percent = Math.min(100, Math.round((used / total) * 100));
    const proto = req.protocol || 'https';
    const host = req.get('host');

    res.json({
      config: cfg,
      usagePercent: percent,
      remainingGb: remaining,
      subUrl: `${proto}://${host}/sub/${cfg.id}`
    });
  });
});

app.get('/api/subscription/:id/json', (req, res) => {
  const queryId = req.params.id;
  db.get('SELECT * FROM configs WHERE id = ? OR uuid = ?', [queryId, queryId], (err, cfg) => {
    if (!cfg) return res.status(404).json({ success: false, error: 'Config not found' });
    res.json({ success: true, data: cfg });
  });
});

app.get('/sub/:id', (req, res) => {
  const defaultHost = req.headers.host;
  const queryId = req.params.id;
  
  db.get('SELECT * FROM configs WHERE id = ? OR uuid = ?', [queryId, queryId], (err, cfg) => {
    if (!cfg) return res.status(403).send('Config not found');
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);
      const links = buildLinks(cfg, defaultHost, setMap['custom_domain'], setMap['clean_ip']);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(Buffer.from(links.plainSub).toString('base64'));
    });
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[ONEX Enterprise] Running on port ${PORT} with Full Proxy Core Tunnel`);
});
