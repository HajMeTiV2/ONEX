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
const crypto = require('crypto');

let TelegramBot;
try {
  TelegramBot = require('node-telegram-bot-api');
} catch (e) {
  TelegramBot = null;
}

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TG_BOT_TOKEN = process.env.BOT_TOKEN || '';
const ADMIN_TG_ID = process.env.ADMIN_TG_ID || '';

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

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
  if (liveLogs.length > 50) liveLogs.pop();
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
});

let botInstance = null;
function notifyAdmin(message) {
  if (botInstance && ADMIN_TG_ID) {
    try {
      botInstance.sendMessage(ADMIN_TG_ID, `📢 *اطلاعیه ONEX*\n\n${message}`, { parse_mode: 'Markdown' });
    } catch (e) {}
  }
}

function getServerMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memPercent = Math.round((usedMem / totalMem) * 100);

  const cpus = os.cpus();
  let user = 0, nice = 0, sys = 0, idle = 0, irq = 0;
  for (const cpu of cpus) {
    user += cpu.times.user;
    nice += cpu.times.nice;
    sys += cpu.times.sys;
    irq += cpu.times.irq;
    idle += cpu.times.idle;
  }
  const total = user + nice + sys + idle + irq;
  const cpuPercent = total > 0 ? Math.round(((total - idle) / total) * 100) : 0;

  return {
    cpu: cpuPercent,
    ram: memPercent,
    ramUsedGb: (usedMem / (1024 ** 3)).toFixed(1),
    ramTotalGb: (totalMem / (1024 ** 3)).toFixed(1),
    uptime: Math.round(os.uptime() / 3600)
  };
}

function startCoreEngine() {
  db.all('SELECT * FROM configs WHERE status != "expired"', (err, rows) => {
    const fallbackId = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const vClients = (rows && rows.length > 0) ? rows.map(r => ({ id: r.uuid, email: r.uuid })) : [{ id: fallbackId, email: fallbackId }];
    const tClients = (rows && rows.length > 0) ? rows.map(r => ({ password: r.uuid, email: r.uuid })) : [{ password: fallbackId, email: fallbackId }];

    const inbounds = [
      {
        tag: "api",
        port: 10085,
        listen: "127.0.0.1",
        protocol: "dokodemo-door",
        settings: { address: "127.0.0.1" }
      },
      {
        port: 8081,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: { clients: vClients, decryption: "none" },
        streamSettings: { network: "ws", wsSettings: { path: "/vless" } }
      },
      {
        port: 8082,
        listen: "127.0.0.1",
        protocol: "vmess",
        settings: { clients: vClients.map(c => ({ id: c.id, alterId: 0, email: c.email })) },
        streamSettings: { network: "ws", wsSettings: { path: "/vmess" } }
      },
      {
        port: 8083,
        listen: "127.0.0.1",
        protocol: "trojan",
        settings: { clients: tClients },
        streamSettings: { network: "ws", wsSettings: { path: "/trojan" } }
      },
      {
        port: 8084,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: { clients: vClients, decryption: "none" },
        streamSettings: { network: "ws", wsSettings: { path: "/xhttp" } }
      },
      {
        port: 8085,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: { clients: vClients, decryption: "none" },
        streamSettings: { network: "ws", wsSettings: { path: "/grpc" } }
      }
    ];

    const xrayConfig = {
      log: { loglevel: "error" },
      stats: {},
      api: { tag: "api", services: ["StatsService"] },
      policy: {
        levels: { "0": { statsUserUplink: true, statsUserDownlink: true } },
        system: { statsInboundUplink: true, statsInboundDownlink: true }
      },
      inbounds: inbounds,
      outbounds: [{ protocol: "freedom" }],
      routing: {
        rules: [{ inboundTag: ["api"], outboundTag: "api", type: "field" }]
      }
    };

    const cfgPath = path.join(DATA_DIR, 'xray_run.json');
    fs.writeFileSync(cfgPath, JSON.stringify(xrayConfig, null, 2));

    const binPath = path.join(__dirname, 'xray-bin', 'xray');
    if (fs.existsSync(binPath)) {
      spawn('pkill', ['-f', 'xray']);
      setTimeout(() => {
        const proc = spawn(binPath, ['run', '-c', cfgPath]);
        proc.stdout.on('data', d => process.stdout.write(`[XRAY]: ${d}`));
        proc.stderr.on('data', d => process.stderr.write(`[XRAY ERR]: ${d}`));
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

            db.get('SELECT id, status, expire_days, used_gb FROM configs WHERE uuid = ?', [uuid], (err, cfg) => {
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

function buildLinks(cfg, defaultHost, customDomain, cleanIp) {
  const remark = `ONEX-${cfg.name}`;
  const activeHost = (customDomain && customDomain.trim() !== '') ? customDomain.trim() : defaultHost;
  const connectionAddress = (cleanIp && cleanIp.trim() !== '') ? cleanIp.trim() : activeHost;

  const vlessWs = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fvless&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark + '-WS')}`;

  const vmessPayload = {
    v: "2", ps: `${remark}-VMess`, add: connectionAddress, port: "443", id: cfg.uuid,
    aid: "0", scy: "auto", net: "ws", type: "none", host: activeHost, path: "/vmess", tls: "tls", sni: activeHost
  };
  const vmessWs = `vmess://${Buffer.from(JSON.stringify(vmessPayload)).toString('base64')}`;
  const trojanWs = `trojan://${cfg.uuid}@${connectionAddress}:443?path=%2Ftrojan&security=tls&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark + '-Trojan')}`;

  const vlessXhttp = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fxhttp&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark + '-XHTTP')}`;
  const vlessGrpc = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fgrpc&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark + '-gRPC')}`;
  const vlessReality = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fvless&security=tls&encryption=none&type=ws&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark + '-REALITY')}`;

  let chosenLinks = [vlessWs, vmessWs, trojanWs, vlessXhttp, vlessGrpc];
  const plainSub = chosenLinks.join('\n');

  return {
    vlessWs, vmessWs, trojanWs, vlessXhttp, vlessGrpc, vlessReality,
    plainSub, activeHost, connectionAddress
  };
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
        userRole: req.session.role,
        configsCount: rows.length,
        totalAllocated: rows.reduce((s, c) => s + (c.total_gb || 0), 0),
        totalUsed: rows.reduce((s, c) => s + (c.used_gb || 0), 0).toFixed(2),
        customDomain: setMap['custom_domain'] || '',
        metrics: getServerMetrics(),
        logs: liveLogs,
        configs: rows
      });
    });
  });
});

app.post('/api/configs/create', auth, (req, res) => {
  const { name, server, protocol, tag, total_gb, expire_days, ip_limit } = req.body;
  const id = uuidv4().substring(0, 8);
  const uuid = uuidv4();

  db.run(
    `INSERT INTO configs (id, name, owner, server, protocol, tag, total_gb, expire_days, uuid, ip_limit, status) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
    [id, name || 'اکانت', req.session.username, server || 'Germany', protocol || 'all', tag || 'normal', parseFloat(total_gb) || 20, parseInt(expire_days) || 30, uuid, parseInt(ip_limit) || 2],
    function(err) {
      if (err) return res.status(500).json({ error: 'خطا در پایگاه داده' });
      startCoreEngine();
      res.json({ success: true, id });
    }
  );
});

// مسیر ویرایش مشخصات کانفیگ
app.post('/api/configs/:id/edit', auth, (req, res) => {
  const { name, total_gb, expire_days } = req.body;
  db.run(
    'UPDATE configs SET name = ?, total_gb = ?, expire_days = ? WHERE id = ?',
    [name, parseFloat(total_gb) || 20, parseInt(expire_days) || 30, req.params.id],
    (err) => {
      if (err) return res.status(500).json({ error: 'خطا در ویرایش اطلاعات' });
      addLog(`کانفیگ ${req.params.id} ویرایش شد.`);
      res.json({ success: true });
    }
  );
});

app.post('/api/configs/:id/renew', auth, (req, res) => {
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).json({ error: 'یافت نشد' });
    const currentExp = cfg.expire_date ? new Date(cfg.expire_date) : new Date();
    const baseDate = currentExp > new Date() ? currentExp : new Date();
    baseDate.setDate(baseDate.getDate() + 30);

    db.run('UPDATE configs SET expire_date = ?, status = "active" WHERE id = ?', [baseDate.toISOString(), req.params.id], () => {
      startCoreEngine();
      res.json({ success: true });
    });
  });
});

app.post('/api/configs/:id/reset-traffic', auth, (req, res) => {
  db.run('UPDATE configs SET used_gb = 0, downlink_bytes = 0, uplink_bytes = 0, status = "active" WHERE id = ?', [req.params.id], () => {
    startCoreEngine();
    res.json({ success: true });
  });
});

app.delete('/api/configs/:id', auth, (req, res) => {
  db.run('DELETE FROM configs WHERE id = ?', [req.params.id], () => {
    startCoreEngine();
    res.json({ success: true });
  });
});

app.get('/sub/:id', (req, res) => {
  const defaultHost = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg || cfg.status === 'expired') return res.status(403).send('منقضی شده');
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
      const activeHost = (setMap['custom_domain'] && setMap['custom_domain'].trim() !== '') ? setMap['custom_domain'].trim() : defaultHost;

      res.json({
        config: cfg,
        remainingGb: Math.max(0, (cfg.total_gb - cfg.used_gb)).toFixed(2),
        usagePercent: Math.min(100, Math.round((cfg.used_gb / cfg.total_gb) * 100)),
        subUrl: `https://${activeHost}/sub/${cfg.id}`,
        vlessWs: links.vlessWs,
        vmessWs: links.vmessWs,
        trojanWs: links.trojanWs,
        vlessXhttp: links.vlessXhttp,
        vlessGrpc: links.vlessGrpc,
        vlessReality: links.vlessReality
      });
    });
  });
});

// مسیر دعوت دوستان (Referral)
app.get('/invite/:uuid', (req, res) => {
  const inviterUuid = req.params.uuid;
  db.get('SELECT * FROM configs WHERE uuid = ?', [inviterUuid], (err, inviter) => {
    if (!inviter) return res.status(404).send('لینک دعوت نامعتبر است.');
    db.run('UPDATE configs SET referral_count = referral_count + 1, total_gb = total_gb + 2 WHERE uuid = ?', [inviterUuid]);
    res.send(`
      <html dir="rtl">
      <head><meta charset="UTF-8"><title>دعوت به ONEX</title></head>
      <body style="background:#050812; color:#fff; font-family:sans-serif; text-align:center; padding-top:60px;">
        <h2>🎉 دعوت‌نامه شما با موفقیت ثبت شد!</h2>
        <p style="color:#38bdf8; margin-top:10px;">۲ گیگابایت حجم هدیه به حساب معرف اضافه شد.</p>
        <a href="/" style="display:inline-block; margin-top:20px; background:#0284c7; color:#fff; padding:10px 20px; border-radius:10px; text-decoration:none;">بازگشت</a>
      </body>
      </html>
    `);
  });
});

const pVless = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8081', ws: true });
const pVmess = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8082', ws: true });
const pTrojan = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8083', ws: true });
const pXhttp = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8084', ws: true });
const pGrpc = httpProxy.createProxyServer({ target: 'http://127.0.0.1:8085', ws: true });

const server = http.createServer(app);

server.on('upgrade', (req, socket, head) => {
  if (req.url.startsWith('/vless')) pVless.ws(req, socket, head);
  else if (req.url.startsWith('/vmess')) pVmess.ws(req, socket, head);
  else if (req.url.startsWith('/trojan')) pTrojan.ws(req, socket, head);
  else if (req.url.startsWith('/xhttp')) pXhttp.ws(req, socket, head);
  else if (req.url.startsWith('/grpc')) pGrpc.ws(req, socket, head);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[ONEX Enterprise Engine] Running on port ${PORT}`);
});
