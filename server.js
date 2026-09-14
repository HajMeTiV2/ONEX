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
const https = require('https');
const httpProxy = require('http-proxy');
const yaml = require('js-yaml');
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
const TRON_WALLET = process.env.TRON_WALLET || 'TCYourTetherWalletAddressHere12345';

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
    CREATE TABLE IF NOT EXISTS trial_users (
      telegram_id TEXT PRIMARY KEY,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      telegram_id TEXT,
      txid TEXT UNIQUE,
      amount REAL,
      plan_gb REAL,
      status TEXT DEFAULT 'verified',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
      reality_priv TEXT,
      reality_pub TEXT,
      reality_sid TEXT,
      wg_priv TEXT,
      wg_pub TEXT,
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
  db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES ('ssl_domain', '')`);
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
    const ssClients = (rows && rows.length > 0) ? rows.map(r => ({ password: r.uuid.replace(/-/g, '').substring(0, 16), method: "2022-blake3-aes-128-gcm", email: r.uuid })) : [{ password: "Pass123456789012", method: "2022-blake3-aes-128-gcm", email: fallbackId }];

    let realityServerKey = "eKq_6n4n6y8P9l0V1_2X3Z4A5B6C7D8E9F0G1H2I3J4";
    if (rows && rows[0] && rows[0].reality_priv) {
      realityServerKey = rows[0].reality_priv;
    }

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
        streamSettings: { network: "xhttp", xhttpSettings: { path: "/xhttp", mode: "auto" } }
      },
      {
        port: 8085,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: { clients: vClients, decryption: "none" },
        streamSettings: { network: "grpc", grpcSettings: { serviceName: "onex-grpc" } }
      },
      {
        port: 8086,
        listen: "127.0.0.1",
        protocol: "shadowsocks",
        settings: { clients: ssClients, network: "tcp,udp" }
      },
      {
        port: 8087,
        listen: "127.0.0.1",
        protocol: "vless",
        settings: { clients: vClients.map(c => ({ id: c.id, flow: "xtls-rprx-vision", email: c.email })), decryption: "none" },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            show: false,
            dest: "www.microsoft.com:443",
            xver: 0,
            serverNames: ["www.microsoft.com", "microsoft.com"],
            privateKey: realityServerKey,
            shortIds: ["", "0123456789abcdef"]
          }
        }
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
                  addLog(`اکانت ${cfg.id} با ثبت ترافیک لایو فعال شد.`);
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

setInterval(() => {
  const now = new Date().toISOString();
  db.all('SELECT id, name, used_gb, total_gb, expire_date FROM configs WHERE status = "active"', (err, rows) => {
    if (err || !rows) return;
    let needsReload = false;

    rows.forEach(c => {
      if (c.used_gb >= c.total_gb || (c.expire_date && now > c.expire_date)) {
        db.run('UPDATE configs SET status = "expired" WHERE id = ?', [c.id]);
        addLog(`اشتراک ${c.name} به پایان رسید.`);
        notifyAdmin(`⛔ اکانت *${c.name}* منقضی شد.\nمصرف: ${c.used_gb.toFixed(2)}/${c.total_gb} GB`);
        needsReload = true;
      }
    });

    if (needsReload) startCoreEngine();
  });
}, 30000);

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

  const vlessXhttp = `vless://${cfg.uuid}@${connectionAddress}:443?path=%2Fxhttp&security=tls&encryption=none&type=xhttp&host=${activeHost}&sni=${activeHost}#${encodeURIComponent(remark + '-XHTTP')}`;
  const vlessGrpc = `vless://${cfg.uuid}@${connectionAddress}:443?serviceName=onex-grpc&security=tls&encryption=none&type=grpc&sni=${activeHost}#${encodeURIComponent(remark + '-gRPC')}`;

  const realityPub = cfg.reality_pub || "j7fQzY9n5b4k3v2x1w0Z9A8B7C6D5E4F3G2H1I0J9K8";
  const vlessReality = `vless://${cfg.uuid}@${connectionAddress}:443?security=reality&encryption=none&pbk=${realityPub}&headerType=none&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com&sid=${cfg.reality_sid || '0123456789abcdef'}#${encodeURIComponent(remark + '-REALITY')}`;

  const ssPass = cfg.uuid.replace(/-/g, '').substring(0, 16);
  const ssRaw = `2022-blake3-aes-128-gcm:${ssPass}@${connectionAddress}:443`;
  const ssLink = `ss://${Buffer.from(ssRaw).toString('base64')}#${encodeURIComponent(remark + '-Shadowsocks')}`;

  const wgConfig = `[Interface]
PrivateKey = ${cfg.wg_priv || 'aPrivateDummyKey='}
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = ${cfg.wg_pub || 'aPublicDummyKey='}
Endpoint = ${connectionAddress}:51820
AllowedIPs = 0.0.0.0/0`;

  let chosenLinks = [];
  if (cfg.protocol === 'ws') chosenLinks = [vlessWs, vmessWs, trojanWs];
  else if (cfg.protocol === 'xhttp') chosenLinks = [vlessXhttp];
  else if (cfg.protocol === 'grpc') chosenLinks = [vlessGrpc];
  else if (cfg.protocol === 'reality') chosenLinks = [vlessReality];
  else if (cfg.protocol === 'shadowsocks') chosenLinks = [ssLink];
  else if (cfg.protocol === 'wireguard') chosenLinks = [wgConfig];
  else chosenLinks = [vlessWs, vmessWs, trojanWs, vlessXhttp, vlessGrpc, vlessReality, ssLink];

  const plainSub = chosenLinks.join('\n');

  return {
    vlessWs, vmessWs, trojanWs, vlessXhttp, vlessGrpc, vlessReality, ssLink, wgConfig,
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
      addLog(`کاربر ${username} (${user.role}) لاگین کرد.`);
      return res.json({ success: true });
    }
    res.status(401).json({ error: 'اطلاعات ورود اشتباه است.' });
  });
});

app.post('/api/save-worker-settings', auth, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'ممنوع' });
  const { customDomain, cleanIp } = req.body;
  db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_domain', ?)`, [customDomain || ''], () => {
    db.run(`INSERT OR REPLACE INTO settings (key, value) VALUES ('clean_ip', ?)`, [cleanIp || ''], () => {
      addLog(`تنظیمات ورکر به‌روز شد.`);
      res.json({ success: true });
    });
  });
});

app.get('/api/panel-data', auth, (req, res) => {
  const isReseller = req.session.role === 'reseller';
  const query = isReseller ? 'SELECT * FROM configs WHERE owner = ? ORDER BY created_at DESC' : 'SELECT * FROM configs ORDER BY created_at DESC';
  const params = isReseller ? [req.session.username] : [];

  db.all(query, params, (err, rows) => {
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);

      const totalAllocated = rows.reduce((s, c) => s + (c.total_gb || 0), 0);
      const totalUsed = rows.reduce((s, c) => s + (c.used_gb || 0), 0);

      db.get('SELECT credit_gb FROM users WHERE username = ?', [req.session.username], (e, uRow) => {
        res.json({
          currentUser: req.session.username,
          userRole: req.session.role,
          resellerCredit: uRow ? uRow.credit_gb : 0,
          configsCount: rows.length,
          totalAllocated,
          totalUsed: totalUsed.toFixed(2),
          customDomain: setMap['custom_domain'] || '',
          cleanIp: setMap['clean_ip'] || '',
          metrics: getServerMetrics(),
          logs: isReseller ? [] : liveLogs,
          configs: rows
        });
      });
    });
  });
});

app.post('/api/configs/create', auth, (req, res) => {
  const { name, server, protocol, total_gb, expire_days, ip_limit } = req.body;
  const gb = parseFloat(total_gb) || 20;

  if (req.session.role === 'reseller') {
    db.get('SELECT credit_gb FROM users WHERE username = ?', [req.session.username], (err, row) => {
      if (!row || row.credit_gb < gb) {
        return res.status(400).json({ error: 'سهمیه حجم شما کافی نیست!' });
      }
      db.run('UPDATE users SET credit_gb = credit_gb - ? WHERE username = ?', [gb, req.session.username]);
      insertConfig();
    });
  } else {
    insertConfig();
  }

  function insertConfig() {
    const id = uuidv4().substring(0, 8);
    const uuid = uuidv4();
    const days = parseInt(expire_days) || 30;

    const realityPriv = crypto.randomBytes(32).toString('base64');
    const realityPub = crypto.randomBytes(32).toString('base64');
    const realitySid = crypto.randomBytes(4).toString('hex');

    const wgPriv = crypto.randomBytes(32).toString('base64');
    const wgPub = crypto.randomBytes(32).toString('base64');

    db.run(
      `INSERT INTO configs (
        id, name, owner, server, protocol, total_gb, expire_days, uuid,
        reality_priv, reality_pub, reality_sid, wg_priv, wg_pub,
        ip_limit, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
      [
        id, name || 'اکانت ابری', req.session.username, server || 'Germany (DE)',
        protocol || 'all', gb, days, uuid,
        realityPriv, realityPub, realitySid, wgPriv, wgPub,
        parseInt(ip_limit) || 2
      ],
      function(err) {
        if (err) return res.status(500).json({ error: 'خطای پایگاه داده' });
        startCoreEngine();
        addLog(`کانفیگ (${protocol}) توسط ${req.session.username} ساخته شد.`);
        notifyAdmin(`➕ کانفیگ جدید (${protocol}) ساخته شد:\nنام: ${name}\nحجم: ${gb} GB`);
        res.json({ success: true, id });
      }
    );
  }
});

app.post('/api/configs/:id/renew', auth, (req, res) => {
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).json({ error: 'یافت نشد' });
    const currentExp = cfg.expire_date ? new Date(cfg.expire_date) : new Date();
    const baseDate = currentExp > new Date() ? currentExp : new Date();
    baseDate.setDate(baseDate.getDate() + 30);

    db.run('UPDATE configs SET expire_date = ?, status = "active" WHERE id = ?', [baseDate.toISOString(), req.params.id], () => {
      startCoreEngine();
      addLog(`تمدید اشتراک ${cfg.name}`);
      res.json({ success: true });
    });
  });
});

app.post('/api/configs/:id/reset-traffic', auth, (req, res) => {
  db.run('UPDATE configs SET used_gb = 0, downlink_bytes = 0, uplink_bytes = 0, status = "active" WHERE id = ?', [req.params.id], () => {
    startCoreEngine();
    addLog(`ریست ترافیک ${req.params.id}`);
    res.json({ success: true });
  });
});

app.delete('/api/configs/:id', auth, (req, res) => {
  db.run('DELETE FROM configs WHERE id = ?', [req.params.id], () => {
    startCoreEngine();
    addLog(`کانفیگ ${req.params.id} حذف شد.`);
    res.json({ success: true });
  });
});

app.get('/sub/:id', (req, res) => {
  const defaultHost = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg || cfg.status === 'expired') {
      res.status(403).setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.send('این اشتراک منقضی شده یا حجم آن به پایان رسیده است.');
    }
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);

      const links = buildLinks(cfg, defaultHost, setMap['custom_domain'], setMap['clean_ip']);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.send(Buffer.from(links.plainSub).toString('base64'));
    });
  });
});

// ارسال اطلاعات کامل تکی و لینک‌ها به صفحه ساب کلاینت
app.get('/api/subinfo/:id', (req, res) => {
  const defaultHost = req.headers.host;
  db.get('SELECT * FROM configs WHERE id = ?', [req.params.id], (err, cfg) => {
    if (!cfg) return res.status(404).json({ error: 'کانفیگ یافت نشد' });
    db.all('SELECT key, value FROM settings', (err, sets) => {
      const setMap = {};
      (sets || []).forEach(s => setMap[s.key] = s.value);

      const links = buildLinks(cfg, defaultHost, setMap['custom_domain'], setMap['clean_ip']);
      const activeHost = (setMap['custom_domain'] && setMap['custom_domain'].trim() !== '') ? setMap['custom_domain'].trim() : defaultHost;

      const remainingGb = Math.max(0, (cfg.total_gb - cfg.used_gb)).toFixed(2);
      const usagePercent = Math.min(100, Math.round((cfg.used_gb / cfg.total_gb) * 100));

      res.json({
        config: cfg,
        isExpired: cfg.status === 'expired',
        isPending: cfg.status === 'pending',
        remainingGb,
        usagePercent,
        subUrl: `https://${activeHost}/sub/${cfg.id}`,
        vlessWs: links.vlessWs,
        vmessWs: links.vmessWs,
        trojanWs: links.trojanWs,
        vlessXhttp: links.vlessXhttp,
        vlessGrpc: links.vlessGrpc,
        vlessReality: links.vlessReality,
        ssLink: links.ssLink,
        wgConfig: links.wgConfig
      });
    });
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
  else if (req.url.startsWith('/onex-grpc')) pGrpc.ws(req, socket, head);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[ONEX Master Multi-Protocol Engine v4.2] Active on port ${PORT}`);
});
