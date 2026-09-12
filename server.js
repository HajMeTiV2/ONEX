const express = require('express');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');
const { generateAllConfigs, generateSubList } = require('./utils/configs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'onex-super-secret-mehtif-2025';

// ═══════════════ MIDDLEWARE ═══════════════
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'توکن ارسال نشده' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'توکن نامعتبر است' });
  }
}

// ═══════════════ LOGIN ═══════════════
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await db.getAsync('SELECT * FROM admins WHERE username = ? AND password = ?', [username, password]);
    if (!admin) return res.status(401).json({ error: 'نام کاربری یا رمز اشتباه است' });

    await db.runAsync("UPDATE admins SET last_login = datetime('now') WHERE id = ?", [admin.id]);
    const token = jwt.sign({ id: admin.id, username: admin.username, role: admin.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, admin: { id: admin.id, username: admin.username, role: admin.role } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════ DASHBOARD STATS ═══════════════
app.get('/api/stats', auth, async (req, res) => {
  try {
    let clients;
    if (req.admin.role === 'superadmin') {
      clients = await db.allAsync('SELECT * FROM clients');
    } else {
      clients = await db.allAsync('SELECT * FROM clients WHERE admin_id = ?', [req.admin.id]);
    }
    
    const activeClients = clients.filter(c => c.status === 'active').length;
    const totalTraffic = clients.reduce((sum, c) => sum + c.total_traffic_gb, 0);
    const usedTraffic = clients.reduce((sum, c) => sum + c.used_traffic_gb, 0);
    
    res.json({
      totalClients: clients.length,
      activeClients,
      totalTraffic: totalTraffic.toFixed(1),
      usedTraffic: usedTraffic.toFixed(1)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════ CLIENTS MANAGEMENT ═══════════════

// لیست کاربران
app.get('/api/clients', auth, async (req, res) => {
  try {
    let clients;
    if (req.admin.role === 'superadmin') {
      clients = await db.allAsync(`SELECT c.*, a.username as admin_name FROM clients c LEFT JOIN admins a ON c.admin_id = a.id ORDER BY c.created_at DESC`);
    } else {
      clients = await db.allAsync('SELECT * FROM clients WHERE admin_id = ? ORDER BY created_at DESC', [req.admin.id]);
    }
    res.json(clients);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ایجاد کاربر جدید
app.post('/api/clients', auth, async (req, res) => {
  try {
    const { name, totalTrafficGB, expireDate, protocols, note } = req.body;
    const id = uuidv4();
    const clientUuid = uuidv4();
    const protoList = protocols || ['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2', 'reality'];

    await db.runAsync(
      `INSERT INTO clients (id, admin_id, name, uuid, total_traffic_gb, expire_date, protocols, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, req.admin.id, name, clientUuid, totalTrafficGB || 30, expireDate, JSON.stringify(protoList), note || '']
    );

    // دیتای نمودار نمونه
    for (let i = 23; i >= 0; i--) {
      const t = new Date(Date.now() - i * 3600000).toISOString();
      await db.runAsync(`INSERT INTO traffic_logs (client_id, timestamp, upload_mb, download_mb) VALUES (?, ?, ?, ?)`,
        [id, t, Math.floor(Math.random() * 30 + 3), Math.floor(Math.random() * 150 + 10)]);
    }

    res.json({ success: true, id, uuid: clientUuid });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ویرایش کاربر
app.put('/api/clients/:id', auth, async (req, res) => {
  try {
    const { name, totalTrafficGB, expireDate, status, protocols, note } = req.body;
    const client = await db.getAsync('SELECT * FROM clients WHERE id = ?', [req.params.id]);
    if (!client) return res.status(404).json({ error: 'کاربر یافت نشد' });
    if (req.admin.role !== 'superadmin' && client.admin_id !== req.admin.id) return res.status(403).json({ error: 'اجازه دسترسی نیست' });

    await db.runAsync(
      `UPDATE clients SET name=?, total_traffic_gb=?, expire_date=?, status=?, protocols=?, note=? WHERE id=?`,
      [name, totalTrafficGB, expireDate, status, JSON.stringify(protocols), note || '', req.params.id]
    );
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// حذف کاربر
app.delete('/api/clients/:id', auth, async (req, res) => {
  try {
    const client = await db.getAsync('SELECT * FROM clients WHERE id = ?', [req.params.id]);
    if (!client) return res.status(404).json({ error: 'کاربر یافت نشد' });
    if (req.admin.role !== 'superadmin' && client.admin_id !== req.admin.id) return res.status(403).json({ error: 'اجازه دسترسی نیست' });

    await db.runAsync('DELETE FROM clients WHERE id = ?', [req.params.id]);
    await db.runAsync('DELETE FROM traffic_logs WHERE client_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// دریافت جزئیات یک کاربر + کانفیگ‌ها
app.get('/api/clients/:id', auth, async (req, res) => {
  try {
    const client = await db.getAsync('SELECT * FROM clients WHERE id = ?', [req.params.id]);
    if (!client) return res.status(404).json({ error: 'یافت نشد' });
    if (req.admin.role !== 'superadmin' && client.admin_id !== req.admin.id) return res.status(403).json({ error: 'اجازه دسترسی نیست' });

    const servers = await db.allAsync('SELECT * FROM servers WHERE status = ?', ['active']);
    const allConfigs = [];
    servers.forEach(s => allConfigs.push(...generateAllConfigs(client, s)));

    res.json({
      client,
      configs: allConfigs,
      subUrl: `${req.protocol}://${req.get('host')}/sub/${client.uuid}`
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// نمودار ترافیک
app.get('/api/clients/:id/traffic', auth, async (req, res) => {
  try {
    const logs = await db.allAsync(`SELECT timestamp, upload_mb, download_mb FROM traffic_logs WHERE client_id = ? ORDER BY timestamp DESC LIMIT 24`, [req.params.id]);
    const reversed = logs.reverse();
    res.json({
      labels: reversed.map(l => new Date(l.timestamp).getHours() + ':00'),
      upload: reversed.map(l => l.upload_mb),
      download: reversed.map(l => l.download_mb)
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ═══════════════ RESELLERS (Super Admin Only) ═══════════════
app.get('/api/resellers', auth, async (req, res) => {
  if (req.admin.role !== 'superadmin') return res.status(403).json({ error: 'فقط سوپر ادمین' });
  const resellers = await db.allAsync("SELECT * FROM admins WHERE role != 'superadmin'");
  res.json(resellers);
});

app.post('/api/resellers', auth, async (req, res) => {
  if (req.admin.role !== 'superadmin') return res.status(403).json({ error: 'فقط سوپر ادمین' });
  try {
    const { username, password, maxUsers, balanceGB } = req.body;
    const id = uuidv4();
    await db.runAsync(`INSERT INTO admins (id, username, password, role, balance_gb, max_users) VALUES (?, ?, ?, 'reseller', ?, ?)`,
      [id, username, password, balanceGB || 500, maxUsers || 50]);
    res.json({ success: true, id });
  } catch (e) { res.status(400).json({ error: 'نام کاربری تکراری' }); }
});

app.delete('/api/resellers/:id', auth, async (req, res) => {
  if (req.admin.role !== 'superadmin') return res.status(403).json({ error: 'فقط سوپر ادمین' });
  await db.runAsync('DELETE FROM admins WHERE id = ? AND role != ?', [req.params.id, 'superadmin']);
  res.json({ success: true });
});

// ═══════════════ SERVERS ═══════════════
app.get('/api/servers', auth, async (req, res) => {
  const servers = await db.allAsync('SELECT * FROM servers');
  res.json(servers);
});

app.post('/api/servers', auth, async (req, res) => {
  if (req.admin.role !== 'superadmin') return res.status(403).json({ error: 'فقط سوپر ادمین' });
  try {
    const { name, host, port, sni } = req.body;
    const id = uuidv4();
    await db.runAsync(`INSERT INTO servers (id, name, host, port, sni) VALUES (?, ?, ?, ?, ?)`, [id, name, host, port, sni]);
    res.json({ success: true, id });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/servers/:id', auth, async (req, res) => {
  if (req.admin.role !== 'superadmin') return res.status(403).json({ error: 'فقط سوپر ادمین' });
  await db.runAsync('DELETE FROM servers WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

// ═══════════════ PUBLIC SUBSCRIPTION ═══════════════
app.get('/sub/:uuid', async (req, res) => {
  try {
    const client = await db.getAsync('SELECT * FROM clients WHERE uuid = ?', [req.params.uuid]);
    if (!client || client.status !== 'active') return res.status(403).send('ONEX: Expired');

    const servers = await db.allAsync('SELECT * FROM servers WHERE status = ?', ['active']);
    const allConfigs = [];
    servers.forEach(s => allConfigs.push(...generateAllConfigs(client, s)));

    const raw = generateSubList(allConfigs);
    const base64 = Buffer.from(raw).toString('base64');
    const totalBytes = client.total_traffic_gb * 1073741824;
    const usedBytes = client.used_traffic_gb * 1073741824;

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Profile-Update-Interval', '6');
    res.setHeader('Subscription-Userinfo', `upload=0; download=${Math.round(usedBytes)}; total=${Math.round(totalBytes)}; expire=0`);
    res.send(base64);
  } catch (e) { res.status(500).send(e.message); }
});

// ═══════════════ PAGES ═══════════════
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/', (req, res) => res.redirect('/login'));

app.listen(PORT, () => console.log(`🚀 ONEX Pro Panel running on port ${PORT}`));
