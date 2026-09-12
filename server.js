const express = require('express');
const path = require('path');
const cors = require('cors');
const db = require('./db');
const { generateAllConfigs, generateSubList } = require('./utils/configs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

// ورود کاربر
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await db.getAsync('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
    if (!user) return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است' });
    
    await db.runAsync("UPDATE users SET last_login = datetime('now') WHERE id = ?", [user.id]);
    res.json({ token: user.id, username: user.username });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// دریافت اطلاعات داشبورد
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await db.getAsync('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!user) return res.status(404).json({ error: 'اشتراک یافت نشد' });
    
    const servers = await db.allAsync('SELECT * FROM servers');
    const allConfigs = [];
    servers.forEach(s => allConfigs.push(...generateAllConfigs(user, s)));

    res.json({
      user: {
        username: user.username,
        totalTrafficGB: user.total_traffic_gb,
        usedTrafficGB: user.used_traffic_gb,
        expireDate: user.expire_date,
        status: user.status,
        lastLogin: user.last_login
      },
      configs: allConfigs,
      subUrl: `${req.protocol}://${req.get('host')}/sub/${user.id}`
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// نمودار ترافیک
app.get('/api/traffic/:id', async (req, res) => {
  try {
    const logs = await db.allAsync(`SELECT timestamp, upload_mb, download_mb FROM traffic_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 24`, [req.params.id]);
    const reversed = logs.reverse();
    res.json({
      labels: reversed.map(l => new Date(l.timestamp).getHours() + ':00'),
      upload: reversed.map(l => l.upload_mb),
      download: reversed.map(l => l.download_mb)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// سابسکریپشن
app.get('/sub/:id', async (req, res) => {
  try {
    const user = await db.getAsync('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!user || user.status !== 'active') return res.status(403).send('ONEX: Subscription Expired');
    
    const servers = await db.allAsync('SELECT * FROM servers');
    const allConfigs = [];
    servers.forEach(s => allConfigs.push(...generateAllConfigs(user, s)));

    const raw = generateSubList(allConfigs);
    const base64 = Buffer.from(raw).toString('base64');
    const totalBytes = user.total_traffic_gb * 1073741824;
    const usedBytes = user.used_traffic_gb * 1073741824;

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Profile-Update-Interval', '6');
    res.setHeader('Subscription-Userinfo', `upload=0; download=${Math.round(usedBytes)}; total=${Math.round(totalBytes)}; expire=0`);
    res.send(base64);
  } catch (e) {
    res.status(500).send('Error: ' + e.message);
  }
});

// ساخت کاربر (ادمین)
app.post('/api/admin/create-user', async (req, res) => {
  try {
    const { username, password, email, totalTrafficGB, expireDate } = req.body;
    const id = uuidv4();
    await db.runAsync(
      `INSERT INTO users (id, username, password, email, total_traffic_gb, expire_date) VALUES (?,?,?,?,?,?)`,
      [id, username, password, email || '', totalTrafficGB || 50, expireDate]
    );
    res.json({ success: true, id, username });
  } catch (e) {
    res.status(400).json({ error: 'نام کاربری قبلاً استفاده شده است' });
  }
});

// لیست کاربران
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await db.allAsync('SELECT * FROM users ORDER BY created_at DESC');
    res.json(users);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// روت‌های صفحات
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/', (req, res) => res.redirect('/login'));

app.listen(PORT, () => console.log(`🚀 ONEX Panel running on port ${PORT}`));
