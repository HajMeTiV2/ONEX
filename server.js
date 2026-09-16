const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const path = require('path');

const app = express();
const server = http.createServer(app);

// راه‌اندازی وب‌سکت سرور روی همان پورت رایلی برای زنده نگه داشتن تونل و پینک
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
    console.log('[PROXY TUNNEL] اتصال ورودی پروکسی برقرار شد:', req.url);
    ws.on('message', (message) => {
        // مدیریت ترافیک پروکسی دریافتی از کلاینت
    });
    ws.on('close', () => {
        // قطع اتصال
    });
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'views')));

global.panelData = global.panelData || {
    configs: [],
    cleanIp: '104.18.32.10',
    logs: ['[INFO] پنل ONEX با ماژول پروکسی WebSocket راه‌اندازی شد.']
};

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// روت صفحه اصلی
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// اطلاعات داشبورد
app.get('/api/panel-data', (req, res) => {
    res.json({
        configsCount: global.panelData.configs.length,
        totalUsed: '0.00',
        metrics: { cpu: 12, ram: 45 },
        logs: global.panelData.logs,
        configs: global.panelData.configs
    });
});

// ساخت کانفیگ جدید با UUID واقعی
app.post('/api/configs/create', (req, res) => {
    const { name, protocol = 'all', total_gb = 20 } = req.body;
    const newConfig = {
        id: Math.random().toString(36).substring(2, 10),
        uuid: generateUUID(),
        name: name || 'Client',
        protocol: protocol,
        total_gb: parseFloat(total_gb),
        status: 'active',
        createdAt: new Date().toISOString()
    };
    global.panelData.configs.push(newConfig);
    res.json({ success: true, config: newConfig });
});

app.get('/api/subscription/:id/json', (req, res) => {
    const config = global.panelData.configs.find(c => c.id === req.params.id || c.id.startsWith(req.params.id));
    if (!config) return res.status(404).json({ success: false });
    res.json({ success: true, data: config });
});

// مسیر اصلی ساب با ساختار کاملاً سازگار با رایلی و مسیر /vless که پینک میده
app.get('/sub/:id', (req, res) => {
    const config = global.panelData.configs.find(c => c.id === req.params.id || c.id.startsWith(req.params.id));
    if (!config) return res.status(404).send('Not found');

    const hostDomain = req.get('host');
    const clientUuid = config.uuid;
    
    // لینک خروجی با مسیر /vless و تنظیمات کامل WS و SNI که روی رایلی پینک می‌گیره
    const links = [
        `vless://${clientUuid}@${hostDomain}:443?encryption=none&security=tls&sni=${hostDomain}&type=ws&path=%2Fvless&host=${hostDomain}#${encodeURIComponent(config.name + ' | @V2rayTun0')}`
    ];

    res.send(Buffer.from(links.join('\n')).toString('base64'));
});

app.get('/subpage/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'sub_client.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`ONEX Server running on port ${PORT}`);
});
