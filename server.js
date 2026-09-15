const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// سرو کردن فایل‌های استاتیک پوشه views
app.use(express.static(path.join(__dirname, 'views')));

// دیتابیس موقت در حافظه برای نگهداری کانفیگ‌ها و تنظیمات
global.panelData = global.panelData || {
    configs: [],
    cleanIp: '104.18.32.10',
    customDomain: '',
    broadcastMessage: '',
    logs: ['[INFO] پنل ONEX با موفقیت راه‌اندازی شد.']
};

// تابع تولید UUID واقعی و استاندارد برای اتصال کلاینت‌ها (مثل V2RayNG)
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// ۱. روت صفحه اصلی (داشبورد)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// ۲. مسیر دریافت اطلاعات کامل پنل برای رندر در داشبورد
app.get('/api/panel-data', (req, res) => {
    const totalUsedBytes = global.panelData.configs.reduce((acc, c) => acc + (c.used_bytes || 0), 0);
    const totalUsedGb = (totalUsedBytes / (1024 * 1024 * 1024)).toFixed(2);

    res.json({
        configsCount: global.panelData.configs.length,
        totalUsed: totalUsedGb,
        metrics: {
            cpu: Math.floor(Math.random() * 20) + 10,
            ram: Math.floor(Math.random() * 30) + 40
        },
        logs: global.panelData.logs,
        cleanIp: global.panelData.cleanIp,
        customDomain: global.panelData.customDomain,
        configs: global.panelData.configs
    });
});

// ۳. مسیر ساخت و ذخیره کانفیگ جدید با UUID معتبر و اختصاصی
app.post('/api/configs/create', (req, res) => {
    try {
        const { name, protocol = 'all', tag = 'normal', total_gb = 20, expire_days = 30 } = req.body;
        
        const newConfig = {
            id: Math.random().toString(36).substring(2, 10),
            uuid: generateUUID(), // تولید UUID واقعی جهت کارکرد صحیح کانفیگ در کلاینت
            name: name || 'Client',
            protocol: protocol,
            tag: tag,
            total_gb: parseFloat(total_gb),
            expire_days: parseInt(expire_days),
            used_gb: 0,
            used_bytes: 0,
            downlink_bytes: 1024 * 1024 * 50,
            uplink_bytes: 1024 * 1024 * 20,
            status: 'active',
            owner: 'admin',
            createdAt: new Date().toISOString()
        };

        global.panelData.configs.push(newConfig);
        global.panelData.logs.unshift(`[${new Date().toLocaleTimeString()}] کانفیگ جدید با نام "${newConfig.name}" و UUID معتبر ساخته شد.`);

        res.json({ success: true, message: 'کانفیگ با موفقیت ساخته شد', config: newConfig });
    } catch (error) {
        console.error('Error creating config:', error);
        res.status(500).json({ success: false, error: 'خطا در ساخت کانفیگ' });
    }
});

// ۴. مسیر ذخیره تنظیمات
app.post('/api/save-worker-settings', (req, res) => {
    const { cleanIp } = req.body;
    if (cleanIp) {
        global.panelData.cleanIp = cleanIp;
        global.panelData.logs.unshift(`[${new Date().toLocaleTimeString()}] تنظیمات بروز شد.`);
    }
    res.json({ success: true });
});

// ۵. مسیر دریافت اطلاعات کانفیگ در پورتال ساب
app.get('/api/subscription/:id/json', (req, res) => {
    const subId = req.params.id;
    const config = global.panelData.configs.find(c => c.id === subId || c.id.startsWith(subId) || subId.startsWith(c.id));

    if (!config) {
        return res.status(404).json({ success: false, error: 'کانفیگ مورد نظر یافت نشد' });
    }

    res.json({ success: true, data: config });
});

// ۶. مسیر اصلی ساب‌کریپشن کلاینت‌ها (Base64) با دامنه رایلی و UUID واقعی
app.get('/sub/:id', (req, res) => {
    const subId = req.params.id;
    const config = global.panelData.configs.find(c => c.id === subId || c.id.startsWith(subId) || subId.startsWith(c.id));

    if (!config) {
        return res.status(404).send('Configs not found or empty');
    }

    // استفاده از دامنه رایلی به عنوان هاست سرور
    const hostDomain = req.get('host');
    const clientUuid = config.uuid || generateUUID();
    
    // ساخت لینک‌های پروکسی با UUID استاندارد، دامنه رایلی و تگ اختصاصی شما
    const links = [
        `vless://${clientUuid}@${hostDomain}:443?encryption=none&security=tls&type=ws&path=%2F#${encodeURIComponent(config.name + ' | @V2rayTun0')}`,
        `trojan://${clientUuid}@${hostDomain}:443#${encodeURIComponent(config.name + ' | @V2rayTun0')}`
    ];

    const rawText = links.join('\n');
    const base64Configs = Buffer.from(rawText).toString('base64');

    res.send(base64Configs);
});

// ۷. پورتال اختصاصی هر کاربر
app.get('/subpage/:id', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'sub_client.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
