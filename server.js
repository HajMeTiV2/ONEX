const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// سرو کردن فایل‌های استاتیک پوشه views
app.use(express.static(path.join(__dirname, 'views')));

// دیتابیس موقت در حافظه برای نگهداری کانفیگ‌ها
global.userConfigs = global.userConfigs || {};

// روت صفحه اصلی (داشبورد)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// ۱. مسیر ساخت و ذخیره کانفیگ جدید (پشتیبانی از پروتکل‌های مختلف و تگ‌های دلخواه)
app.post('/api/create', (req, res) => {
    try {
        // دریافت اطلاعات از فرم داشبورد (با فرض اینکه نام کاربری یا شناسه ساب ارسال میشه)
        const { subId = 'default', remark, type = 'vless' } = req.body;
        
        if (!global.userConfigs[subId]) {
            global.userConfigs[subId] = [];
        }

        // ساخت لینک نمونه بر اساس پروتکل با تگ‌های مد نظر شما (مثل NEXO و کانال)
        const configName = remark || `NEXO-${Math.random().toString(36).substring(7)}`;
        let generatedLink = '';

        if (type === 'vless') {
            // ساختار استاندارد VLESS
            generatedLink = `vless://uuid-example@server-ip:443?encryption=none&security=tls&type=ws&path=%2F#${encodeURIComponent(configName + ' | @V2rayTun0')}`;
        } else if (type === 'vmess') {
            const vmessObj = { v: "2", ps: configName + " | @V2rayTun0", add: "server-ip", port: "443", id: "uuid-example", aid: "0", net: "ws", type: "none", host: "", path: "/", tls: "tls" };
            generatedLink = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;
        } else {
            generatedLink = `trojan://password-example@server-ip:443#${encodeURIComponent(configName + ' | @V2rayTun0')}`;
        }

        // ذخیره در لیست کانفیگ‌های کاربر
        global.userConfigs[subId].push(generatedLink);

        res.json({ success: true, message: 'کانفیگ با موفقیت ساخته شد', link: generatedLink });
    } catch (error) {
        console.error('Error creating config:', error);
        res.status(500).json({ success: false, error: 'خطا در ساخت کانفیگ' });
    }
});

// ۲. مسیر دریافت لیست کانفیگ‌ها برای نمایش در جدول داشبورد
app.get('/api/configs/:id', (req, res) => {
    const subId = req.params.id;
    const configs = global.userConfigs[subId] || [];
    res.json({ success: true, configs: configs });
});

// ۳. مسیر API برای بررسی ساب در فرانت‌اند
app.get('/api/subscription/:id/json', (req, res) => {
    const subId = req.params.id;
    const configs = global.userConfigs[subId] || [];
    if (configs.length === 0) {
        return res.status(404).json({ success: false, error: 'کانفیگ‌ها موجود نیستند' });
    }
    res.json({ success: true, data: configs });
});

// ۴. مسیر اصلی ساب‌کریپشن برای کلاینت‌ها (Base64)
app.get('/sub/:id', (req, res) => {
    const subId = req.params.id;
    const configs = global.userConfigs[subId] || [];
    if (configs.length === 0) {
        return res.status(404).send('Configs not found or empty');
    }
    const rawConfigsText = configs.join('\n');
    const base64Configs = Buffer.from(rawConfigsText).toString('base64');
    res.send(base64Configs);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
