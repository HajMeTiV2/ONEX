const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// سرو کردن فایل‌های استاتیک پوشه views
app.use(express.static(path.join(__dirname, 'views')));

// دیتابیس موقت در حافظه برای نگهداری کانفیگ‌ها
global.userConfigs = global.userConfigs || {};

// تابع دریافت کانفیگ‌ها بر اساس شناسه اشتراک
async function getConfigsBySubscriptionId(subId) {
    return global.userConfigs[subId] || [];
}

// 1. روت صفحه اصلی برای باز شدن پنل
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});

// 2. مسیر جدید برای اضافه کردن و ساخت کانفیگ جدید
app.post('/api/configs/add', (req, res) => {
    try {
        const { subId, configLink } = req.body;
        
        if (!subId || !configLink) {
            return res.status(400).json({ success: false, error: 'اطلاعات ناقص است' });
        }

        if (!global.userConfigs[subId]) {
            global.userConfigs[subId] = [];
        }

        // اضافه کردن کانفیگ جدید (با تگ‌های مدنظر مثل NEXO و @V2rayTun0)
        global.userConfigs[subId].push(configLink);

        res.json({ success: true, message: 'کانفیگ با موفقیت ساخته و ذخیره شد' });
    } catch (error) {
        console.error('Error adding config:', error);
        res.status(500).json({ success: false, error: 'خطای سرور در ساخت کانفیگ' });
    }
});

// 3. مسیر API برای دریافت اطلاعات کانفیگ‌ها به صورت JSON (استفاده در فرانت‌اند)
app.get('/api/subscription/:id/json', async (req, res) => {
    try {
        const subId = req.params.id;
        const configs = await getConfigsBySubscriptionId(subId);

        if (!configs || configs.length === 0) {
            return res.status(404).json({ success: false, error: 'کانفیگ‌ها موجود نیستند' });
        }

        res.json({ success: true, data: configs });
    } catch (error) {
        console.error('Error fetching subscription json:', error);
        res.status(500).json({ success: false, error: 'خطای سرور داخلی' });
    }
});

// 4. مسیر اصلی ساب‌کریپشن برای کلاینت‌ها (مثل V2RayNG)
app.get('/sub/:id', async (req, res) => {
    try {
        const subId = req.params.id;
        const configs = await getConfigsBySubscriptionId(subId);

        if (!configs || configs.length === 0) {
            return res.status(404).send('Configs not found or empty');
        }

        // تبدیل کانفیگ‌ها به متن خط به خط و انکود Base64
        const rawConfigsText = configs.join('\n');
        const base64Configs = Buffer.from(rawConfigsText).toString('base64');

        res.send(base64Configs);
    } catch (error) {
        console.error('Error generating subscription:', error);
        res.status(500).send('Internal Server Error');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
