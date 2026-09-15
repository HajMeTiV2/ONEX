const express = require('express');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// تابع نمونه برای دریافت کانفیگ‌ها (این بخش را به دیتابیس یا منطق ذخیره‌سازی خود متصل کنید)
async function getConfigsBySubscriptionId(subId) {
    // نمونه آرایه کانفیگ‌ها؛ در صورت اتصال به دیتابیس، داده‌ها از آنجا خوانده می‌شوند
    // مطمئن شوید نام پروژه NEXO و تگ‌های دلخواه در کانفیگ‌ها لحاظ شده‌اند
    return global.userConfigs && global.userConfigs[subId] ? global.userConfigs[subId] : [];
}

// مسیر API برای دریافت اطلاعات کانفیگ‌ها به صورت JSON (استفاده در فرانت‌اند)
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

// مسیر اصلی ساب‌کریپشن برای کلاینت‌ها (مثل V2RayNG)
app.get('/sub/:id', async (req, res) => {
    try {
        const subId = req.params.id;
        const configs = await getConfigsBySubscriptionId(subId);

        if (!configs || configs.length === 0) {
            return res.status(404).send('Configs not found or empty');
        }

        // تبدیل کانفیگ‌ها به متن خط به خط
        const rawConfigsText = configs.join('\n');

        // کدگذاری Base64 استاندارد برای خوانش توسط کلاینت‌ها
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
