# 🚀 ONEX 1.3.1

<p align="center">
  <img src="onex-logo-3d.png" alt="ONEX Logo" width="260">
</p>

<h1 align="center">ONEX</h1>

<p align="center">
  <strong>پنل حرفه‌ای مدیریت کانفیگ، Native Runtime و مرکز کنترل تلگرام</strong>
</p>

<p align="center">
  <a href="README.md">🇮🇷 فارسی</a> •
  <a href="README.en.md">🇬🇧 English</a>
</p>

<p align="center">
  <a href="https://github.com/HajMeTiV2/ONEX">⭐ GitHub</a> •
  <a href="https://t.me/V2rayTun0">📢 کانال تلگرام</a> •
  <a href="https://t.me/Mehtif">👨‍💻 سازنده</a>
</p>

---

## ✨ ONEX چیست؟

**ONEX** یک پنل Self-Hosted مدرن و حرفه‌ای برای مدیریت کانفیگ‌ها، Native Runtime مبتنی بر `sing-box`، آمار، سرویس‌های Relay/XHTTP و مدیریت تلگرام است.

این پروژه برای استفاده در محیط‌های مختلف طراحی شده و به Railway محدود نیست. در حال حاضر می‌توان ONEX را روی **Railway** اجرا کرد و برای اجرای مستقل روی **VPS/Linux** نیز آماده‌سازی شده است.

> 🎯 هدف ONEX: ترکیب یک پنل مدیریتی سریع، ظاهر مدرن، مدیریت دقیق کانفیگ و ابزارهای عملیاتی در یک محیط واحد.

---

## 🧩 امکانات اصلی

### 🛠️ مدیریت کانفیگ

- ساخت کانفیگ جدید
- ویرایش کامل کانفیگ موجود
- فعال / غیرفعال کردن هر کانفیگ
- مدیریت حجم و تاریخ انقضا
- مدیریت گروه و دسته‌بندی
- منوی عملیات سه‌نقطه
- انتخاب چند کانفیگ
- عملیات گروهی
- Advanced Configuration
- حفظ وضعیت انتخاب‌ها در بروزرسانی پنل

### ⚡ Native Runtime

ONEX از Native Core برای مدیریت Runtime `sing-box` استفاده می‌کند.

جریان اعمال تغییر:

```text
Advanced UI
      ↓
Persisted State
      ↓
Native Core Builder
      ↓
Validation
      ↓
sing-box check
      ↓
Staged Configuration
      ↓
Runtime Start
      ↓
Health Check
      ↓
Commit / Rollback
```

تغییرات Native قبل از اعمال نهایی اعتبارسنجی می‌شوند تا احتمال اعمال Configuration نامعتبر کاهش پیدا کند.

### 🌐 پروتکل‌ها

- Trojan
- Shadowsocks
- SOCKS5
- HTTP Proxy
- Hysteria2
- VLESS gRPC Reality
- VLESS WebSocket Relay
- XHTTP

### 🤖 Telegram Control Center

مرکز کنترل تلگرام برای مدیریت بهتر کاربران و سرویس:

- وضعیت Bot
- وضعیت Webhook
- آمار کاربران
- کاربران فعال
- مدیریت کاربران
- فعال / مسدود کردن کاربران
- اتصال Telegram ID به کانفیگ
- Broadcast
- اعلان‌ها
- Activity Log
- تنظیمات Bot

### 🎨 رابط کاربری

- طراحی Glass / Modern UI
- حالت روشن و تاریک
- طراحی Responsive
- کارت‌های مدیریتی
- داشبورد آماری
- منوی پایدار سه‌نقطه
- کنترل فعال/غیرفعال کانفیگ
- بهینه‌سازی عملکرد Dark Mode

---

# 🏗️ معماری پروژه

```text
                         ┌─────────────────────┐
                         │       ONEX UI       │
                         │  Glass Dashboard    │
                         └──────────┬──────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
       Config Manager         Telegram Center       Statistics
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                              Native Core
                                    │
                                    ▼
                               sing-box
```

---

# 📁 ساختار پروژه

```text
ONEX/
├── main.py
├── requirements.txt
├── version.json
├── README.md
├── README.en.md
│
├── app/
│   ├── core/
│   │   ├── protocol_core.py
│   │   └── speed_limit.py
│   │
│   ├── services/
│   │   ├── telegram_bot.py
│   │   ├── relay_vless.py
│   │   └── xhttp_siz10.py
│   │
│   ├── web/
│   │   ├── assets/
│   │   └── static/
│   │
│   └── config/
│
├── data/
├── tests/
└── legacy/
```

---

# 🚂 نصب روی Railway

ONEX برای Railway آماده است.

### مراحل

1. Repository را به Railway متصل کنید.
2. Environment Variables را وارد کنید.
3. در صورت نیاز Persistent Volume ایجاد کنید.
4. سرویس را Deploy کنید.
5. Endpoint پنل را بررسی کنید.

### Start Command

```bash
python main.py
```

یا:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### ذخیره‌سازی

برای داده‌هایی که باید بعد از Restart باقی بمانند، Persistent Volume توصیه می‌شود.

متغیر مهم:

```text
RAILWAY_VOLUME_MOUNT_PATH
```

در صورت نبود Volume، داده‌های محیط‌های Ephemeral ممکن است بعد از Restart باقی نمانند.

---

# 🖥️ نصب روی VPS

ONEX را می‌توان روی VPS لینوکسی نیز اجرا کرد.

### معماری پیشنهادی

```text
Internet
   │
   ▼
Nginx / Caddy
   │
   │ HTTPS
   ▼
ONEX / FastAPI
   │
   ├── Telegram
   ├── sing-box
   ├── Config Manager
   └── Statistics
```

### نصب

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

sudo mkdir -p /opt/onex
cd /opt/onex

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

برای اجرای دائمی در Production، استفاده از `systemd` و قرار دادن پنل پشت Nginx یا Caddy توصیه می‌شود.

---

# 🔐 متغیرهای محیطی

برخی متغیرهای اصلی:

| متغیر | کاربرد |
|---|---|
| `PORT` | پورت HTTP |
| `DATA_DIR` | مسیر داده‌ها |
| `SECRET_KEY` | کلید Secret |
| `ONEX_NATIVE_CORE` | حالت Native Core |
| `ONEX_SINGBOX_BIN` | مسیر sing-box |
| `ONEX_SINGBOX_VERSION` | نسخه sing-box |
| `ONEX_SINGBOX_AUTO_DOWNLOAD` | دریافت خودکار sing-box |
| `ONEX_TLS_CERT` | مسیر Certificate |
| `ONEX_TLS_KEY` | مسیر Private Key |
| `ONEX_UPDATE_REPO` | Repository بروزرسانی |
| `ONEX_UPDATE_BRANCH` | Branch بروزرسانی |
| `RAILWAY_API_TOKEN` | Railway API Token |
| `RAILWAY_SERVICE_ID` | Railway Service |
| `RAILWAY_ENVIRONMENT_ID` | Railway Environment |

> 🔒 هیچ Token، Password، Private Key یا Secret را داخل GitHub قرار ندهید.

---

# 🤖 Telegram

برای راه‌اندازی Bot:

1. Bot را با BotFather ایجاد کنید.
2. Bot Token را در Secret/Environment قرار دهید.
3. Telegram ID ادمین را تنظیم کنید.
4. اتصال Bot را تست کنید.
5. وضعیت Webhook را بررسی کنید.

### کانال رسمی

📢 **[عضویت در کانال @V2rayTun0](https://t.me/V2rayTun0)**

آخرین اخبار، بروزرسانی‌ها و اطلاع‌رسانی‌های پروژه از طریق کانال منتشر می‌شود.

### سازنده

👨‍💻 **[@Mehtif](https://t.me/Mehtif)**

---

# 🔄 سیستم Update

```text
GitHub
   ↓
version.json
   ↓
Version / Commit Check
   ↓
Deployment
   ↓
Health Check
   ↓
Success / Failure
```

در Railway، Credentialهای Deployment باید فقط در Environment Variables نگهداری شوند.

---

# 🧪 تست

تست Native:

```bash
python tests/smoke_native.py
```

برای تست کامل Runtime، محیط Linux و فایل اجرایی سازگار `sing-box` لازم است.

---

# 🛡️ امنیت

برای محیط Production:

- HTTPS فعال باشد.
- Secretها داخل Repository نباشند.
- Telegram Bot Token عمومی نشود.
- Railway API Token عمومی نشود.
- دسترسی Admin محدود شود.
- فایل‌های Certificate و Key محافظت شوند.
- از `data/` Backup تهیه شود.
- Firewall روی VPS فعال باشد.
- FastAPI ترجیحاً پشت Reverse Proxy اجرا شود.

---

# 📌 نسخه فعلی

## `1.3.1`

- ⚡ بهینه‌سازی Dark Mode
- 🤖 Telegram Control Center
- 👥 مدیریت کاربران Telegram
- 🔗 اتصال Telegram ID به کانفیگ
- 🔄 بهبود Update System
- ☑️ حفظ وضعیت انتخاب کانفیگ
- 🔴 فعال / غیرفعال کردن کانفیگ
- ✏️ ویرایش کانفیگ
- 🧊 Glass UI
- 📁 ساختار حرفه‌ای پروژه

---

# ❤️ حمایت از ONEX

اگر ONEX برای شما مفید است، می‌توانید با چند کار ساده از توسعه پروژه حمایت کنید:

### ⭐ Star

در GitHub به پروژه **Star** بدهید تا پروژه بیشتر دیده شود.

### 🍴 Fork

پروژه را **Fork** کنید، آن را توسعه دهید و ایده‌ها و تغییرات خود را با جامعه به اشتراک بگذارید.

### 📢 عضویت در کانال

برای دریافت اخبار و نسخه‌های جدید عضو کانال رسمی شوید:

**[@V2rayTun0](https://t.me/V2rayTun0)**

### 👨‍💻 سازنده

پروژه توسط **[@Mehtif](https://t.me/Mehtif)** توسعه داده می‌شود.

---

# 🔗 لینک‌های رسمی

| بخش | لینک |
|---|---|
| ⭐ GitHub | [HajMeTiV2/ONEX](https://github.com/HajMeTiV2/ONEX) |
| 📢 Telegram | [@V2rayTun0](https://t.me/V2rayTun0) |
| 👨‍💻 Developer | [@Mehtif](https://t.me/Mehtif) |

---

<p align="center">
  <strong>ONEX — Fast · Secure · Stable</strong>
</p>

<p align="center">
  © 2026 ONEX · Designed by @Mehtif
</p>
