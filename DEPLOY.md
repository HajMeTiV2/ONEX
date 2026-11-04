# دیپلوی ONEX 1.5.0

## مسیرهای آماده دیپلوی

- Railway: `railway.toml` با Docker و health check روی `/health`
- Render: `render.yaml` با دیسک پایدار، برای نگه‌داری state پنل
- Fly.io: `fly.toml` با volume روی `/data`
- Koyeb: `koyeb.yaml` برای سرویس Docker
- VPS: اجرای `sudo ONEX_REPO=https://github.com/OWNER/REPO.git ./start.sh`
- نصب VPS سرویس `systemd` با کاربر محدود `onex`، restart خودکار و نگه‌داری data

پلتفرم‌های ابری معمولا فقط HTTP/HTTPS و WebSocket را عبور می‌دهند. برای TCP/UDP واقعی
مثل Reality، Hysteria2 و TUIC از Fly.io یا VPS استفاده کن. روی هر محیطی که دیسک دائمی
ندارد، حتما `DATA_DIR` را به volume وصل کن، وگرنه state پنل بعد از redeploy پاک می‌شود.

برای سرویس‌هایی که دامنه را خودکار اعلام نمی‌کنند، مقدار `ONEX_PUBLIC_URL` را دستی تنظیم کن.
نمونه متغیرها در `.env.example` قرار دارد. هیچ secret را داخل Git commit نکن.

مثل قبل: فایل‌ها رو روی ریپو push کن، Railway خودش بیلد می‌کنه (بدون Dockerfile).
هیچ تنظیم یا متغیر جدیدی لازم نیست.

- هسته Xray برای پروتکل‌های SideRail بار اول که لینک VMess WS یا SideRail VLESS XHTTP وجود داشته باشه، خودکار از گیت‌هاب دانلود می‌شه و توی پوشه دیتا (`siderail-xray`) ذخیره می‌شه.
- لاگ موفق: `SideRail core (xray) running`
- وضعیت: `GET /api/siderail/status`
