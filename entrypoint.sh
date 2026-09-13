
#!/bin/bash

# تنظیم پورت ریلوی روی Nginx
envsubst '$PORT' < /app/nginx.conf.template > /etc/nginx/sites-available/default

# ساخت دیتابیس و تنظیم کانفیگ‌های Xray
python -c "from app import init_db, sync_xray_config; init_db(); sync_xray_config()"

# اجرای Xray در پس‌زمینه
xray -config /app/xray_config.json &

# اجرای Nginx در پس‌زمینه
nginx -g "daemon off;" &

# اجرای برنامه Flask Panel
exec gunicorn app:app --bind 127.0.0.1:5000 --workers 2
