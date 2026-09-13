#!/bin/bash

# تنظیم پورت Nginx
envsubst '$PORT' < /app/nginx.conf.template > /etc/nginx/sites-available/default

# ساخت دیتابیس اولیه و کانفیگ Xray
python -c "from app import init_db, sync_xray_config; init_db(); sync_xray_config()"

# ۱. اجرای سرور Nginx در پس‌زمینه
nginx &

# ۲. اجرای مستقیم و مستقل هسته Xray در پس‌زمینه
/usr/local/bin/xray -config /app/xray_config.json &

# ۳. اجرای پنل اصلی
exec gunicorn app:app --bind 127.0.0.1:5000 --workers 2
