#!/bin/bash

# تنظیم پورت Nginx
envsubst '$PORT' < /app/nginx.conf.template > /etc/nginx/sites-available/default

# اجرای Nginx در پس‌زمینه
nginx &

# ساخت دیتابیس و روشن کردن Xray
python -c "from app import init_db, sync_xray_config; init_db(); sync_xray_config()"

# اجرای وب سرور اصلی
exec gunicorn app:app --bind 127.0.0.1:5000 --workers 2
