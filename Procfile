FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# نصب کتابخانه‌ها
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# کپی کردن بقیه فایل‌های پروژه
COPY . .

# اجرای ساخت دیتابیس و پنل
CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && gunicorn app:app --bind 0.0.0.0:$PORT --workers 2"]
