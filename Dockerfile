FROM python:3.11-slim

# نصب ابزارهای مورد نیاز
RUN apt-get update && apt-get install -y nginx curl unzip gettext-base && rm -rf /var/lib/apt/lists/*

# دانلود و نصب Xray Core
RUN curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o /tmp/xray.zip && \
    unzip /tmp/xray.zip -d /usr/local/bin/ xray && \
    rm /tmp/xray.zip && \
    chmod +x /usr/local/bin/xray

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

#  مهم: دادن دسترسی اجرا به فایل اسکریپت
RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]
