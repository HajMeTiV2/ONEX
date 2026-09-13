FROM python:3.11-slim

# نصب Nginx، curl و unzip برای دریافت هسته Xray
RUN apt-get update && apt-get install -y nginx curl unzip gettext-base procps && rm -rf /var/lib/apt/lists/*

# دانلود و نصب آخرین نسخه Xray Core
RUN curl -L https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -o /tmp/xray.zip && \
    unzip /tmp/xray.zip -d /usr/local/bin/ xray && \
    rm /tmp/xray.zip && \
    chmod +x /usr/local/bin/xray

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# مجوز دادن به فایل استارت
RUN chmod +x entrypoint.sh

CMD ["/app/entrypoint.sh"]
