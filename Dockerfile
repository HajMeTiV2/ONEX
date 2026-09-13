FROM node:18-alpine

WORKDIR /app

# نصب ابزارها و دانلود هسته واقعی Xray
RUN apk add --no-cache curl unzip supervisor
RUN curl -L -H "Cache-Control: no-cache" -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && \
    unzip xray.zip -d /usr/bin/xray-bin && \
    chmod +x /usr/bin/xray-bin/xray && \
    rm xray.zip

# کپی فایل‌ها و نصب پکیج‌های Node
COPY package*.json ./
RUN npm install
COPY . .

# اسکریپت راه‌اندازی همزمان پنل و موتور پروکسی
COPY supervisord.conf /etc/supervisord.conf

EXPOSE 3000
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
