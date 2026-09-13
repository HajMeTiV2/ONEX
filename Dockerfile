FROM node:18-alpine

WORKDIR /app

# نصب ابزارهای دانلود و دانلود مستقیم هسته Xray
RUN apk add --no-cache curl unzip
RUN curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && \
    unzip xray.zip -d /app/xray-bin && \
    chmod +x /app/xray-bin/xray && \
    rm xray.zip

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
