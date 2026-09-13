
FROM node:18-alpine

WORKDIR /app

RUN apk add --no-cache curl unzip ca-certificates certbot
RUN mkdir -p /app/xray-bin && \
    curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip && \
    unzip -q xray.zip -d /app/xray-bin && \
    chmod +x /app/xray-bin/xray && \
    rm xray.zip

COPY package*.json ./
RUN npm install --production

COPY . .

ENV PORT=3000
ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
