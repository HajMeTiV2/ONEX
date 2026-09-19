# 🚀 ONEX 1.3.1

<p align="center">
  <img src="onex-logo-3d.png" alt="ONEX Logo" width="260">
</p>

<h1 align="center">ONEX</h1>

<p align="center">
  <strong>Advanced Configuration Management, Native Runtime & Telegram Control Center</strong>
</p>

<p align="center">
  <a href="README.md">🇮🇷 فارسی</a> •
  <a href="README.en.md">🇬🇧 English</a>
</p>

<p align="center">
  <a href="https://github.com/HajMeTiV2/ONEX">⭐ GitHub</a> •
  <a href="https://t.me/V2rayTun0">📢 Telegram Channel</a> •
  <a href="https://t.me/Mehtif">👨‍💻 Developer</a>
</p>

---

## ✨ What is ONEX?

**ONEX** is a modern self-hosted management panel for configuration management, native `sing-box` runtime control, statistics, Relay/XHTTP services, and Telegram administration.

ONEX is **not limited to Railway**. Railway is a supported deployment target, while the project is also structured for independent Linux/VPS deployments.

> 🎯 ONEX aims to combine a fast management panel, modern glass UI, precise configuration control, and practical operational tools in one place.

---

## 🧩 Core Features

### 🛠️ Configuration Management

- Create configurations
- Edit existing configurations
- Enable / disable individual configurations
- Manage traffic limits and expiration
- Group and category management
- Persistent three-dot action menu
- Multi-selection
- Bulk operations
- Advanced Configuration
- Persistent selection state during panel refresh

### ⚡ Native Runtime

ONEX uses a Native Core for `sing-box` runtime management.

Runtime flow:

```text
Advanced UI
      ↓
Persisted State
      ↓
Native Core Builder
      ↓
Validation
      ↓
sing-box check
      ↓
Staged Configuration
      ↓
Runtime Start
      ↓
Health Check
      ↓
Commit / Rollback
```

Native changes are validated before they are considered successfully applied.

### 🌐 Protocols

- Trojan
- Shadowsocks
- SOCKS5
- HTTP Proxy
- Hysteria2
- VLESS gRPC Reality
- VLESS WebSocket Relay
- XHTTP

### 🤖 Telegram Control Center

The Telegram center provides a foundation for:

- Bot status
- Webhook status
- User statistics
- Active users
- User management
- User activation / blocking
- Telegram ID to configuration ownership
- Broadcast messaging
- Notifications
- Activity logs
- Bot settings

### 🎨 UI

- Modern Glass UI
- Light and Dark themes
- Responsive layout
- Management cards
- Statistics dashboard
- Persistent three-dot menu
- Per-configuration enable/disable control
- Dark Mode performance optimization

---

# 🏗️ Architecture

```text
                         ┌─────────────────────┐
                         │       ONEX UI       │
                         │  Glass Dashboard    │
                         └──────────┬──────────┘
                                    │
             ┌──────────────────────┼──────────────────────┐
             │                      │                      │
             ▼                      ▼                      ▼
       Config Manager         Telegram Center       Statistics
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    ▼
                              Native Core
                                    │
                                    ▼
                               sing-box
```

---

# 📁 Project Structure

```text
ONEX/
├── main.py
├── requirements.txt
├── version.json
├── README.md
├── README.en.md
│
├── app/
│   ├── core/
│   │   ├── protocol_core.py
│   │   └── speed_limit.py
│   │
│   ├── services/
│   │   ├── telegram_bot.py
│   │   ├── relay_vless.py
│   │   └── xhttp_siz10.py
│   │
│   ├── web/
│   │   ├── assets/
│   │   └── static/
│   │
│   └── config/
│
├── data/
├── tests/
└── legacy/
```

---

# 🚂 Railway Deployment

ONEX is Railway-ready.

### Steps

1. Connect the repository to Railway.
2. Configure environment variables.
3. Attach a Persistent Volume when persistent state is required.
4. Deploy the service.
5. Verify the application endpoint.

### Start Command

```bash
python main.py
```

or:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### Persistent Storage

Use a persistent Railway Volume when data must survive restarts.

Important variable:

```text
RAILWAY_VOLUME_MOUNT_PATH
```

Without persistent storage, data in ephemeral environments may not survive a restart or redeploy.

---

# 🖥️ VPS Deployment

ONEX can also run on a Linux VPS.

### Recommended Architecture

```text
Internet
   │
   ▼
Nginx / Caddy
   │
   │ HTTPS
   ▼
ONEX / FastAPI
   │
   ├── Telegram
   ├── sing-box
   ├── Config Manager
   └── Statistics
```

### Installation

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip

sudo mkdir -p /opt/onex
cd /opt/onex

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

For production, use `systemd` and place the application behind Nginx or Caddy with HTTPS.

---

# 🔐 Environment Variables

Important variables include:

| Variable | Purpose |
|---|---|
| `PORT` | HTTP port |
| `DATA_DIR` | Data directory |
| `SECRET_KEY` | Persistent application secret |
| `ONEX_NATIVE_CORE` | Native Core mode |
| `ONEX_SINGBOX_BIN` | `sing-box` executable path |
| `ONEX_SINGBOX_VERSION` | Expected `sing-box` version |
| `ONEX_SINGBOX_AUTO_DOWNLOAD` | Automatic binary download |
| `ONEX_TLS_CERT` | Certificate path |
| `ONEX_TLS_KEY` | Private key path |
| `ONEX_UPDATE_REPO` | Update repository |
| `ONEX_UPDATE_BRANCH` | Update branch |
| `RAILWAY_API_TOKEN` | Railway API token |
| `RAILWAY_SERVICE_ID` | Railway service |
| `RAILWAY_ENVIRONMENT_ID` | Railway environment |

> 🔒 Never commit tokens, passwords, private keys, or other secrets to GitHub.

---

# 🤖 Telegram

To configure the Bot:

1. Create the Bot with BotFather.
2. Store the Bot Token in secret/environment storage.
3. Configure the administrator Telegram ID.
4. Test the Bot connection.
5. Verify the Webhook status.

### Official Channel

📢 **[Join @V2rayTun0](https://t.me/V2rayTun0)**

Project news, updates, and service announcements are published through the official channel.

### Developer

👨‍💻 **[@Mehtif](https://t.me/Mehtif)**

---

# 🔄 Update System

```text
GitHub
   ↓
version.json
   ↓
Version / Commit Check
   ↓
Deployment
   ↓
Health Check
   ↓
Success / Failure
```

Railway deployment credentials should remain server-side in environment/secret storage.

---

# 🧪 Testing

Native smoke test:

```bash
python tests/smoke_native.py
```

Full runtime validation requires a Linux environment and a compatible `sing-box` executable.

---

# 🛡️ Security

For production:

- Enable HTTPS.
- Keep secrets out of the repository.
- Never expose the Telegram Bot Token.
- Never expose the Railway API Token.
- Restrict administrative access.
- Protect certificate and Reality key material.
- Back up persistent data.
- Enable a VPS firewall.
- Prefer a reverse proxy in front of FastAPI.

---

# 📌 Current Release

## `1.3.1`

- ⚡ Dark Mode performance improvements
- 🤖 Telegram Control Center
- 👥 Telegram user management
- 🔗 Telegram ID / configuration ownership
- 🔄 Update System improvements
- ☑️ Persistent configuration selection
- 🔴 Per-configuration enable/disable control
- ✏️ Configuration editing
- 🧊 Glass UI
- 📁 Professional project structure

---

# ❤️ Support ONEX

If ONEX is useful to you, you can support the project in a few simple ways:

### ⭐ Star

Give the repository a **Star** on GitHub to help more people discover ONEX.

### 🍴 Fork

**Fork** the project, improve it, experiment with it, and share your changes with the community.

### 📢 Join the Channel

Stay up to date with project news and releases:

**[@V2rayTun0](https://t.me/V2rayTun0)**

### 👨‍💻 Developer

ONEX is developed by **[@Mehtif](https://t.me/Mehtif)**.

---

# 🔗 Official Links

| Section | Link |
|---|---|
| ⭐ GitHub | [HajMeTiV2/ONEX](https://github.com/HajMeTiV2/ONEX) |
| 📢 Telegram | [@V2rayTun0](https://t.me/V2rayTun0) |
| 👨‍💻 Developer | [@Mehtif](https://t.me/Mehtif) |

---

<p align="center">
  <strong>ONEX — Fast · Secure · Stable</strong>
</p>

<p align="center">
  © 2026 ONEX · Designed by @Mehtif
</p>
