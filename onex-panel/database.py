
import sqlite3
import uuid
from datetime import datetime, timedelta
import random

DB_FILE = "onex.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # جدول کاربران
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        total_traffic_gb REAL DEFAULT 50,
        used_traffic_gb REAL DEFAULT 0,
        expire_date TEXT NOT NULL,
        status TEXT DEFAULT 'active',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        last_login TEXT
    )
    """)
    
    # جدول گزارش مصرف ترافیک
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        upload_mb REAL DEFAULT 0,
        download_mb REAL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)
    
    # جدول سرورها
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL,
        sni TEXT,
        protocols TEXT DEFAULT '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]'
    )
    """)
    
    # ثبت سرور پیش‌فرض ONEX
    cursor.execute("SELECT COUNT(*) FROM servers")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO servers VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), "ONEX Core Server", "server1.onexvpn.net", 443, "server1.onexvpn.net", '["vless","vmess","trojan","shadowsocks","hysteria2","reality"]')
        )
        
    # ثبت کاربر ادمین پیش‌فرض
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        user_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO users (id, username, password, email, total_traffic_gb, used_traffic_gb, expire_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, "admin", "admin123", "info@onex.pro", 60.0, 14.5, "1404/05/20")
        )
        # دیتای تستی نمودار ۲۴ ساعته
        now = datetime.utcnow()
        for i in range(24):
            t = (now - timedelta(hours=i)).isoformat()
            cursor.execute(
                "INSERT INTO traffic_logs (user_id, timestamp, upload_mb, download_mb) VALUES (?, ?, ?, ?)",
                (user_id, t, random.randint(5, 45), random.randint(20, 180))
            )
            
    conn.commit()
    conn.close()

init_db()
