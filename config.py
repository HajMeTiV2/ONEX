
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'onex-super-secret-key-2024')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///onex.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Admin
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')

    # Server
    SERVER_PORT = int(os.environ.get('PORT', 5000))

    # Xray
    XRAY_SNI = os.environ.get('XRAY_SNI', 'www.speedtest.net')
    XRAY_ADDRESS = os.environ.get('XRAY_ADDRESS', 'your-server-ip')
    XRAY_PORT = int(os.environ.get('XRAY_PORT', 443))
    XRAY_PATH = os.environ.get('XRAY_PATH', '/ws')
    XRAY_NETWORK = os.environ.get('XRAY_NETWORK', 'ws')
    XRAY_SECURITY = os.environ.get('XRAY_SECURITY', 'tls')
    XRAY_FINGERPRINT = os.environ.get('XRAY_FINGERPRINT', 'chrome')
    PANEL_DOMAIN = os.environ.get('PANEL_DOMAIN', 'localhost:5000')

    # Branding
    PANEL_NAME = 'ONEX'
    CREATOR = '@MehTif'
    TELEGRAM_CHANNEL = '@V2rayTun0'
    TELEGRAM_CHANNEL_URL = 'https://t.me/V2rayTun0'
    CREATOR_URL = 'https://t.me/MehTif'
