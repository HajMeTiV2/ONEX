import json
import base64
import urllib.parse
from config import Config


def get_server_address(request_domain=None):
    """اگر آدرس سرور تنظیم نشده باشد، از دامنه ریلوی استفاده میکند"""
    if Config.XRAY_ADDRESS and Config.XRAY_ADDRESS != 'your-server-ip':
        return Config.XRAY_ADDRESS
    if request_domain:
        return request_domain
    return Config.PANEL_DOMAIN


def generate_vless_config(user, request_domain=None):
    uuid_str = user.uuid_str
    address = get_server_address(request_domain)
    port = Config.XRAY_PORT
    sni = Config.XRAY_SNI if Config.XRAY_SNI != 'www.speedtest.net' else address
    path = Config.XRAY_PATH
    network = Config.XRAY_NETWORK
    security = Config.XRAY_SECURITY
    fp = Config.XRAY_FINGERPRINT

    params = {
        'type': network,
        'security': security,
        'sni': sni,
        'fp': fp,
        'path': urllib.parse.quote(path),
        'host': sni,
        'encryption': 'none'
    }

    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    remark = urllib.parse.quote(f'ONEX-{user.username}')

    return f"vless://{uuid_str}@{address}:{port}?{params_str}#{remark}"


def generate_vmess_config(user, request_domain=None):
    address = get_server_address(request_domain)
    sni = Config.XRAY_SNI if Config.XRAY_SNI != 'www.speedtest.net' else address

    config_dict = {
        "v": "2",
        "ps": f"ONEX-{user.username}",
        "add": address,
        "port": str(Config.XRAY_PORT),
        "id": user.uuid_str,
        "aid": "0",
        "scy": "auto",
        "net": Config.XRAY_NETWORK,
        "type": "none",
        "host": sni,
        "path": Config.XRAY_PATH,
        "tls": Config.XRAY_SECURITY,
        "sni": sni,
        "alpn": "",
        "fp": Config.XRAY_FINGERPRINT
    }

    json_str = json.dumps(config_dict)
    b64 = base64.b64encode(json_str.encode()).decode()
    return f"vmess://{b64}"


def generate_trojan_config(user, request_domain=None):
    password = user.uuid_str
    address = get_server_address(request_domain)
    port = Config.XRAY_PORT
    sni = Config.XRAY_SNI if Config.XRAY_SNI != 'www.speedtest.net' else address
    path = Config.XRAY_PATH
    network = Config.XRAY_NETWORK

    params = {
        'type': network,
        'security': 'tls',
        'sni': sni,
        'fp': Config.XRAY_FINGERPRINT,
        'path': urllib.parse.quote(path),
        'host': sni
    }

    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    remark = urllib.parse.quote(f'ONEX-{user.username}')

    return f"trojan://{password}@{address}:{port}?{params_str}#{remark}"


def generate_config(user, request_domain=None):
    generators = {
        'vless': generate_vless_config,
        'vmess': generate_vmess_config,
        'trojan': generate_trojan_config
    }
    return generators.get(user.protocol, generate_vless_config)(user, request_domain)


def generate_subscription_content(user, request_domain=None):
    config = generate_config(user, request_domain)
    return base64.b64encode(config.encode()).decode()


def format_bytes(bytes_val):
    if bytes_val == 0:
        return '0 B'
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(bytes_val)
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    return f"{size:.2f} {units[unit_index]}"
