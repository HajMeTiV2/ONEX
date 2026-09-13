import json
import base64
import urllib.parse
from config import Config


def generate_vless_config(user, request_domain=None):
    uuid_str = user.uuid_str
    
    # دامنه اختصاصی ریلوی
    domain = request_domain or Config.PANEL_DOMAIN
    
    params = {
        'type': 'ws',
        'security': 'tls',
        'sni': domain,
        'fp': 'chrome',
        'path': '/ws',
        'host': domain,
        'encryption': 'none'
    }

    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    remark = urllib.parse.quote(f'ONEX-{user.username}')

    # اتصال پورت 443 با TLS
    return f"vless://{uuid_str}@{domain}:443?{params_str}#{remark}"


def generate_vmess_config(user, request_domain=None):
    domain = request_domain or Config.PANEL_DOMAIN
    config_dict = {
        "v": "2",
        "ps": f"ONEX-{user.username}",
        "add": domain,
        "port": "443",
        "id": user.uuid_str,
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": domain,
        "path": "/ws",
        "tls": "tls",
        "sni": domain,
        "alpn": "",
        "fp": "chrome"
    }

    json_str = json.dumps(config_dict)
    b64 = base64.b64encode(json_str.encode()).decode()
    return f"vmess://{b64}"


def generate_trojan_config(user, request_domain=None):
    domain = request_domain or Config.PANEL_DOMAIN
    params = {
        'type': 'ws',
        'security': 'tls',
        'sni': domain,
        'fp': 'chrome',
        'path': '/ws',
        'host': domain
    }

    params_str = '&'.join(f'{k}={v}' for k, v in params.items())
    remark = urllib.parse.quote(f'ONEX-{user.username}')

    return f"trojan://{user.uuid_str}@{domain}:443?{params_str}#{remark}"


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
