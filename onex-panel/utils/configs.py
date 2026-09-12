
import json
import base64
import urllib.parse

def generate_all_configs(user, server):
    protocols = json.loads(server["protocols"])
    configs = []
    uuid_str = user["id"]
    username = user["username"]
    tag = f"ONEX | {username}"
    host = server["host"]
    port = server["port"]
    sni = server["sni"]

    # 1. VLESS WS
    if "vless" in protocols:
        configs.append({
            "protocol": "VLESS",
            "name": f"{tag} — VLESS WS (TLS)",
            "link": f"vless://{uuid_str}@{host}:{port}?encryption=none&security=tls&type=ws&host={urllib.parse.quote(sni)}&path=%2Fonex-vless#{urllib.parse.quote(tag + ' VLESS')}"
        })

    # 2. VLESS Reality
    if "reality" in protocols:
        configs.append({
            "protocol": "Reality",
            "name": f"{tag} — VLESS Reality",
            "link": f"vless://{uuid_str}@{host}:{port}?encryption=none&security=reality&sni=www.speedtest.net&fp=chrome&pbk=1yH9eXk4z3Q2...&sid=6ba7b810&type=grpc&serviceName=onex-grpc#{urllib.parse.quote(tag + ' Reality')}"
        })

    # 3. VMess
    if "vmess" in protocols:
        vmess_data = {
            "v": "2", "ps": f"{tag} VMess WS", "add": host, "port": str(port),
            "id": uuid_str, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": sni, "path": "/onex-vmess", "tls": "tls", "sni": sni
        }
        raw_v = json.dumps(vmess_data)
        b64_v = base64.b64encode(raw_v.encode('utf-8')).decode('utf-8')
        configs.append({
            "protocol": "VMess",
            "name": f"{tag} — VMess WS CDN",
            "link": f"vmess://{b64_v}"
        })

    # 4. Trojan
    if "trojan" in protocols:
        configs.append({
            "protocol": "Trojan",
            "name": f"{tag} — Trojan Secure",
            "link": f"trojan://{uuid_str}@{host}:{port}?security=tls&sni={sni}&type=ws&path=%2Fonex-trojan#{urllib.parse.quote(tag + ' Trojan')}"
        })

    # 5. Shadowsocks
    if "shadowsocks" in protocols:
        secret = uuid_str.replace("-", "")[:16]
        ss_key = base64.b64encode(f"2022-blake3-aes-128-gcm:{secret}".encode()).decode()
        configs.append({
            "protocol": "Shadowsocks",
            "name": f"{tag} — SS-2022 Turbo",
            "link": f"ss://{ss_key}@{host}:{port}#{urllib.parse.quote(tag + ' Shadowsocks')}"
        })

    # 6. Hysteria 2
    if "hysteria2" in protocols:
        configs.append({
            "protocol": "Hysteria2",
            "name": f"{tag} — Hysteria 2 (UDP)",
            "link": f"hysteria2://{uuid_str}@{host}:{port}?insecure=1&sni={sni}#{urllib.parse.quote(tag + ' Hysteria2')}"
        })

    return configs

def generate_sub_list(configs):
    raw_list = "\n".join([c["link"] for c in configs])
    return base64.b64encode(raw_list.encode('utf-8')).decode('utf-8')
