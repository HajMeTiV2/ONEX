"""Offline smoke checks for ONEX native configuration mapping.
Run with: python tests/smoke_native.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from protocol_core import NativeCore, _protocol_safe_advanced

base = {"tls": {"mode": "tls", "enabled": True}, "network": {"type": "ws"}, "ports": [443]}
expected = {
    "trojan": ("ws", "tls"),
    "shadowsocks": ("tcp", "none"),
    "socks5": ("tcp", "none"),
    "http": ("tcp", "tls"),
    "hysteria2": ("tcp", "tls"),
    "vless-grpc-reality": ("grpc", "reality"),
}
for protocol, pair in expected.items():
    a = _protocol_safe_advanced(base, protocol)
    assert (a["network"]["type"], a["tls"]["mode"]) == pair, (protocol, a)

assert NativeCore._transport({"network": {"type": "httpupgrade"}, "host": {"path": "/x", "host": "example.com"}})["type"] == "httpupgrade"
print("ONEX native mapping smoke tests: PASS")
