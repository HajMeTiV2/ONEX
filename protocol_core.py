"""Native sing-box runtime for ONEX.

The panel remains responsible for account/state management.  This module turns
per-link advanced settings into real sing-box inbounds, validates the complete
configuration with the installed binary, and reloads it atomically with
rollback on failure.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import secrets
import shutil
import stat
import tarfile
import tempfile
import urllib.request
from copy import deepcopy
from pathlib import Path
from typing import Any

VERSION = os.getenv("ONEX_SINGBOX_VERSION", "1.14.1").lstrip("v")
REPO = "SagerNet/sing-box"

# Protocols that are actually implemented by this native runtime.
SUPPORTED = (
    "trojan",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "vless-grpc-reality",
)

# Legacy fallback ports.  A link's advanced.ports takes precedence.
DEFAULT_PORTS = {
    "trojan": 18443,
    "shadowsocks": 18388,
    "socks5": 11080,
    "http": 18080,
    "hysteria2": 18444,
    "vless-grpc-reality": 18445,
}

SUPPORTED_NETWORKS = {"tcp", "ws", "grpc", "http", "h2", "httpupgrade", "quic", "kcp", "xhttp"}
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}


def _arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)


def _asset_url() -> str:
    return f"https://github.com/{REPO}/releases/download/v{VERSION}/sing-box-{VERSION}-linux-{_arch()}.tar.gz"


def _safe_port(value: Any, fallback: int = 443) -> int:
    try:
        p = int(value)
    except Exception:
        return fallback
    return p if 1 <= p <= 65535 else fallback


def _truth(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    if value is None:
        return []
    return [x.strip() for x in str(value).split(",") if x.strip()]


def _protocol_safe_advanced(advanced: dict[str, Any], protocol: str, *, all_protocols: bool = False) -> dict[str, Any]:
    """Apply only structural defaults that the selected inbound requires.

    This prevents the UI's generic WebSocket default from accidentally making
    native SOCKS/HTTP/Shadowsocks/Hysteria2 configs invalid, while preserving
    explicit transport choices for protocols that support them.
    """
    a = deepcopy(advanced or {})
    n = a.setdefault("network", {})
    tls = a.setdefault("tls", {})
    typ = str(n.get("type") or "tcp").lower()

    if protocol in {"shadowsocks", "socks5", "http", "hysteria2"}:
        n["type"] = "tcp"
        if protocol in {"shadowsocks", "socks5"}:
            tls["mode"] = "none"
            tls["enabled"] = False
    elif protocol == "vless-grpc-reality":
        n["type"] = "grpc"
        tls["mode"] = "reality"
        tls["enabled"] = True
    elif protocol == "trojan":
        if typ not in {"tcp", "ws", "http", "h2", "grpc", "quic", "httpupgrade"}:
            n["type"] = "tcp"
        if str(tls.get("mode") or "tls").lower() == "none":
            # Trojan requires TLS. Do not silently downgrade an explicit
            # selection; validation will report it below.
            pass

    if all_protocols:
        # One account can expose all native protocols, but transports are not
        # interchangeable between them.
        if protocol in {"shadowsocks", "socks5", "http", "hysteria2"}:
            n["type"] = "tcp"
        elif protocol == "vless-grpc-reality":
            n["type"] = "grpc"
            tls["mode"] = "reality"
            tls["enabled"] = True
        elif protocol == "trojan" and str(tls.get("mode") or "tls").lower() == "reality":
            tls["mode"] = "tls"
    return a


class NativeCore:
    SUPPORTED = SUPPORTED

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.core_dir = self.data_dir / "sing-box"
        self.bin_path = self.core_dir / "sing-box"
        self.config_path = self.core_dir / "config.json"
        self.previous_path = self.core_dir / "config.previous.json"
        self.reality_path = self.core_dir / "reality.json"
        self.proc: asyncio.subprocess.Process | None = None
        self.last_error = ""
        self.self_signed = False
        self._certificate_pair: tuple[str, str] | None = None
        self.last_status: dict[str, Any] = {"running": False, "applied": False, "listeners": 0}
        self.sync_lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return os.getenv("ONEX_NATIVE_CORE", "auto").lower() not in {"0", "false", "off", "no"}

    def binary_exists(self) -> bool:
        return self._find_binary() is not None

    def is_runtime_ready(self) -> bool:
        return bool(self.proc and self.proc.returncode is None)

    @staticmethod
    def _redact_config(config: dict[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(config, dict):
            return config
        out = deepcopy(config)
        secret_keys = {"password", "private_key", "key", "token", "secret"}
        def walk(value):
            if isinstance(value, dict):
                for k in list(value):
                    if k in secret_keys and value[k]:
                        value[k] = "***"
                    else:
                        walk(value[k])
            elif isinstance(value, list):
                for item in value:
                    walk(item)
        walk(out)
        return out

    def status(self) -> dict[str, Any]:
        safe_status = dict(self.last_status)
        if "config" in safe_status:
            safe_status["config"] = self._redact_config(safe_status.get("config"))
        return {
            **safe_status,
            **self.last_status,
            "running": self.is_runtime_ready(),
            "binary": str(self._find_binary() or ""),
            "config_path": str(self.config_path),
            "last_error": self.last_error,
            "self_signed": self.self_signed,
        }

    def reality_info(self) -> dict[str, str]:
        if not self.reality_path.is_file():
            return {}
        try:
            return json.loads(self.reality_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _find_binary(self) -> Path | None:
        configured = os.getenv("ONEX_SINGBOX_BIN", "").strip()
        if configured and Path(configured).is_file():
            return Path(configured)
        found = shutil.which("sing-box")
        if found:
            return Path(found)
        if self.bin_path.is_file():
            return self.bin_path
        return None

    async def ensure_binary(self) -> Path | None:
        found = self._find_binary()
        if found:
            return found
        if os.getenv("ONEX_SINGBOX_AUTO_DOWNLOAD", "1").lower() in {"0", "false", "off", "no"}:
            self.last_error = "sing-box binary is not installed"
            return None
        if _arch() not in {"amd64", "arm64"}:
            self.last_error = f"Unsupported Linux architecture: {_arch()}"
            return None
        self.core_dir.mkdir(parents=True, exist_ok=True)
        archive = self.core_dir / f"sing-box-{VERSION}.tar.gz"
        try:
            await asyncio.to_thread(self._download, _asset_url(), archive)
            await asyncio.to_thread(self._extract, archive)
            if self.bin_path.is_file():
                self.bin_path.chmod(self.bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                return self.bin_path
        except Exception as exc:
            self.last_error = f"sing-box download/install failed: {exc}"
        return None

    @staticmethod
    def _download(url: str, dst: Path) -> None:
        req = urllib.request.Request(url, headers={"User-Agent": "ONEX/1.1"})
        with urllib.request.urlopen(req, timeout=30) as src, open(dst, "wb") as out:
            shutil.copyfileobj(src, out)

    def _extract(self, archive: Path) -> None:
        with tarfile.open(archive, "r:gz") as tf:
            member = next((m for m in tf.getmembers() if m.name.endswith("/sing-box") or m.name == "sing-box"), None)
            if not member:
                raise RuntimeError("sing-box binary was not found in release archive")
            member.name = "sing-box"
            tf.extract(member, self.core_dir)
        archive.unlink(missing_ok=True)

    async def reality_keypair(self, binary: Path) -> dict[str, str]:
        if self.reality_path.is_file():
            try:
                data = json.loads(self.reality_path.read_text(encoding="utf-8"))
                if data.get("private_key") and data.get("public_key") and data.get("short_id"):
                    return data
            except Exception:
                pass
        proc = await asyncio.create_subprocess_exec(
            str(binary), "generate", "reality-keypair",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError((err or out).decode(errors="ignore").strip() or "reality-keypair failed")
        private_key = public_key = ""
        for line in out.decode(errors="ignore").splitlines():
            if "PrivateKey:" in line:
                private_key = line.split("PrivateKey:", 1)[1].strip()
            elif "PublicKey:" in line:
                public_key = line.split("PublicKey:", 1)[1].strip()
        if not private_key or not public_key:
            raise RuntimeError("could not parse reality keypair")
        data = {"private_key": private_key, "public_key": public_key, "short_id": hashlib.sha256(private_key.encode()).hexdigest()[:8]}
        self.reality_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    async def _ensure_certificate(self, domain: str) -> tuple[str, str] | None:
        cert = os.getenv("ONEX_TLS_CERT", "").strip()
        key = os.getenv("ONEX_TLS_KEY", "").strip()
        if cert and key and Path(cert).is_file() and Path(key).is_file():
            self.self_signed = False
            return cert, key
        openssl = shutil.which("openssl")
        if not openssl:
            return None
        cert_path = self.core_dir / "selfsigned.crt"
        key_path = self.core_dir / "selfsigned.key"
        if not cert_path.is_file() or not key_path.is_file():
            self.core_dir.mkdir(parents=True, exist_ok=True)
            cmd = [
                openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-keyout", str(key_path), "-out", str(cert_path), "-subj", f"/CN={domain}",
                "-addext", f"subjectAltName=DNS:{domain}",
            ]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate()
            if proc.returncode != 0:
                self.last_error = err.decode(errors="ignore").strip()
                return None
        self.self_signed = True
        return str(cert_path), str(key_path)

    async def _tls_for(self, adv: dict[str, Any], domain: str, *, reality_data: dict[str, str] | None = None) -> dict[str, Any] | None:
        tls = adv.get("tls") or {}
        mode = str(tls.get("mode") or "tls").lower()
        if mode == "none" or not _truth(tls.get("enabled", mode != "none")):
            return None
        server_name = str(tls.get("sni") or tls.get("server_name") or domain).strip()
        alpn = _list(tls.get("alpn"))
        out: dict[str, Any] = {"enabled": True, "server_name": server_name}
        if alpn:
            out["alpn"] = alpn
        if tls.get("min_version"):
            out["min_version"] = str(tls["min_version"])
        if tls.get("max_version"):
            out["max_version"] = str(tls["max_version"])

        if mode == "reality":
            if not reality_data:
                raise RuntimeError("Reality keypair unavailable")
            r = tls.get("reality") or {}
            out["reality"] = {
                "enabled": True,
                "handshake": {
                    "server": str(r.get("handshake_server") or os.getenv("ONEX_REALITY_HANDSHAKE", "www.cloudflare.com")),
                    "server_port": _safe_port(r.get("handshake_port"), 443),
                },
                "private_key": str(r.get("private_key") or reality_data["private_key"]),
                "short_id": [str(r.get("short_id") or reality_data["short_id"])[:8]],
            }
            if r.get("max_time_difference"):
                out["reality"]["max_time_difference"] = str(r["max_time_difference"])
            return out

        custom_cert = str(tls.get("certificate_path") or "").strip()
        custom_key = str(tls.get("key_path") or "").strip()
        if custom_cert and custom_key and Path(custom_cert).is_file() and Path(custom_key).is_file():
            pair = (custom_cert, custom_key)
            self.self_signed = False
        else:
            pair = await self._ensure_certificate(domain)
        if pair:
            out["certificate_path"], out["key_path"] = pair
        else:
            raise RuntimeError("TLS certificate unavailable; set ONEX_TLS_CERT/ONEX_TLS_KEY or install openssl")
        return out

    @staticmethod
    def _listen_fields(adv: dict[str, Any], port: int) -> dict[str, Any]:
        n = adv.get("network") or {}
        l = adv.get("listener") or {}
        out: dict[str, Any] = {
            "listen": str(l.get("listen") or "0.0.0.0"),
            "listen_port": port,
        }
        mapping = {
            "bind_interface": "bind_interface",
            "routing_mark": "routing_mark",
            "netns": "netns",
            "reuse_addr": "reuse_addr",
            "tcp_fast_open": "tcp_fast_open",
            "tcp_multi_path": "tcp_multi_path",
            "disable_tcp_keep_alive": "disable_tcp_keep_alive",
            "tcp_keep_alive": "tcp_keep_alive",
            "tcp_keep_alive_interval": "tcp_keep_alive_interval",
            "udp_fragment": "udp_fragment",
            "udp_timeout": "udp_timeout",
        }
        for src, dst in mapping.items():
            if src in l and l[src] not in (None, "", False, 0):
                out[dst] = l[src]
        routing = adv.get("routing") or {}
        if _truth(routing.get("sniff")):
            # These legacy fields are still accepted by many 1.13/1.14 builds.
            out["sniff"] = True
            if routing.get("sniff_override"):
                out["sniff_override_destination"] = True
            if routing.get("sniff_timeout"):
                out["sniff_timeout"] = str(routing["sniff_timeout"])
        return out

    @staticmethod
    def _transport(adv: dict[str, Any]) -> dict[str, Any] | None:
        n = adv.get("network") or {}
        h = adv.get("host") or {}
        headers = adv.get("headers") or {}
        typ = str(n.get("type") or "tcp").lower()
        path = str(h.get("path") or n.get("path") or "/")
        host = str(h.get("host") or headers.get("host") or "")
        extra = {}
        if host:
            extra["Host"] = host
        for line in headers.get("extra") or []:
            if ":" in str(line):
                k, v = str(line).split(":", 1)
                if k.strip():
                    extra[k.strip()] = v.strip()
        if typ == "tcp":
            return None
        if typ == "ws":
            t: dict[str, Any] = {"type": "ws", "path": path}
            if extra:
                t["headers"] = extra
            tr = adv.get("transport") or {}
            if _safe_port(tr.get("max_early_data"), 0) > 0:
                t["max_early_data"] = _safe_port(tr.get("max_early_data"), 0)
                t["early_data_header_name"] = str(tr.get("early_data_header_name") or "Sec-WebSocket-Protocol")
            return t
        if typ in {"http", "h2"}:
            t = {"type": "http", "path": path}
            if host:
                t["host"] = [host]
            if extra:
                t["headers"] = extra
            return t
        if typ == "grpc":
            return {"type": "grpc", "service_name": str(h.get("service_name") or n.get("service_name") or "ONEX")}
        if typ == "quic":
            return {"type": "quic"}
        if typ == "httpupgrade":
            t = {"type": "httpupgrade", "path": path}
            if host:
                t["host"] = host
            if extra:
                t["headers"] = extra
            return t
        if typ == "xhttp":
            # XHTTP is not a sing-box V2Ray transport. Never emit a fake schema.
            return None
        if typ == "kcp":
            return None
        return None

    def _effective_ports(self, link: dict[str, Any], fallback: int, protocol: str) -> list[int]:
        adv = link.get("advanced") or {}
        ports = adv.get("ports") if isinstance(adv, dict) else None
        if _truth(link.get("all_protocols")) and isinstance(ports, list) and ports:
            try:
                idx = list(SUPPORTED).index(protocol)
            except ValueError:
                idx = 0
            if idx < len(ports):
                p = _safe_port(ports[idx], 0)
                if p:
                    return [p]
            return [fallback]
        if isinstance(ports, list) and ports:
            out = []
            for p in ports:
                p = _safe_port(p, 0)
                if p and p not in out:
                    out.append(p)
            if out:
                return out[:16]
        return [_safe_port(link.get("port"), fallback)]

    @staticmethod
    def _native_protocols_for(link: dict[str, Any]) -> list[str]:
        if _truth(link.get("all_protocols")):
            return list(SUPPORTED)
        proto = str(link.get("protocol") or "")
        return [proto] if proto in SUPPORTED else []

    @staticmethod
    def _effective_advanced(link: dict[str, Any], protocol: str) -> dict[str, Any]:
        return _protocol_safe_advanced(
            link.get("advanced") or {},
            protocol,
            all_protocols=_truth(link.get("all_protocols")),
        )


    def _validate_advanced_for_protocol(self, link: dict[str, Any], protocol: str) -> list[str]:
        a = self._effective_advanced(link, protocol)
        tls = a.get("tls") or {}
        net = a.get("network") or {}
        typ = str(net.get("type") or "tcp").lower()
        errors: list[str] = []
        mode = str(tls.get("mode") or "tls").lower()
        if typ not in SUPPORTED_NETWORKS:
            errors.append(f"Unsupported network transport: {typ}")
        if typ in {"xhttp", "kcp"}:
            errors.append(f"{typ} is not emitted by sing-box native transport schema")
        if protocol in {"socks5", "shadowsocks"} and mode != "none":
            errors.append(f"TLS mode {mode} is not supported by {protocol} inbound")
        if protocol in {"socks5", "shadowsocks", "http", "hysteria2"} and typ != "tcp":
            errors.append(f"Network transport {typ} is not supported by {protocol} native inbound")
        if protocol == "trojan" and mode == "none":
            errors.append("Trojan inbound requires TLS")
        if protocol == "http" and mode == "reality":
            errors.append("Reality is not supported by HTTP inbound")
        if protocol == "hysteria2" and mode == "reality":
            errors.append("Reality is not supported by Hysteria2 inbound")
        if protocol == "trojan" and typ not in {"tcp", "ws", "grpc", "http", "h2", "httpupgrade", "quic"}:
            errors.append(f"Transport {typ} is not valid for Trojan")
        if protocol == "vless-grpc-reality" and mode != "reality":
            errors.append("VLESS gRPC Reality requires TLS mode Reality")
        if protocol == "vless-grpc-reality" and typ != "grpc":
            errors.append("VLESS gRPC Reality requires gRPC transport")
        sid = str((tls.get("reality") or {}).get("short_id") or "")
        if mode == "reality" and sid and (len(sid) > 8 or any(c.lower() not in "0123456789abcdef" for c in sid)):
            errors.append("Reality Short ID must be 0-8 hexadecimal characters")
        if typ == "grpc" and not str((a.get("host") or {}).get("service_name") or (net.get("service_name") or "")).strip():
            errors.append("gRPC Service Name is required")
        p = a.get("ports") or []
        if not p:
            errors.append("At least one port is required")
        for value in p:
            if _safe_port(value, 0) == 0:
                errors.append(f"Invalid port: {value}")
        return errors

    def _apply_route(self, config: dict[str, Any], links: list[dict[str, Any]]) -> None:
        final = "direct"
        for link in links:
            r = (link.get("advanced") or {}).get("routing") or {}
            candidate = str(r.get("route") or "").strip()
            if candidate:
                final = candidate
                break
        if final not in {"direct", "block"}:
            raise RuntimeError(f"Unsupported final outbound '{final}'. Configure a supported outbound first.")
        outbounds = [{"type": "direct", "tag": "direct"}]
        if final == "block":
            outbounds.append({"type": "block", "tag": "block"})
        config["outbounds"] = outbounds
        config["route"] = {"final": final}

    async def build_config(self, links: dict[str, dict[str, Any]] | dict[str, Any], domain: str) -> dict[str, Any]:
        binary = await self.ensure_binary()
        if not binary:
            raise RuntimeError(self.last_error or "sing-box binary unavailable")
        reality_needed = False
        link_values: list[dict[str, Any]] = []
        if isinstance(links, dict) and links.get("preview"):
            link_values = [links]
        else:
            link_values = []
            for _uid, _link in (links or {}).items():
                if isinstance(_link, dict) and _link.get("active", True):
                    item = deepcopy(_link)
                    item.setdefault("uuid", str(_uid))
                    link_values.append(item)
        for link in link_values:
            for proto in self._native_protocols_for(link):
                adv = _protocol_safe_advanced(link.get("advanced") or {}, proto, all_protocols=_truth(link.get("all_protocols")))
                probe = dict(link)
                probe["advanced"] = adv
                reality_needed |= str((adv.get("tls") or {}).get("mode") or "tls").lower() == "reality"
                errors = self._validate_advanced_for_protocol(probe, proto)
                if errors:
                    raise RuntimeError("; ".join(errors))
        reality = {}
        if reality_needed:
            custom_pairs = []
            for link in link_values:
                for proto in self._native_protocols_for(link):
                    adv = _protocol_safe_advanced(link.get("advanced") or {}, proto, all_protocols=_truth(link.get("all_protocols")))
                    r = (adv.get("tls") or {}).get("reality") or {}
                    private_key, public_key = str(r.get("private_key") or "").strip(), str(r.get("public_key") or "").strip()
                    if private_key or public_key:
                        if not (private_key and public_key):
                            raise RuntimeError("Reality public_key and private_key must be supplied together")
                        custom_pairs.append((private_key, public_key))
            if custom_pairs:
                if len(set(custom_pairs)) != 1:
                    raise RuntimeError("All native Reality listeners must use the same keypair")
                private_key, public_key = custom_pairs[0]
                reality = {"private_key": private_key, "public_key": public_key, "short_id": ""}
            else:
                reality = await self.reality_keypair(binary)

        inbounds: list[dict[str, Any]] = []
        seen: dict[tuple[str, int], str] = {}
        groups: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
        conflicts: list[str] = []

        for link in link_values:
            for proto in self._native_protocols_for(link):
                fallback = DEFAULT_PORTS.get(proto, 443)
                for port in self._effective_ports(link, fallback, proto):
                    adv = self._effective_advanced(link, proto)
                    # Fingerprint/allow_insecure are client-side properties. They are
                    # intentionally not injected into server listeners.
                    adv.pop("fingerprint", None)
                    key_material = {"advanced": adv, "protocol": proto, "port": port}
                    key = (proto, port, json.dumps(key_material, sort_keys=True, ensure_ascii=False))
                    conflict_key = (proto, port)
                    digest = hashlib.sha256(json.dumps(key_material, sort_keys=True).encode()).hexdigest()[:10]
                    if conflict_key in seen and seen[conflict_key] != digest:
                        conflicts.append(f"Port {port} is configured differently for {proto}")
                    seen[conflict_key] = digest
                    groups.setdefault(key, []).append(link)

        if conflicts:
            raise RuntimeError("; ".join(sorted(set(conflicts))))

        for (proto, port, _), users_links in groups.items():
            # Use the first link's settings; all grouped links have identical settings.
            link = users_links[0]
            adv = self._effective_advanced(link, proto)
            listen = self._listen_fields(adv, port)
            tag = f"onex-{proto}-{port}"
            users = []
            for item in users_links:
                uid = str(item.get("uuid") or item.get("id") or "")
                if not uid:
                    # main.py stores the UUID as the dict key. Preview supplies it in uuid.
                    uid = str(item.get("preview_uuid") or secrets.token_hex(16))
                if proto == "vless-grpc-reality":
                    users.append({"name": uid, "uuid": uid})
                elif proto in {"trojan", "hysteria2"}:
                    users.append({"name": uid, "password": uid})
                elif proto == "shadowsocks":
                    users.append({"name": uid, "password": uid})
                else:
                    users.append({"username": uid, "password": uid})

            if proto == "trojan":
                inbound = {"type": "trojan", "tag": tag, **listen, "users": users}
                tls = await self._tls_for(adv, domain)
                if tls:
                    inbound["tls"] = tls
                transport = self._transport(adv)
                if transport:
                    inbound["transport"] = transport
            elif proto == "shadowsocks":
                method = str(adv.get("shadowsocks", {}).get("method") or os.getenv("ONEX_SS_METHOD", "aes-256-gcm"))
                inbound = {"type": "shadowsocks", "tag": tag, **listen, "method": method, "users": users}
            elif proto == "socks5":
                inbound = {"type": "socks", "tag": tag, **listen, "users": users}
            elif proto == "http":
                inbound = {"type": "http", "tag": tag, **listen, "users": users}
                tls = await self._tls_for(adv, domain)
                if tls:
                    inbound["tls"] = tls
            elif proto == "hysteria2":
                inbound = {"type": "hysteria2", "tag": tag, **listen, "users": users}
                tls = await self._tls_for(adv, domain)
                if not tls:
                    raise RuntimeError("Hysteria2 requires TLS")
                inbound["tls"] = tls
                hy = adv.get("hysteria2") or {}
                if hy.get("up_mbps") is not None:
                    inbound["up_mbps"] = int(hy.get("up_mbps") or 0)
                if hy.get("down_mbps") is not None:
                    inbound["down_mbps"] = int(hy.get("down_mbps") or 0)
                if hy.get("obfs_type") and hy.get("obfs_password"):
                    inbound["obfs"] = {"type": str(hy["obfs_type"]), "password": str(hy["obfs_password"])}
                if hy.get("masquerade"):
                    inbound["masquerade"] = str(hy["masquerade"])
            elif proto == "vless-grpc-reality":
                inbound = {"type": "vless", "tag": tag, **listen, "users": users}
                inbound["tls"] = await self._tls_for(adv, domain, reality_data=reality)
                inbound["transport"] = self._transport(adv) or {"type": "grpc", "service_name": "ONEX"}
            else:
                continue
            inbounds.append(inbound)

        config: dict[str, Any] = {
            "$schema": "https://sing-box.sagernet.org/schema.json",
            "log": {"level": os.getenv("ONEX_SINGBOX_LOG_LEVEL", "warn")},
            "inbounds": inbounds,
            "outbounds": [{"type": "direct", "tag": "direct"}],
        }
        self._apply_route(config, link_values)
        return config

    async def validate_config(self, config: dict[str, Any]) -> tuple[bool, str]:
        binary = await self.ensure_binary()
        if not binary:
            return False, self.last_error or "sing-box binary unavailable"
        self.core_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="validate-", suffix=".json", dir=self.core_dir)
        os.close(fd)
        tmp = Path(name)
        try:
            tmp.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
            proc = await asyncio.create_subprocess_exec(
                str(binary), "check", "-c", str(tmp),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
            detail = (err or out).decode(errors="ignore").strip()
            return proc.returncode == 0, detail
        finally:
            tmp.unlink(missing_ok=True)

    async def _sync_impl(self, links: dict[str, dict[str, Any]], domain: str) -> bool:
        if not self.enabled:
            self.last_status = {"running": False, "applied": False, "listeners": 0, "disabled": True}
            return False
        binary = await self.ensure_binary()
        if not binary:
            self.last_status = {"running": False, "applied": False, "listeners": 0}
            return False
        try:
            config = await self.build_config(links, domain)
            ok, detail = await self.validate_config(config)
            if not ok:
                raise RuntimeError(detail or "sing-box config check failed")
            self.core_dir.mkdir(parents=True, exist_ok=True)
            staged = self.core_dir / "config.staged.json"
            staged.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
            if self.config_path.is_file():
                shutil.copy2(self.config_path, self.previous_path)
            await self.stop()
            os.replace(staged, self.config_path)
            self.proc = await asyncio.create_subprocess_exec(
                str(binary), "run", "-c", str(self.config_path),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.sleep(0.35)
            if self.proc.returncode is not None:
                err = await self.proc.stderr.read()
                raise RuntimeError(err.decode(errors="ignore").strip() or "sing-box exited")
            self.last_error = ""
            self.last_status = {"running": True, "applied": True, "listeners": len(config.get("inbounds", [])), "config": config}
            return True
        except Exception as exc:
            self.last_error = str(exc)
            # Roll back the last known good config and attempt to restore it.
            if self.previous_path.is_file():
                try:
                    await self.stop()
                    shutil.copy2(self.previous_path, self.config_path)
                    self.proc = await asyncio.create_subprocess_exec(
                        str(binary), "run", "-c", str(self.config_path),
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                    )
                    await asyncio.sleep(0.25)
                except Exception as rollback_exc:
                    self.last_error = f"{self.last_error}; rollback failed: {rollback_exc}"
            self.last_status = {"running": self.is_runtime_ready(), "applied": False, "listeners": 0, "error": self.last_error}
            return False

    async def sync(self, links: dict[str, dict[str, Any]], domain: str) -> bool:
        async with self.sync_lock:
            return await self._sync_impl(links, domain)

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        self.proc = None

    async def reload(self, links: dict[str, dict[str, Any]], domain: str) -> bool:
        return await self.sync(links, domain)

    def current_config(self) -> dict[str, Any] | None:
        if not self.config_path.is_file():
            return None
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def public_ports(self) -> dict[str, int]:
        result = dict(DEFAULT_PORTS)
        cfg = self.current_config() or {}
        for inbound in cfg.get("inbounds", []):
            typ = inbound.get("type")
            port = inbound.get("listen_port")
            if typ == "vless":
                result["vless-grpc-reality"] = port
            elif typ == "trojan":
                result["trojan"] = port
            elif typ == "shadowsocks":
                result["shadowsocks"] = port
            elif typ == "socks":
                result["socks5"] = port
            elif typ == "http":
                result["http"] = port
            elif typ == "hysteria2":
                result["hysteria2"] = port
        return result
