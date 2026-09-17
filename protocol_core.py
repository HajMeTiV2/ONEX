"""Optional native protocol core for ONEX.

Uses the official sing-box binary for native TCP/UDP proxy protocols.  The
panel itself remains the HTTP/WebSocket front-end, so Railway deployments can
keep using the existing VLESS WS/XHTTP paths while a host with raw TCP/UDP
publishing can expose the native listeners as well.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import shutil
import stat
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

VERSION = os.getenv("ONEX_SINGBOX_VERSION", "1.14.1").lstrip("v")
REPO = "SagerNet/sing-box"

# Native listeners. Override with ONEX_PROTOCOL_PORTS="trojan=8443,shadowsocks=8388,..."
DEFAULT_PORTS = {
    "trojan": 18443,
    "shadowsocks": 18388,
    "socks5": 11080,
    "http": 18080,
    "hysteria2": 18444,
    "vless-grpc-reality": 18445,
}

SUPPORTED = tuple(DEFAULT_PORTS)


def _arch() -> str:
    m = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, m)


def _asset_url() -> str:
    return f"https://github.com/{REPO}/releases/download/v{VERSION}/sing-box-{VERSION}-linux-{_arch()}.tar.gz"


def _port_map() -> dict[str, int]:
    out = dict(DEFAULT_PORTS)
    raw = os.getenv("ONEX_PROTOCOL_PORTS", "")
    for item in raw.split(","):
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        try:
            p = int(value.strip())
        except ValueError:
            continue
        if name.strip() in out and 1 <= p <= 65535:
            out[name.strip()] = p
    return out


class NativeCore:
    SUPPORTED = SUPPORTED

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.core_dir = self.data_dir / "sing-box"
        self.bin_path = self.core_dir / "sing-box"
        self.config_path = self.core_dir / "config.json"
        self.reality_path = self.core_dir / "reality.json"
        self.proc: asyncio.subprocess.Process | None = None
        self.ports = _port_map()
        self.last_error = ""
        self.self_signed = False
        self._certificate_pair: tuple[str, str] | None = None

    @property
    def enabled(self) -> bool:
        return os.getenv("ONEX_NATIVE_CORE", "auto").lower() not in {"0", "false", "off", "no"}

    def binary_exists(self) -> bool:
        return self._find_binary() is not None

    def is_runtime_ready(self) -> bool:
        return bool(self.proc and self.proc.returncode is None)

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
            return None
        if _arch() not in {"amd64", "arm64"}:
            self.last_error = f"Unsupported Linux architecture: {_arch()}"
            return None
        self.core_dir.mkdir(parents=True, exist_ok=True)
        url = _asset_url()
        archive = self.core_dir / f"sing-box-{VERSION}.tar.gz"
        try:
            await asyncio.to_thread(self._download, url, archive)
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
        with urllib.request.urlopen(req, timeout=20) as src, open(dst, "wb") as out:
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
        proc = await asyncio.create_subprocess_exec(str(binary), "generate", "reality-keypair", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError((err or out).decode(errors="ignore").strip() or "reality-keypair failed")
        text = out.decode(errors="ignore")
        private_key = public_key = ""
        for line in text.splitlines():
            if "PrivateKey:" in line:
                private_key = line.split("PrivateKey:", 1)[1].strip()
            elif "PublicKey:" in line:
                public_key = line.split("PublicKey:", 1)[1].strip()
        if not private_key or not public_key:
            raise RuntimeError("could not parse reality keypair")
        short_id = hashlib.sha256(private_key.encode()).hexdigest()[:8]
        data = {"private_key": private_key, "public_key": public_key, "short_id": short_id}
        self.reality_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    async def _ensure_certificate(self, domain: str) -> tuple[str, str] | None:
        cert = os.getenv("ONEX_TLS_CERT", "").strip()
        key = os.getenv("ONEX_TLS_KEY", "").strip()
        if cert and key and Path(cert).is_file() and Path(key).is_file():
            self.self_signed = False
            return cert, key
        if os.getenv("ONEX_ACME_EMAIL", "").strip():
            self.self_signed = False
            return None
        openssl = shutil.which("openssl")
        if not openssl:
            return None
        cert_path = self.core_dir / "selfsigned.crt"
        key_path = self.core_dir / "selfsigned.key"
        if not cert_path.is_file() or not key_path.is_file():
            self.core_dir.mkdir(parents=True, exist_ok=True)
            cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-keyout", str(key_path), "-out", str(cert_path), "-subj", f"/CN={domain}", "-addext", f"subjectAltName=DNS:{domain}"]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            _, err = await proc.communicate()
            if proc.returncode != 0:
                self.last_error = err.decode(errors="ignore").strip()
                return None
        self.self_signed = True
        return str(cert_path), str(key_path)

    def _tls(self, domain: str, reality: bool = False, reality_data: dict[str, str] | None = None) -> dict[str, Any]:
        if reality:
            r = reality_data or {}
            return {
                "enabled": True,
                "server_name": domain,
                "reality": {
                    "enabled": True,
                    "handshake": {"server": os.getenv("ONEX_REALITY_HANDSHAKE", "www.cloudflare.com"), "server_port": 443},
                    "private_key": r["private_key"],
                    "short_id": [r["short_id"]],
                },
            }
        cert = os.getenv("ONEX_TLS_CERT", "").strip()
        key = os.getenv("ONEX_TLS_KEY", "").strip()
        if cert and key and Path(cert).is_file() and Path(key).is_file():
            self.self_signed = False
            return {"enabled": True, "server_name": domain, "certificate_path": cert, "key_path": key}
        email = os.getenv("ONEX_ACME_EMAIL", "").strip() or f"admin@{domain}"
        cf_token = os.getenv("ONEX_CLOUDFLARE_API_TOKEN", "").strip()
        if cf_token:
            self.self_signed = False
            return {
                "enabled": True,
                "server_name": domain,
                "acme": {
                    "domain": [domain],
                    "email": email,
                    "dns01_challenge": {"provider": "cloudflare", "api_token": cf_token},
                },
            }
        if os.getenv("ONEX_ACME_EMAIL", "").strip():
            self.self_signed = False
            return {"enabled": True, "server_name": domain, "acme": {"domain": [domain], "email": email}}
        # A self-signed certificate keeps the native core checkable on a host
        # without ACME. The generated client links explicitly set insecure=1.
        pair = self._certificate_pair
        if pair:
            self.self_signed = True
            return {"enabled": True, "server_name": domain, "certificate_path": pair[0], "key_path": pair[1]}
        raise RuntimeError("TLS certificate unavailable; set ONEX_TLS_CERT/ONEX_TLS_KEY or ONEX_ACME_EMAIL")

    async def build_config(self, links: dict[str, dict[str, Any]], domain: str) -> dict[str, Any]:
        binary = await self.ensure_binary()
        if not binary:
            raise RuntimeError(self.last_error or "sing-box binary unavailable")
        reality = await self.reality_keypair(binary)
        self._certificate_pair = await self._ensure_certificate(domain)
        ports = self.ports
        inbounds: list[dict[str, Any]] = []

        active = [
            (uid, link)
            for uid, link in links.items()
            if link.get("active", True)
            and (link.get("all_protocols") or link.get("protocol") in SUPPORTED)
        ]
        users = lambda key: [{"name": uid, key: uid} for uid, _ in active]
        inbounds.append({"type": "trojan", "tag": "onex-trojan", "listen": "0.0.0.0", "listen_port": ports["trojan"], "users": [{"name": uid, "password": uid} for uid, _ in active], "tls": self._tls(domain)})
        inbounds.append({"type": "shadowsocks", "tag": "onex-ss", "listen": "0.0.0.0", "listen_port": ports["shadowsocks"], "method": os.getenv("ONEX_SS_METHOD", "aes-256-gcm"), "password": active[0][0] if active else "onex-disabled", "users": [{"name": uid, "password": uid} for uid, _ in active]})
        inbounds.append({"type": "socks", "tag": "onex-socks", "listen": "0.0.0.0", "listen_port": ports["socks5"], "users": [{"username": uid, "password": uid} for uid, _ in active]})
        inbounds.append({"type": "http", "tag": "onex-http", "listen": "0.0.0.0", "listen_port": ports["http"], "users": [{"username": uid, "password": uid} for uid, _ in active]})
        inbounds.append({"type": "hysteria2", "tag": "onex-hy2", "listen": "0.0.0.0", "listen_port": ports["hysteria2"], "users": [{"name": uid, "password": uid} for uid, _ in active], "tls": self._tls(domain)})
        inbounds.append({"type": "vless", "tag": "onex-vless-grpc-reality", "listen": "0.0.0.0", "listen_port": ports["vless-grpc-reality"], "users": [{"name": uid, "uuid": uid} for uid, _ in active], "tls": self._tls(domain, True, reality), "transport": {"type": "grpc", "service_name": "ONEX"}})
        return {"log": {"level": "warn"}, "inbounds": inbounds, "outbounds": [{"type": "direct", "tag": "direct"}]}

    async def sync(self, links: dict[str, dict[str, Any]], domain: str) -> bool:
        if not self.enabled:
            return False
        binary = await self.ensure_binary()
        if not binary:
            return False
        try:
            config = await self.build_config(links, domain)
            self.core_dir.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
            check = await asyncio.create_subprocess_exec(str(binary), "check", "-c", str(self.config_path), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await check.communicate()
            if check.returncode != 0:
                raise RuntimeError((err or out).decode(errors="ignore").strip() or "sing-box config check failed")
            await self.stop()
            self.proc = await asyncio.create_subprocess_exec(str(binary), "run", "-c", str(self.config_path), stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            await asyncio.sleep(0.25)
            if self.proc.returncode is not None:
                err = await self.proc.stderr.read()
                raise RuntimeError(err.decode(errors="ignore").strip() or "sing-box exited")
            return True
        except Exception as exc:
            self.last_error = str(exc)
            return False

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        self.proc = None

    def public_ports(self) -> dict[str, int]:
        return dict(self.ports)
