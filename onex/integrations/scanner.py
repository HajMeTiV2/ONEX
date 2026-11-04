"""ONEX Scanner: Reality/SNI target checker and Cloudflare clean-IP helpers.

* SNI scan runs on the server: a Reality inbound's "dest" is contacted by the
  server, so latency/TLS 1.3/H2 must be measured from the server.
* Clean-IP scan runs in the admin's browser (see the Scanner page), because a
  "clean" Cloudflare IP depends on the *user's* ISP, not on Railway's network.
  The server only provides the official Cloudflare ranges.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request

SNI_FILE = Path(__file__).resolve().parents[2] / "config" / "sni_reality.txt"
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Official Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4).
CF_RANGES_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]


_REPO_FILE = Path(__file__).resolve().parents[2] / "onex_repo" / "ips.txt"
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


_REPO_DIR = _REPO_FILE.parent


def _repo_lines(name: str = "ips.txt") -> list[str]:
    try:
        text = (_REPO_DIR / name).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return [x.strip() for x in text.splitlines() if x.strip() and not x.strip().startswith("#")]


def default_sni_list() -> list[str]:
    try:
        return [x.strip().lower() for x in SNI_FILE.read_text(encoding="utf-8").splitlines() if _HOST_RE.match(x.strip().lower())]
    except Exception:
        return ["www.google.com", "www.microsoft.com", "www.apple.com", "www.cloudflare.com", "www.speedtest.net"]


async def check_sni(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    res = {"host": host, "ok": False, "ms": None, "tls13": False, "h2": False, "cert_ok": False, "ip": "", "issuer": "", "error": ""}
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=timeout)
        res["ip"] = infos[0][4][0]
    except Exception:
        res["error"] = "DNS"
        return res
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    t0 = time.perf_counter()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(res["ip"], port, ssl=ctx, server_hostname=host), timeout=timeout)
        res["ms"] = int((time.perf_counter() - t0) * 1000)
        sslobj = writer.get_extra_info("ssl_object")
        res["tls13"] = (sslobj.version() == "TLSv1.3") if sslobj else False
        res["h2"] = (sslobj.selected_alpn_protocol() == "h2") if sslobj else False
        res["cert_ok"] = True
        cert = sslobj.getpeercert() if sslobj else {}
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
        res["issuer"] = issuer.get("organizationName") or issuer.get("commonName") or ""
        res["ok"] = res["tls13"] and res["h2"]
    except ssl.SSLCertVerificationError:
        res["error"] = "CERT"
    except asyncio.TimeoutError:
        res["error"] = "TIMEOUT"
    except Exception as exc:
        res["error"] = type(exc).__name__
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass
    return res


def build_router(require_perm) -> APIRouter:
    r = APIRouter(prefix="/api/scanner", tags=["scanner"])
    dep = Depends(require_perm("settings"))

    @r.get("/sni-list")
    async def sni_list(_=dep):
        return {"hosts": default_sni_list()}


    @r.get("/repository/ips")
    async def repository_ips(_=dep):
        """Return the complete bundled IP repository, not a 60-item preview."""
        path = Path(__file__).resolve().parents[2] / "onex_repo" / "ips.txt"
        try:
            rows = [x.strip() for x in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
        except Exception as exc:
            raise HTTPException(500, "مخزن IP قابل خواندن نیست") from exc
        ips = []
        seen = set()
        for value in rows:
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value) and value not in seen:
                seen.add(value)
                ips.append(value)
        return {"ok": True, "count": len(ips), "ips": ips}

    @r.get("/repository/domains")
    async def repository_domains(_=dep):
        """Domains listed in onex_repo/ips.txt (lowercase, unique)."""
        out, seen = [], set()
        for value in _repo_lines("dom.txt") + _repo_lines("ips.txt"):
            v = value.lower()
            if _DOMAIN_RE.match(v) and v not in seen:
                seen.add(v)
                out.append(v)
        return {"ok": True, "count": len(out), "ips": out}

    @r.get("/repository/ipv6")
    async def repository_ipv6(_=dep):
        """IPv6 addresses listed in onex_repo/ips.txt (unique)."""
        out, seen = [], set()
        for value in _repo_lines("ip6.txt"):
            if ":" not in value:
                continue
            try:
                v = str(ipaddress.IPv6Address(value))
            except ValueError:
                continue
            if v not in seen:
                seen.add(v)
                out.append(v)
        return {"ok": True, "count": len(out), "ips": out}

    @r.get("/repository/ech/{kind}")
    async def repository_ech(kind: str, _=dep):
        """ECH helper lists: dns resolver IPs (ech_dns.txt) or ECH domains (ech_dom.txt)."""
        if kind == "dns":
            out, seen = [], set()
            for value in _repo_lines("ech_dns.txt"):
                try:
                    v = str(ipaddress.ip_address(value))
                except ValueError:
                    continue
                if v not in seen:
                    seen.add(v)
                    out.append(v)
        elif kind == "dom":
            out, seen = [], set()
            for value in _repo_lines("ech_dom.txt"):
                v = value.lower()
                if _DOMAIN_RE.match(v) and v not in seen:
                    seen.add(v)
                    out.append(v)
        else:
            raise HTTPException(404, "not found")
        return {"ok": True, "count": len(out), "ips": out}

    @r.get("/cf-ranges")
    async def cf_ranges(_=dep):
        return {"v4": CF_RANGES_V4}

    @r.post("/sni")
    async def sni_scan(request: Request, _=dep):
        body = await request.json()
        raw = body.get("hosts") or []
        if isinstance(raw, str):
            raw = re.split(r"[\s,]+", raw)
        hosts = []
        for h in raw:
            h = str(h).strip().lower().removeprefix("https://").split("/")[0].split(":")[0]
            if _HOST_RE.match(h) and h not in hosts:
                hosts.append(h)
        if not hosts:
            raise HTTPException(400, "هیچ دامنه معتبری وارد نشده")
        hosts = hosts[:300]
        try:
            port = max(1, min(65535, int(body.get("port") or 443)))
            timeout = max(1.0, min(10.0, float(body.get("timeout") or 4)))
        except ValueError:
            raise HTTPException(400, "پورت/تایم‌اوت نامعتبر")
        sem = asyncio.Semaphore(25)

        async def one(h):
            async with sem:
                return await check_sni(h, port, timeout)

        results = await asyncio.gather(*(one(h) for h in hosts))
        results.sort(key=lambda x: (not x["ok"], x["ms"] if x["ms"] is not None else 10 ** 9))
        return {"count": len(results), "good": sum(1 for x in results if x["ok"]), "results": results}

    return r
