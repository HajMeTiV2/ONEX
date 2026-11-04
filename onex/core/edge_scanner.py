"""Bounded Cloudflare/Railway endpoint scanner for ONEX.

It probes only explicitly supplied or bundled provider ranges. It is not an
open-ended port scanner. Cloudflare ranges are expanded lazily and capped.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import random
import socket
import ssl
import time
from pathlib import Path

DEFAULT_CLOUDFLARE_CIDRS = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
)


def _parse_endpoint(value: str, default_port: int = 443) -> tuple[str, int] | None:
    value = str(value or "").strip()
    if not value or value.startswith("#"):
        return None
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        try:
            return host.strip(), max(1, min(65535, int(port)))
        except ValueError:
            return None
    return value.strip("[]"), default_port


def _expand_network(raw: str, limit: int, mode: str) -> list[tuple[str, int]]:
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return []
    # Never materialise a giant network. Full mode is still bounded by the
    # request limit and sampling remains deterministic for repeatable results.
    total = max(0, net.num_addresses - (2 if net.version == 4 and net.num_addresses > 2 else 0))
    take = min(max(1, limit), total)
    if take <= 0:
        return []
    if mode == "sample" and total > take:
        rng = random.Random(str(net))
        offsets = sorted(rng.sample(range(total), take))
    else:
        offsets = range(take)
    first = int(net.network_address) + (1 if net.version == 4 and net.num_addresses > 2 else 0)
    return [(str(ipaddress.ip_address(first + i)), 443) for i in offsets]


def load_candidates(root: Path, source: str, limit: int = 80, mode: str = "sample") -> list[tuple[str, int]]:
    """Load and expand provider candidates with validation and hard caps."""
    source = "railway" if source == "railway" else "cloudflare"
    limit = max(1, min(20000, int(limit or 80)))
    values: list[str] = []
    if source == "railway":
        files = (root / "data" / "endpoint.txt", root / "config" / "endpoint.txt")
    else:
        files = (root / "data" / "cf_subnets.txt", root / "config" / "cf_subnets.txt")
    for path in files:
        if path.is_file():
            values.extend(path.read_text(errors="ignore").splitlines())
            break
    if source == "cloudflare" and not values:
        values = list(DEFAULT_CLOUDFLARE_CIDRS)
    if source == "railway" and not values:
        target = (os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("RAILWAY_STATIC_URL") or os.environ.get("ONEX_PUBLIC_URL") or "")
        target = target.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0]
        if target:
            try:
                values = [f"{item[4][0]}:443" for item in socket.getaddrinfo(target, 443, type=socket.SOCK_STREAM)]
            except OSError:
                values = []

    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    per_range = max(1, min(limit, 4096))
    for raw in values:
        raw = raw.strip()
        items = _expand_network(raw, per_range, mode) if "/" in raw else []
        if not items:
            item = _parse_endpoint(raw)
            items = [item] if item else []
        for item in items:
            if item and item not in seen:
                host, port = item
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    if not host or len(host) > 253:
                        continue
                seen.add(item)
                out.append(item)
                if len(out) >= limit:
                    return out
    return out


async def check_endpoint(host: str, port: int = 443, sni: str = "", timeout: float = 3.0, retries: int = 1) -> dict:
    started = time.perf_counter()
    last_error = ""
    for attempt in range(max(0, min(2, retries)) + 1):
        writer = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host), timeout=timeout
            )
            return {"host": host, "port": port, "ok": True,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                    "protocol": "tls", "sni": sni or host, "attempt": attempt + 1}
        except Exception as exc:
            last_error = str(exc)[:160]
            if attempt < retries:
                await asyncio.sleep(0.08 * (attempt + 1))
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    return {"host": host, "port": port, "ok": False,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "error": last_error, "sni": sni or host, "attempt": retries + 1}


async def scan(candidates: list[tuple[str, int]], sni: str = "", timeout: float = 3.0, concurrency: int = 24, retries: int = 1) -> list[dict]:
    sem = asyncio.Semaphore(max(1, min(48, concurrency)))
    unique = list(dict.fromkeys(candidates))[:4096]

    async def one(host: str, port: int) -> dict:
        async with sem:
            return await check_endpoint(host, port, sni=sni, timeout=timeout, retries=retries)

    results = await asyncio.gather(*(one(h, p) for h, p in unique))
    return sorted(results, key=lambda item: (not item["ok"], item["latency_ms"]))


def load_onex_repo_ips(root: Path, limit: int = 80, mode: str = "sample") -> list[tuple[str, int]]:
    """IPv4 addresses from the bundled onex_repo/ips.txt (unique, capped).

    sample: a random subset (different each scan). full: an evenly spaced subset.
    Non-IP lines (domains, comments, IPv6) are skipped. Returns (ip, 443) pairs.
    """
    limit = max(1, min(20000, int(limit or 80)))
    try:
        lines = (Path(root) / "onex_repo" / "ips.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    seen: set[str] = set()
    ips: list[str] = []
    for raw in lines:
        try:
            text = str(ipaddress.IPv4Address(raw.strip()))
        except ValueError:
            continue
        if text not in seen:
            seen.add(text)
            ips.append(text)
    if not ips:
        return []
    if len(ips) <= limit:
        chosen = ips
    elif mode == "full":
        step = len(ips) / limit
        chosen = [ips[int(i * step)] for i in range(limit)]
    else:
        chosen = random.sample(ips, limit)
    return [(ip, 443) for ip in chosen]


def aggregate_runs(first: dict, extra: list[dict]) -> dict:
    """Combine repeated probes of one endpoint into reliability stats.

    ok stays the first-run result when only one run exists. With several runs,
    an endpoint is healthy when at least half of its runs succeeded.
    """
    runs = [first] + list(extra or [])
    oks = [x for x in runs if x.get("ok")]
    lat = [float(x["latency_ms"]) for x in oks if x.get("latency_ms") is not None]
    pct = round(len(oks) / len(runs) * 100)
    out = dict(first)
    out.update({
        "tests": len(runs),
        "ok_count": len(oks),
        "success_pct": pct,
        "avg_latency_ms": round(sum(lat) / len(lat), 1) if lat else None,
        "jitter_ms": round(max(lat) - min(lat), 1) if len(lat) > 1 else 0.0,
    })
    if lat:
        out["latency_ms"] = out["avg_latency_ms"]
    out["ok"] = (pct >= 50) if len(runs) > 1 else bool(first.get("ok"))
    return out
