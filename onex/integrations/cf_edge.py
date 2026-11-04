"""ONEX Edge: one-click Cloudflare Worker relay in front of the panel.

The panel uploads ``worker/onex-edge.js`` to the admin's Cloudflare account,
enables its workers.dev route (and optionally a custom domain on a Cloudflare
zone) and then appends "☁️ Edge" copies of every WebSocket config to each
subscription. Those copies connect to Cloudflare, and the Worker forwards the
stream to the panel, so accounting/limits keep working unchanged.

Settings: DATA_DIR/cf_edge.json (contains the API token; never commit it).
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request

CF_API = "https://api.cloudflare.com/client/v4"
WORKER_FILE = Path(__file__).resolve().parents[2] / "worker" / "onex-edge.js"
TOKEN_HELP_URL = "https://dash.cloudflare.com/profile/api-tokens"
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$")

DEFAULTS = {
    "enabled": False,
    "account_id": "",
    "api_token": "",
    "script_name": "",
    "workers_dev_host": "",
    "custom_domain": "",
    "secret": "",
    "include_in_sub": True,
    "clean_ips": [],
    "edge_ip_limit": 5,
    "deployed_at": "",
    "origin": "",
    "last_error": "",
}


def _m():
    for name in ("main", "__main__"):
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "LINKS"):
            return mod
    import main as mod  # noqa
    return mod


def _file() -> Path:
    return Path(_m().DATA_DIR) / "cf_edge.json"


def load() -> dict:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**DEFAULTS, **data}
    except Exception:
        pass
    return dict(DEFAULTS)


def save(data: dict) -> None:
    p = _file()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except Exception:
        pass


def edge_host(cfg: dict | None = None) -> str:
    cfg = cfg or load()
    return (cfg.get("custom_domain") or cfg.get("workers_dev_host") or "").strip().lower()


def valid_edge_secret(value: str | None, cfg: dict | None = None) -> bool:
    """Validate the secret injected into requests by the managed Worker."""
    import hmac
    expected = str((cfg or load()).get("secret") or "").strip()
    received = str(value or "").strip()
    return bool(expected and received and hmac.compare_digest(received, expected))


def public_view(cfg: dict) -> dict:
    tok = cfg.get("api_token") or ""
    out = {k: v for k, v in cfg.items() if k not in ("api_token", "secret")}
    out["has_token"] = bool(tok)
    out["token_masked"] = (tok[:4] + "…" + tok[-4:]) if len(tok) > 10 else ("•••" if tok else "")
    out["edge_host"] = edge_host(cfg)
    out["token_help_url"] = TOKEN_HELP_URL
    return out


# ---------------------------------------------------------------- Cloudflare API

class CFError(Exception):
    pass


async def _cf(method: str, path: str, token: str, **kw):
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=httpx.Timeout(40, connect=15)) as c:
        r = await c.request(method, CF_API + path, headers=headers, **kw)
    try:
        data = r.json()
    except Exception:
        raise CFError(f"Cloudflare HTTP {r.status_code}")
    if not data.get("success", False):
        errs = data.get("errors") or []
        msg = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs if isinstance(e, dict)) or f"HTTP {r.status_code}"
        raise CFError(msg)
    return data.get("result")


async def _resolve_account(token: str, account_id: str) -> str:
    if account_id:
        return account_id
    accounts = await _cf("GET", "/accounts", token, params={"per_page": 50}) or []
    if len(accounts) == 1:
        return accounts[0]["id"]
    if not accounts:
        raise CFError("هیچ اکانتی برای این توکن پیدا نشد؛ Account ID را دستی وارد کنید")
    raise CFError("توکن به چند اکانت دسترسی دارد؛ Account ID را دستی وارد کنید")


async def _ensure_subdomain(token: str, acc: str) -> str:
    try:
        res = await _cf("GET", f"/accounts/{acc}/workers/subdomain", token)
        sub = (res or {}).get("subdomain")
        if sub:
            return sub
    except CFError:
        pass
    want = "onex-" + secrets.token_hex(3)
    res = await _cf("PUT", f"/accounts/{acc}/workers/subdomain", token, json={"subdomain": want})
    return (res or {}).get("subdomain") or want


async def _zone_for(token: str, hostname: str) -> str:
    parts = hostname.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        res = await _cf("GET", "/zones", token, params={"name": cand}) or []
        if res:
            return res[0]["id"]
    raise CFError(f"دامنه {hostname} در این اکانت Cloudflare نیست")


async def deploy(cfg: dict, origin: str) -> dict:
    token = (cfg.get("api_token") or "").strip()
    if not token:
        raise CFError("API Token وارد نشده")
    if not origin or not _HOST_RE.match(origin):
        raise CFError("دامنه عمومی پنل پیدا نشد؛ پنل را یک‌بار از آدرس Railway باز کنید")
    if not WORKER_FILE.exists():
        raise CFError("فایل worker/onex-edge.js پیدا نشد")
    acc = await _resolve_account(token, (cfg.get("account_id") or "").strip())
    name = cfg.get("script_name") or ("onex-edge-" + secrets.token_hex(3))
    secret = cfg.get("secret") or secrets.token_urlsafe(24)
    metadata = {
        "main_module": "onex-edge.js",
        "compatibility_date": "2024-11-01",
        "bindings": [
            {"type": "plain_text", "name": "ORIGIN", "text": origin},
            {"type": "secret_text", "name": "KEY", "text": secret},
        ],
    }
    files = {
        "metadata": ("metadata.json", json.dumps(metadata), "application/json"),
        "onex-edge.js": ("onex-edge.js", WORKER_FILE.read_bytes(), "application/javascript+module"),
    }
    await _cf("PUT", f"/accounts/{acc}/workers/scripts/{name}", token, files=files)
    await _cf("POST", f"/accounts/{acc}/workers/scripts/{name}/subdomain", token,
              json={"enabled": True, "previews_enabled": False})
    sub = await _ensure_subdomain(token, acc)
    custom = (cfg.get("custom_domain") or "").strip().lower()
    if custom:
        if not _HOST_RE.match(custom):
            raise CFError("دامنه سفارشی نامعتبر است")
        zid = await _zone_for(token, custom)
        await _cf("PUT", f"/accounts/{acc}/workers/domains", token,
                  json={"environment": "production", "hostname": custom, "service": name, "zone_id": zid})
    cfg.update(
        enabled=True, account_id=acc, script_name=name, secret=secret, origin=origin,
        workers_dev_host=f"{name}.{sub}.workers.dev", deployed_at=datetime.now().isoformat(), last_error="",
    )
    return cfg


async def remove(cfg: dict) -> dict:
    token, acc, name = cfg.get("api_token"), cfg.get("account_id"), cfg.get("script_name")
    if token and acc and name:
        try:
            await _cf("DELETE", f"/accounts/{acc}/workers/scripts/{name}", token, params={"force": "true"})
        except CFError as exc:
            if "10007" not in str(exc):  # 10007 = script not found
                raise
    cfg.update(enabled=False, script_name="", workers_dev_host="", deployed_at="", secret="")
    return cfg


async def test(cfg: dict) -> dict:
    host = edge_host(cfg)
    if not host:
        raise CFError("Edge هنوز دیپلوی نشده")
    async with httpx.AsyncClient(timeout=15) as c:
        t0 = datetime.now()
        r = await c.get(f"https://{host}/__onex_ping")
        ms = int((datetime.now() - t0).total_seconds() * 1000)
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    return {"ok": r.status_code == 200 and data.get("edge") == "onex", "status": r.status_code, "ms": ms, "colo": data.get("colo", "")}


# ---------------------------------------------------------------- subscription variants

_TAG = " ☁️Edge"


def _rewrite_uri(uri: str, host: str, address: str, tag: str = _TAG) -> str | None:
    if uri.startswith("vmess://"):
        try:
            raw = uri[8:]
            obj = json.loads(base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8"))
        except Exception:
            return None
        if str(obj.get("net")) != "ws":
            return None
        obj.update(add=address, port="443", host=host, sni=host, tls="tls", alpn="http/1.1",
                   ps=str(obj.get("ps") or "ONEX") + tag)
        return "vmess://" + base64.b64encode(json.dumps(obj, ensure_ascii=False).encode()).decode()
    if not (uri.startswith("vless://") or uri.startswith("trojan://")):
        return None
    parts = urlsplit(uri)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    if q.get("type") != "ws" or q.get("security") == "reality":
        return None
    user = parts.netloc.rsplit("@", 1)[0] if "@" in parts.netloc else ""
    if not user:
        return None
    addr = f"[{address}]" if ":" in address and not address.startswith("[") else address
    q.update(security="tls", sni=host, host=host, alpn="http/1.1")
    q.pop("pbk", None); q.pop("sid", None); q.pop("spx", None)
    name = unquote(parts.fragment or "ONEX") + tag
    return urlunsplit((parts.scheme, f"{user}@{addr}:443", parts.path, urlencode(q, safe="/,"), quote(name, safe="")))


def edge_uids(cfg: dict | None = None) -> set[str]:
    cfg = cfg or load()
    return {str(x) for x in (cfg.get("edge_uids") or []) if str(x)}


def is_edge_only(*keys) -> bool:
    ids = edge_uids()
    return any(str(k) in ids for k in keys if k)


def edge_only_uris(uris: list[str]) -> list[str]:
    """Edge variants for the dedicated Edge subscription (ignores include_in_sub)."""
    cfg = load()
    host = edge_host(cfg)
    if not host:
        return []
    return _expand_edge(uris, cfg, host)


def _expand_edge(uris: list[str], cfg: dict, host: str) -> list[str]:
    limit = max(1, min(50, int(cfg.get("edge_ip_limit") or 5)))
    addresses = [a for a in (cfg.get("clean_ips") or []) if a][:limit] or [host]
    out: list[str] = []
    for uri in uris:
        for i, addr in enumerate(addresses):
            new = _rewrite_uri(uri, host, addr, _TAG if len(addresses) == 1 else f"{_TAG}{i + 1}")
            if new:
                out.append(new)
    return out


def extra_uris(uris: list[str]) -> list[str]:
    cfg = load()
    if not cfg.get("enabled") or not cfg.get("include_in_sub"):
        return []
    host = edge_host(cfg)
    if not host:
        return []
    return _expand_edge(uris, cfg, host)


# ---------------------------------------------------------------- panel API

async def _sync_clean_ips_to_links(clean_ips: list[str]) -> int:
    """Keep Cloudflare Edge IPs in the same link field subscriptions emit."""
    try:
        m = _m()
        changed = 0
        ids = edge_uids()
        merged = list(dict.fromkeys([str(x) for x in clean_ips if str(x).strip()]))[:50]
        async with m.LINKS_LOCK:
            for key, link in m.LINKS.items():
                is_edge = str(key) in ids or str(link.get("uuid") or "") in ids
                # only Edge configs get the Cloudflare IPs; public configs must keep their own addresses
                target = merged if is_edge else []
                old = list(link.get("clean_ips") or [])
                if not is_edge and not old:
                    continue
                if target != old:
                    link["clean_ips"] = target
                    changed += 1
        if changed:
            await m.save_state()
        return changed
    except Exception:
        return 0


def _config_count(link: dict) -> int:
    """How many real configs this sub emits (mirrors link_config_uris)."""
    pairs = link.get("ip_proto_pairs") or []
    if pairs:
        return len(pairs)
    protos = list(link.get("bundle_protocols") or []) or [link.get("protocol") or ""]
    return max(1, len(protos)) * max(1, len(link.get("clean_ips") or []))


def build_router(require_perm) -> APIRouter:
    r = APIRouter(prefix="/api/cfedge", tags=["cloudflare-edge"])
    dep = Depends(require_perm("settings"))

    def _clean_ips(raw) -> list[str]:
        items = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw or ""))
        out = []
        for x in items:
            x = str(x).strip().lower()
            if x and (_IP_RE.match(x) or _HOST_RE.match(x)) and x not in out:
                out.append(x)
        return out[:50]

    @r.get("")
    async def get_cfg(_=dep):
        return public_view(load())

    @r.post("/settings")
    async def set_cfg(request: Request, _=dep):
        body = await request.json()
        cfg = load()
        if body.get("api_token"):
            cfg["api_token"] = str(body["api_token"]).strip()[:200]
        if "account_id" in body:
            acc = str(body.get("account_id") or "").strip()
            if acc and not re.fullmatch(r"[0-9a-f]{32}", acc):
                raise HTTPException(400, "Account ID باید ۳۲ کاراکتر hex باشد")
            cfg["account_id"] = acc
        if "custom_domain" in body:
            d = str(body.get("custom_domain") or "").strip().lower()
            if d and not _HOST_RE.match(d):
                raise HTTPException(400, "دامنه سفارشی نامعتبر است")
            cfg["custom_domain"] = d
        if "include_in_sub" in body:
            cfg["include_in_sub"] = bool(body.get("include_in_sub"))
        if "edge_ip_limit" in body:
            try:
                cfg["edge_ip_limit"] = max(1, min(50, int(body.get("edge_ip_limit") or 5)))
            except (TypeError, ValueError):
                raise HTTPException(400, "سقف IP باید ۳، ۵ یا ۱۰ باشد")
            if not 1 <= cfg["edge_ip_limit"] <= 50:
                raise HTTPException(400, "سقف IP باید بین ۱ تا ۵۰ باشد")
        synced_links = 0
        if "clean_ips" in body:
            cfg["clean_ips"] = _clean_ips(body.get("clean_ips"))
        save(cfg)
        if "clean_ips" in body:
            synced_links = await _sync_clean_ips_to_links(cfg.get("clean_ips") or [])
        view = public_view(cfg)
        view["synced_links"] = synced_links
        return view

    @r.get("/sub")
    async def sub_get(request: Request, _=dep):
        cfg = load()
        m = _m()
        ids = edge_uids(cfg)
        rows = []
        async with m.LINKS_LOCK:
            items = [(k, dict(v)) for k, v in m.LINKS.items() if k in ids or str(v.get("uuid") or "") in ids]
        for key, link in items:
            rows.append({
                "uid": key, "uuid": str(link.get("uuid") or ""),
                "label": link.get("label") or key, "protocol": link.get("protocol") or "",
                "active": bool(link.get("active", True)),
                "used_bytes": int(link.get("used_bytes") or 0),
                "limit_bytes": int(link.get("limit_bytes") or 0),
                "connected_ips": int(link.get("connected_ips") or 0),
                "expires_at": link.get("expires_at"),
                "bundle_protocols": list(link.get("bundle_protocols") or []),
                "ip_limit": int(link.get("ip_limit") or 0),
                "config_count": _config_count(link),
            })
        return {"ok": True, "settings": cfg.get("edge_sub") or {}, "links": rows,
                "sub_url": f"https://{_m().get_host(request)}/sub/edge/{get_sub_token()}"}

    @r.post("/sub/settings")
    async def sub_settings(request: Request, _=dep):
        body = await request.json()
        cfg = load()
        proto = str(body.get("protocol") or "all")[:40]
        cfg["edge_sub"] = {
            "protocol": proto,
            "count": max(1, min(200, int(body.get("count") or 10))),
            "quota": max(0, min(2000, float(body.get("quota") or 0))),
            "days": max(0, min(365, int(body.get("days") or 0))),
            "users": max(0, min(100000, int(body.get("users") or 0))),
            "opt": bool(body.get("opt")),
            "ech": bool(body.get("ech")),
            "echval": str(body.get("echval") or "")[:200],
        }
        save(cfg)
        return {"ok": True, "settings": cfg["edge_sub"]}

    @r.post("/sub/mark")
    async def sub_mark(request: Request, _=dep):
        body = await request.json()
        cfg = load()
        new = [str(x)[:80] for x in (body.get("uids") or []) if str(x).strip()][:200]
        cfg["edge_uids"] = list(dict.fromkeys(list(edge_uids(cfg)) + new))
        save(cfg)
        return {"ok": True, "count": len(cfg["edge_uids"])}

    @r.post("/deploy")
    async def do_deploy(request: Request, _=dep):
        cfg = load()
        m = _m()
        origin = m.get_host(request)
        try:
            cfg = await deploy(cfg, origin)
        except (CFError, httpx.HTTPError) as exc:
            cfg["last_error"] = str(exc)
            save(cfg)
            raise HTTPException(400, f"Cloudflare: {exc}")
        save(cfg)
        synced_links = await _sync_clean_ips_to_links(cfg.get("clean_ips") or [])
        try:
            m.log_activity("edge", f"Cloudflare Edge دیپلوی شد: {edge_host(cfg)}؛ {synced_links} لینک sync شد")
        except Exception:
            pass
        view = public_view(cfg)
        view["synced_links"] = synced_links
        return view

    @r.post("/remove")
    async def do_remove(_=dep):
        cfg = load()
        try:
            cfg = await remove(cfg)
        except (CFError, httpx.HTTPError) as exc:
            raise HTTPException(400, f"Cloudflare: {exc}")
        save(cfg)
        return public_view(cfg)

    @r.post("/toggle")
    async def do_toggle(request: Request, _=dep):
        body = await request.json()
        cfg = load()
        if body.get("enabled") and not cfg.get("script_name"):
            raise HTTPException(400, "اول Edge را دیپلوی کنید")
        cfg["enabled"] = bool(body.get("enabled"))
        save(cfg)
        return public_view(cfg)

    @r.post("/test")
    async def do_test(_=dep):
        try:
            return await test(load())
        except (CFError, httpx.HTTPError, ValueError) as exc:
            return {"ok": False, "error": str(exc)}

    return r


def get_sub_token() -> str:
    """Secret path segment of the single Edge subscription (created once)."""
    cfg = load()
    tok = str(cfg.get("sub_token") or "")
    if not tok:
        tok = secrets.token_urlsafe(18)
        cfg["sub_token"] = tok
        save(cfg)
    return tok


def valid_sub_token(value) -> bool:
    import hmac
    expected = str(load().get("sub_token") or "")
    return bool(expected) and hmac.compare_digest(str(value or ""), expected)


def edge_variants(uris: list[str], addresses=None) -> list[str]:
    """Edge (Cloudflare relay) variants of normal URIs, one per address (link IPs or global IPs)."""
    cfg = load()
    host = edge_host(cfg)
    if not host:
        return []
    addrs = [a for a in (addresses or cfg.get("clean_ips") or []) if a] or [host]
    out: list[str] = []
    for uri in uris:
        for i, addr in enumerate(addrs):
            new = _rewrite_uri(uri, host, addr, _TAG if len(addrs) == 1 else f"{_TAG}{i + 1}")
            if new:
                out.append(new)
    return out
