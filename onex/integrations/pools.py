"""ONEX managed IP and outbound proxy pools.

The pool stores operator-managed entries only. It never imports public proxy
lists automatically and never exposes proxy credentials in API responses.
"""
from __future__ import annotations
import asyncio, ipaddress, json, re, socket, ssl, sys, time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import APIRouter, Depends, HTTPException, Request

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_PROXY_SCHEMES = {"http", "https", "socks4", "socks5"}

def _m():
    # Railway starts ONEX with `python main.py`, so the application module is
    # named __main__. Importing `main` here would boot a second application
    # during every pool request and makes the add buttons appear to do nothing.
    for name in ("main", "__main__"):
        mod = sys.modules.get(name)
        if mod is not None and hasattr(mod, "DATA_DIR"):
            return mod
    import main
    return main

def _file():
    return Path(_m().DATA_DIR) / "onex_pools.json"

def _load():
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("ips", []); data.setdefault("proxies", [])
            return data
    except Exception:
        pass
    return {"ips": [], "proxies": []}

def _save(data):
    p = _file(); p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp"); tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"); tmp.replace(p)
    try: p.chmod(0o600)
    except Exception: pass

def _id(prefix):
    import secrets
    return prefix + "_" + secrets.token_hex(5)

def _clean_host(v):
    x = str(v or "").strip().lower()
    try:
        ipaddress.ip_address(x); return x
    except ValueError:
        if _HOST_RE.fullmatch(x): return x
    raise HTTPException(400, "آدرس IP یا دامنه معتبر نیست")

def _split_host_port(value, default_port=443):
    """Parse host:port without breaking IPv6 literals."""
    raw = str(value or "").strip()
    if not raw:
        raise HTTPException(400, "آدرس خالی است")
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0:
            raise HTTPException(400, "آدرس IPv6 نامعتبر است")
        host = raw[1:end]
        suffix = raw[end + 1:]
        port = int(suffix[1:]) if suffix.startswith(":") and suffix[2:] else default_port
    elif raw.count(":") == 1:
        host, port_text = raw.rsplit(":", 1)
        port = int(port_text) if port_text else default_port
    else:
        host, port = raw, default_port
    if not 1 <= int(port) <= 65535:
        raise HTTPException(400, "پورت باید بین ۱ تا ۶۵۵۳۵ باشد")
    return host.strip().lower(), int(port)

def _public_ip(row):
    return {k:v for k,v in row.items() if k not in {"username", "password"}}

def _public_proxy(row):
    out = dict(row); out.pop("username", None); out.pop("password", None)
    out["has_auth"] = bool(row.get("username") or row.get("password"))
    return out

async def _probe(host, port, timeout=3.0, tls=False):
    started=time.perf_counter(); writer=None
    try:
        ctx=None
        if tls:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        _,writer=await asyncio.wait_for(asyncio.open_connection(host,port,ssl=ctx,server_hostname=host if tls else None),timeout=timeout)
        return {"ok":True,"latency_ms":round((time.perf_counter()-started)*1000,1)}
    except Exception as exc:
        return {"ok":False,"latency_ms":round((time.perf_counter()-started)*1000,1),"error":str(exc)[:120]}
    finally:
        if writer:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass

async def _probe_proxy(row, timeout=4.0):
    """Check that the configured proxy listener is reachable.

    This deliberately checks the proxy endpoint itself, not an arbitrary
    destination. It works for HTTP and SOCKS listeners and avoids leaking
    stored credentials while still catching dead hosts and closed ports.
    """
    return await _probe(
        str(row.get("host") or ""),
        int(row.get("port") or 0),
        timeout,
        str(row.get("scheme") or "").lower() == "https",
    )

_REPO_CACHE = {}
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_REPO_DIRS = (
    _PROJECT_ROOT / "onex_repo",          # repository layout shown in GitHub
    _PROJECT_ROOT / "assets" / "onex_repo",  # backwards-compatible layout
    _PROJECT_ROOT / "assets" / "zeus_repo",  # legacy upgrade path
)

async def _repo_text(path):
    now = time.time()
    cached = _REPO_CACHE.get(path)
    if cached and now - cached[0] < 900:
        return cached[1]
    file_path = None
    for repo_dir in _REPO_DIRS:
        candidate = (repo_dir / path).resolve()
        if repo_dir in candidate.parents and candidate.is_file():
            file_path = candidate
            break
    if file_path is None:
        raise FileNotFoundError(path)
    text = file_path.read_text(encoding="utf-8", errors="ignore")
    _REPO_CACHE[path] = (now, text)
    return text

def _repo_lines(text):
    out=[]
    for raw in str(text or "").splitlines():
        x=raw.strip()
        if not x or x.startswith("#") or x.startswith("[") or x.startswith("---") or x.startswith("==="):
            continue
        if x not in out: out.append(x)
    return out

def build_router(require_perm):
    r=APIRouter(prefix="/api/pools",tags=["pools"]); dep=Depends(require_perm("settings"))
    @r.get("/repository/ips")
    async def zeus_ips(limit: int = 500, _=dep):
        try:
            text=await _repo_text("ips.txt")
            values=[]
            for x in _repo_lines(text):
                try:
                    host,port=_split_host_port(x)
                    host=_clean_host(host)
                    values.append(f"{host}:{port}" if port != 443 else host)
                except (HTTPException,ValueError,TypeError):
                    continue
            return {"ok":True,"source":"ONEX","items":values[:max(1,min(500,int(limit or 500)))]}
        except Exception as exc:
            raise HTTPException(502, "دریافت مخزن IP های ONEX ناموفق بود") from exc

    @r.get("/repository/proxies")
    async def zeus_proxies(country: str = "ALL", limit: int = 200, _=dep):
        country=str(country or "ALL").upper()
        try:
            if country != "ALL" and re.fullmatch(r"[A-Z]{2,3}", country):
                paths=[f"proxy/{country}.txt", f"proxy_vip/{country}.txt"]
            else:
                paths=["proxy/ALL.txt"]
            seen=set(); items=[]
            for path in paths:
                for value in _repo_lines(await _repo_text(path)):
                    if value not in seen:
                        seen.add(value)
                        items.append({"value":value,"country":country if country != "ALL" else "—"})
            return {"ok":True,"source":"ONEX", "country":country, "items":items[:max(1,min(200,int(limit or 200)))]}
        except Exception as exc:
            raise HTTPException(502, "دریافت مخزن Proxy های ONEX ناموفق بود") from exc

    @r.get("")
    async def get_pools(_=dep):
        d=_load(); return {"ok":True,"ips":[_public_ip(x) for x in d["ips"]],"proxies":[_public_proxy(x) for x in d["proxies"]]}
    @r.post("/ips")
    async def add_ips(request:Request,_=dep):
        b=await request.json(); raw=b.get("ips") or b.get("value") or []
        if isinstance(raw,str): raw=re.split(r"[\s,]+",raw)
        d=_load(); out=[]; invalid=[]
        for item in raw[:200]:
            try:
                host, port = _split_host_port(item)
            except (TypeError, ValueError, HTTPException):
                invalid.append(str(item).strip())
                continue
            try:
                host=_clean_host(host)
            except HTTPException:
                invalid.append(str(item).strip())
                continue
            key=f"{host}:{port}"
            if not any(f"{x['host']}:{x['port']}"==key for x in d["ips"]):
                row={"id":_id("ip"),"host":host,"port":port,"sni":str(b.get("sni") or "").strip().lower(),"enabled":True,"status":"untested","latency_ms":None,"last_check":""}
                d["ips"].append(row); out.append(row)
        if not out and invalid:
            raise HTTPException(400, "فرمت IP نامعتبر است: " + ", ".join(invalid[:3]))
        _save(d); return {"ok":True,"added":len(out),"invalid":invalid[:10],"ips":[_public_ip(x) for x in d["ips"]]}
    @r.delete("/ips/{entry_id}")
    async def delete_ip(entry_id:str,_=dep):
        d=_load(); before=len(d["ips"]); d["ips"]=[x for x in d["ips"] if x.get("id")!=entry_id]
        if len(d["ips"])==before: raise HTTPException(404,"IP پیدا نشد")
        _save(d); return {"ok":True}
    @r.delete("/ips")
    async def delete_all_ips(_=dep):
        d=_load(); count=len(d["ips"]); d["ips"]=[]; _save(d); return {"ok":True,"deleted":count}
    @r.post("/ips/check")
    async def check_ips(request:Request,_=dep):
        try:
            b=await request.json()
        except Exception:
            b={}
        ids=set(str(x) for x in (b.get("ids") or [])); d=_load(); rows=[x for x in d["ips"] if not ids or str(x.get("id")) in ids]
        sem=asyncio.Semaphore(24)
        async def one(x):
            async with sem:
                return await _check_one_ip(x)

        async def _check_one_ip(x):
            try:
                res=await _probe(str(x.get("host") or ""),int(x.get("port") or 443),3.0,bool(int(x.get("port") or 443) in {443,2053,2083,2087,2096,8443}))
            except Exception as exc:
                res={"ok":False,"latency_ms":0,"error":str(exc)[:120]}
            x.update(status="healthy" if res["ok"] else "down",latency_ms=res.get("latency_ms"),last_check=datetime.now().isoformat(),error=res.get("error","")); return x
        await asyncio.gather(*(one(x) for x in rows)); _save(d)
        good=sorted([x for x in rows if x.get("status")=="healthy"],key=lambda x:x.get("latency_ms") or 999999)
        return {"ok":True,"checked":len(rows),"healthy":len(good),"ips":[_public_ip(x) for x in good]}
    @r.post("/proxies")
    async def add_proxy(request:Request,_=dep):
        b=await request.json(); raw=str(b.get("url") or b.get("proxy") or "").strip()
        if not raw: raise HTTPException(400,"آدرس Proxy لازم است")
        try:
            u=urlsplit(raw if "://" in raw else "http://"+raw)
            scheme=u.scheme.lower()
            host=(u.hostname or "").strip().lower()
            port=int(u.port or 0)
        except (ValueError, TypeError):
            raise HTTPException(400,"آدرس Proxy یا پورت نامعتبر است")
        if scheme not in _PROXY_SCHEMES or not host or not 1 <= port <= 65535:
            raise HTTPException(400,"Proxy باید HTTP یا SOCKS4/SOCKS5 و دارای پورت معتبر باشد")
        d=_load()
        if any(x.get("scheme")==scheme and x.get("host")==host and int(x.get("port") or 0)==port for x in d["proxies"]):
            raise HTTPException(409,"این Proxy قبلاً در مخزن ثبت شده است")
        row={"id":_id("px"),"scheme":scheme,"host":host,"port":port,"username":u.username or "","password":u.password or "","country":str(b.get("country") or "").upper()[:2],"enabled":True,"status":"untested","latency_ms":None,"last_check":""}
        d["proxies"].append(row); _save(d); return {"ok":True,"proxy":_public_proxy(row)}
    @r.post("/proxies/check")
    async def check_proxies(request:Request,_=dep):
        """Check every saved proxy listener, or only the requested ids."""
        try:
            b=await request.json()
        except Exception:
            b={}
        ids=set(str(x) for x in (b.get("ids") or []))
        d=_load()
        rows=[x for x in d["proxies"] if not ids or str(x.get("id")) in ids]

        sem=asyncio.Semaphore(24)
        async def one(x):
            async with sem:
                return await _check_one_proxy(x)

        async def _check_one_proxy(x):
            try:
                res=await _probe_proxy(x, 4.0)
            except Exception as exc:
                res={"ok":False,"latency_ms":0,"error":str(exc)[:120]}
            x.update(
                status="healthy" if res["ok"] else "down",
                latency_ms=res.get("latency_ms"),
                last_check=datetime.now().isoformat(),
                error=res.get("error",""),
            )
            return x

        await asyncio.gather(*(one(x) for x in rows))
        good=sorted(
            [x for x in rows if x.get("status")=="healthy"],
            key=lambda x:x.get("latency_ms") or 999999,
        )
        _save(d)
        return {
            "ok":True,
            "checked":len(rows),
            "healthy":len(good),
            "proxies":[_public_proxy(x) for x in good],
        }
    @r.delete("/proxies/{entry_id}")
    async def delete_proxy(entry_id:str,_=dep):
        d=_load(); before=len(d["proxies"]); d["proxies"]=[x for x in d["proxies"] if x.get("id")!=entry_id]
        if len(d["proxies"])==before: raise HTTPException(404,"Proxy پیدا نشد")
        _save(d); return {"ok":True}
    @r.delete("/proxies")
    async def delete_all_proxies(_=dep):
        d=_load(); count=len(d["proxies"]); d["proxies"]=[]; _save(d); return {"ok":True,"deleted":count}
    return r
