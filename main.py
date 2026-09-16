# ============================================================
# Railway Ready
# Designed by @Mehtif
# ============================================================
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import string
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs
import aiofiles
import httpx
import uvicorn
from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.responses import (
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# APP
# ============================================================

APP_NAME = "ONEX"
APP_VERSION = "13.10.0"

SUPPORT_USERNAME = "@V2rayTun0"
SUPPORT_URL = "https://t.me/V2rayTun0"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)

# ============================================================
# TIMEZONE
# ============================================================

try:
    from zoneinfo import ZoneInfo

    IRAN_TZ = ZoneInfo("Asia/Tehran")

except Exception:
    IRAN_TZ = None


# ============================================================
# RAILWAY
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get(
            "DATA_DIR",
            "./data",
        ),
    )
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
TG_FILE = DATA_DIR / "telegram_settings.json"

SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOCKS
# ============================================================

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            existing = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if existing:
                return existing

        generated = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:
        logger.warning(
            "Could not persist SECRET_KEY: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "port": PORT,
    "secret": SECRET_KEY,
    "host": os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    ),
}


# ============================================================
# STATE
# ============================================================

LINKS: dict = {}
SUBS: dict = {}
SESSIONS: dict = {}
connections: dict = {}
CATEGORIES: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)

hourly_traffic = defaultdict(int)

http_client: httpx.AsyncClient | None = None


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
    "vmess-ws",
    "trojan-ws",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
    "wireguard",
    "highspeed-demo",
    "gaming-lite-demo",
)

PROTOCOL_LABELS = {
    "vless-ws": "Vortex Link",
    "xhttp-packet-up": "XPacket Flow",
    "xhttp-stream-up": "XStream Pulse",
    "xhttp-stream-one": "XStream Core",
    "vmess-ws": "VMesh Nova",
    "trojan-ws": "Trojan Glide",
    "shadowsocks": "Shadow Mesh",
    "socks5": "Socket Guard",
    "http": "Web Shield",
    "hysteria2": "Hysteria Nova",
    "tuic": "TUIC Blaze",
    "wireguard": "WireGuard Orbit",
    "highspeed-demo": "Turbo Surge",
    "gaming-lite-demo": "Game Pulse",
}

PROTOCOL_ALIASES = {
    "vmess": "vmess-ws", "trojan": "trojan-ws", "ss": "shadowsocks",
    "socks": "socks5", "hy2": "hysteria2", "hysteria": "hysteria2",
}

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
)

DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    return value if value in PROTOCOLS else DEFAULT_PROTOCOL


# ============================================================
# LOGGING
# ============================================================

def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "level": level,
            "message": message,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# HELPERS
# ============================================================

def escape_html(value) -> str:
    return (
        str(
            value
            if value is not None
            else ""
        )
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def safe_int(
    value,
    default=0,
    minimum=0,
    maximum=None,
):
    try:
        number = int(value)
    except Exception:
        number = default

    if number < minimum:
        number = minimum

    if maximum is not None and number > maximum:
        number = maximum

    return number


def safe_float(
    value,
    default=0.0,
    minimum=0.0,
):
    try:
        number = float(value)
    except Exception:
        number = default

    return max(
        minimum,
        number,
    )


def generate_uuid():
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def random_config_name(existing=None):
    existing = existing or set()
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(80):
        length = secrets.randbelow(6) + 8
        name = "".join(secrets.choice(alphabet) for _ in range(length))
        if name not in existing and name and not name[0].isdigit():
            return name
    return secrets.token_hex(6)

def sanitize_config_name(name: str) -> str:
    if not name:
        return random_config_name()
    # Keep the project/config separator so generated names remain readable.
    cleaned = "".join(
        ch for ch in str(name)
        if ch.isascii() and (ch.isalnum() or ch in "-_" )
    ).strip("-_ ")
    if not cleaned:
        return random_config_name()
    if cleaned[0].isdigit():
        cleaned = "a" + cleaned
    return cleaned[:40]

def auto_config_name() -> str:
    return random_config_name()


def project_config_name(existing=None) -> str:
    """Generate a unique config remark/name with the project prefix first."""
    existing = existing or set()
    for _ in range(80):
        name = f"{APP_NAME}-{random_config_name()}"
        if name not in existing:
            return name
    return f"{APP_NAME}-{secrets.token_hex(6)}"


def now_ir():
    if IRAN_TZ:
        return datetime.now(IRAN_TZ)

    return datetime.now()


def uptime():
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    h = seconds // 3600

    m = (
        seconds
        % 3600
    ) // 60

    s = (
        seconds
        % 60
    )

    return (
        f"{h:02d}:"
        f"{m:02d}:"
        f"{s:02d}"
    )


def fmt_bytes(value: int):
    value = int(
        value or 0
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.1f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024 ** 2:.2f} MB"
        )

    return (
        f"{value / 1024 ** 3:.2f} GB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "GB"
    ).upper()

    if unit == "TB":
        return int(
            value
            * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value
            * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value
            * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value
            * 1024
        )

    return int(value)


def parse_speed_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "MBIT"
    ).upper()

    if unit == "MBIT":
        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "KB":
        return int(
            value * 1024
        )

    if unit == "MB":
        return int(
            value
            * 1024
            * 1024
        )

    return int(value)


def is_link_expired(
    link: dict,
):
    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expiry
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
):
    if link is None:
        return False

    if not link.get(
        "active",
        True,
    ):
        return False

    if is_link_expired(link):
        return False

    limit = int(
        link.get(
            "limit_bytes",
            0,
        )
        or 0
    )

    used = int(
        link.get(
            "used_bytes",
            0,
        )
        or 0
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def unique_ips_for_uuid(
    uuid: str,
):
    return {
        connection.get("ip")
        for connection in connections.values()
        if connection.get("uuid") == uuid
        and connection.get("ip")
    }


def client_ip(
    request: Request,
):
    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
        )

    real = request.headers.get(
        "x-real-ip"
    )

    if real:
        return real.strip()

    if request.client:
        return request.client.host

    return "unknown"


def is_ip_allowed(
    link: dict | None,
    uuid: str,
    ip: str,
):
    if link is None:
        return False

    limit = int(
        link.get(
            "ip_limit",
            0,
        )
        or 0
    )

    if limit <= 0:
        return True

    ips = unique_ips_for_uuid(uuid)

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        forwarded = request.headers.get(
            "x-forwarded-host"
        )

        normal = request.headers.get(
            "host"
        )

        host = (
            forwarded
            or normal
        )

        if host:
            host = host.split(":")[0].strip()

            CONFIG["host"] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG["host"]


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


# ONEX default owner credentials.
# First deployment starts with username=admin / password=admin.
# After the owner changes credentials from Settings, the saved values are used.
_env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
_env_user = os.environ.get("ADMIN_USERNAME", "admin").strip().lower() or "admin"
AUTH = {
    "username": _env_user,
    "password_hash": hash_password(_env_pw or "admin"),
    "password_configured": True,
    "credentials_version": 1,
}

# Sub-admin accounts (panel operators with granular permissions)
ADMIN_ACCOUNTS: dict = {}
# session_token -> {"role": "owner"|"admin", "admin_id": str|None, "username": str}
SESSION_META: dict = {}

ALL_PERMS = (
    "dash", "configs", "create", "stats", "logs",
    "settings", "support", "telegram", "news", "admins",
)
DEFAULT_PERMS = {p: True for p in ALL_PERMS}


def default_admin_record(username: str, password: str, **kwargs) -> dict:
    return {
        "id": secrets.token_hex(8),
        "username": username.strip().lower(),
        "password_hash": hash_password(password),
        "label": kwargs.get("label") or username,
        "limit_bytes": int(kwargs.get("limit_bytes") or 0),
        "used_bytes": 0,
        "expires_at": kwargs.get("expires_at"),
        "active": True,
        "blocked": False,
        "permissions": {**DEFAULT_PERMS, **(kwargs.get("permissions") or {})},
        "created_at": datetime.now().isoformat(),
    }


def find_admin_by_username(username: str):
    u = (username or "").strip().lower()
    for aid, a in ADMIN_ACCOUNTS.items():
        if a.get("username") == u:
            return aid, a
    return None, None


def admin_is_valid(admin: dict) -> bool:
    if not admin or admin.get("blocked") or not admin.get("active", True):
        return False
    exp = admin.get("expires_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(str(exp)):
                return False
        except Exception:
            pass
    limit = int(admin.get("limit_bytes") or 0)
    used = int(admin.get("used_bytes") or 0)
    if limit > 0 and used >= limit:
        return False
    return True



# ============================================================
# LOGIN BRUTE-FORCE PROTECTION
# ============================================================
# Maximum failed login attempts per IP inside the rolling window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 30 * 60  # 30 minutes lockout
LOGIN_MIN_PASSWORD_LENGTH = 6

LOGIN_FAILURES = defaultdict(deque)
LOGIN_LOCKED_UNTIL = {}


def _cleanup_login_state(ip: str, now: float | None = None):
    now = now if now is not None else time.time()

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until and locked_until <= now:
        LOGIN_LOCKED_UNTIL.pop(ip, None)

    failures = LOGIN_FAILURES.get(ip)
    if not failures:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    while failures and failures[0] <= cutoff:
        failures.popleft()

    if not failures:
        LOGIN_FAILURES.pop(ip, None)


def login_is_blocked(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until > now:
        return True, max(1, int(locked_until - now))

    return False, 0


def register_login_failure(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    failures = LOGIN_FAILURES.setdefault(ip, deque())
    failures.append(now)

    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        LOGIN_LOCKED_UNTIL[ip] = now + LOGIN_LOCKOUT_SECONDS
        failures.clear()
        log_activity(
            "auth",
            f"IP به دلیل تلاش‌های متعدد ورود ناموفق به مدت {LOGIN_LOCKOUT_SECONDS // 60} دقیقه مسدود شد: {ip}",
            "err",
        )
        return True, LOGIN_LOCKOUT_SECONDS

    return False, max(0, LOGIN_MAX_ATTEMPTS - len(failures))


def clear_login_failures(ip: str):
    LOGIN_FAILURES.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)


# ============================================================
# SESSION
# ============================================================

SESSION_COOKIE = "pixonpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session(meta: dict | None = None) -> str:

    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )
        SESSION_META[token] = meta or {"role": "owner", "admin_id": None, "username": "owner"}

    return token


async def is_valid_session(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(token)

        if expiry is None:
            return False

        if expiry < time.time():

            SESSIONS.pop(
                token,
                None,
            )

            return False

        return True


async def destroy_session(
    token: str | None,
):
    if not token:
        return

    async with SESSIONS_LOCK:
        SESSIONS.pop(
            token,
            None,
        )
        SESSION_META.pop(token, None)


def get_session_meta(token: str | None) -> dict:
    if not token:
        return {"role": "owner", "admin_id": None, "username": "owner", "permissions": {p: True for p in ALL_PERMS}}
    meta = dict(SESSION_META.get(token) or {"role": "owner", "admin_id": None, "username": "owner"})
    if meta.get("role") == "owner":
        meta["permissions"] = {p: True for p in ALL_PERMS}
    else:
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "") or {}
        meta["permissions"] = {p: bool((admin.get("permissions") or {}).get(p, False)) for p in ALL_PERMS}
        meta["blocked"] = bool(admin.get("blocked"))
    return meta


def require_perm(perm: str):
    async def _dep(request: Request, token=Depends(require_auth)):
        meta = get_session_meta(token)
        if meta.get("role") == "owner":
            return token
        if not (meta.get("permissions") or {}).get(perm):
            raise HTTPException(status_code=403, detail="دسترسی به این بخش مجاز نیست")
        return token
    return _dep


async def require_auth(
    request: Request,
):
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await is_valid_session(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    meta = get_session_meta(token)
    if meta.get("role") == "admin":
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "")
        if not admin_is_valid(admin or {}):
            await destroy_session(token)
            raise HTTPException(status_code=401, detail="حساب منقضی یا مسدود شده است")

    return token


def set_auth_cookie(
    response,
    request: Request,
    token: str,
):
    forwarded_proto = (
        request.headers
        .get(
            "x-forwarded-proto",
            "",
        )
        .lower()
    )

    is_https = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=is_https,
    )


# ============================================================
# VLESS LINK GENERATION
# ============================================================

def generate_vless_link(
    uuid: str, host: str, remark: str = "ONEX",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None,
):
    protocol = normalize_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT)
    alpn_value = (alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    label = quote(str(remark or "ONEX"), safe="")
    if protocol == "vless-ws":
        q = {"encryption":"none","security":"tls","type":"ws","host":host,"path":f"/ws/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":mode,"host":host,"path":f"/xhttp-siz10/{mode}/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2": return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "wireguard": return f"wireguard://{uuid}@{host}:{port_value}?publicKey={uuid}#{label}"
    if protocol == "highspeed-demo":
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":"stream-up","host":host,"path":f"/xhttp-siz10/stream-up/{uuid}","sni":host,"fp":fp,"alpn":"h2,http/1.1"}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "gaming-lite-demo":
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0&obfs=salamander#{label}"
    return f"vless://{uuid}@{host}:{port_value}"

def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=str(link.get("label") or "Config"),
        protocol=link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=link.get(
            "alpn"
        ),
        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


def get_link_info(
    link: dict,
    uid: str,
    host: str,
):
    connected_count = len(unique_ips_for_uuid(uid))
    is_active = is_link_allowed(link)
    limit_b = int(link.get("limit_bytes", 0) or 0)
    used_b = int(link.get("used_bytes", 0) or 0)
    is_expired = is_link_expired(link) or (limit_b > 0 and used_b >= limit_b)
    if not is_active or is_expired:
        status_color = "red"
    elif connected_count > 0:
        status_color = "green"
    else:
        status_color = "gray"
    clean_ips = link.get("clean_ips") or []
    cfg_count = int(link.get("config_count") or 1)
    show_vless = len(clean_ips) <= 1 and cfg_count <= 1
    cat = CATEGORIES.get(str(link.get("category_id") or "0")) or {}
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_active,
        "used_bytes": used_b,
        "limit_bytes": limit_b,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "clean_ips": clean_ips,
        "alarm_enabled": bool(link.get("alarm_enabled", False)),
        "category_id": str(link.get("category_id") or "0"),
        "sort_order": int(link.get("sort_order") or 0),
        "category_number": int(cat.get("number", 0)),
        "category_name": str(cat.get("name", "عمومی")),
        "config_count": cfg_count,
        "status_color": status_color,
        "connected_ips": connected_count,
        "show_vless": show_vless,
        "vless": vless_link_for_link(link, uid, host) if show_vless else "",
        "vless_full": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            raw = await file.read()

        data = json.loads(raw)

        LINKS.update(
            data.get(
                "links",
                {},
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {},
            )
        )

        CATEGORIES.update(
            data.get(
                "categories",
                {},
            )
        )

        ADMIN_ACCOUNTS.clear()
        ADMIN_ACCOUNTS.update(data.get("admin_accounts") or {})

        stored_password = data.get(
            "password_hash"
        )
        stored_username = str(data.get("username") or "").strip().lower()
        stored_cred_version = int(data.get("credentials_version") or 0)

        # One-time migration from the old PX/ONEX setup screen.
        # Existing legacy credentials are intentionally replaced with admin/admin.
        if stored_cred_version < 1:
            AUTH["username"] = "admin"
            AUTH["password_hash"] = hash_password("admin")
            AUTH["password_configured"] = True
            AUTH["credentials_version"] = 1
            logger.info("Legacy credentials migrated to ONEX default admin/admin")
        else:
            if stored_username:
                AUTH["username"] = stored_username
            if stored_password:
                AUTH["password_hash"] = stored_password
            AUTH["password_configured"] = True
            AUTH["credentials_version"] = stored_cred_version

        # Remove the legacy automatically-created default config.
        await remove_legacy_default_links()

        # Compatibility for older records
        for uid, link in LINKS.items():

            link.setdefault(
                "protocol",
                DEFAULT_PROTOCOL,
            )

            link.setdefault(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            )

            link.setdefault(
                "alpn",
                "",
            )

            link.setdefault(
                "port",
                DEFAULT_PORT,
            )

            link.setdefault(
                "ip_limit",
                0,
            )

            link.setdefault(
                "speed_limit_bytes",
                0,
            )

            link.setdefault(
                "connection_limit",
                0,
            )

            link.setdefault(
                "fragment",
                "off",
            )

            link.setdefault(
                "used_bytes",
                0,
            )
            link.setdefault("clean_ips", [])
            link.setdefault("alarm_enabled", False)
            link.setdefault("category_id", "0")
            link.setdefault("config_count", 1)
            link.setdefault("sort_order", 0)
            link.setdefault("usage_history", [])

        logger.info(
            "State loaded: %d links / %d subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "Could not load state: %s",
            exc,
        )


async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "categories":
                    dict(CATEGORIES),

                "admin_accounts":
                    dict(ADMIN_ACCOUNTS),

                "username":
                    AUTH.get("username", "admin"),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "credentials_version":
                    1,

                "saved_at":
                    datetime.now().isoformat(),
            }

            temp_file = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            temp_file.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "Could not save state: %s",
                exc,
            )


# ============================================================
# DEFAULT LINK
# ============================================================

async def ensure_default_categories():
    # گروه‌های پیش‌فرض ساخته نمی‌شوند — کاربر خودش می‌سازد
    return


async def remove_legacy_default_links():
    """Remove the old automatically-created default config from persisted state."""
    removed = []
    async with LINKS_LOCK:
        for uid, link in list(LINKS.items()):
            if link.get("is_default") or str(link.get("label") or "").strip() == "لینک پیش‌فرض":
                removed.append(uid)
                del LINKS[uid]
    if removed:
        logger.info("Removed %d legacy default link(s)", len(removed))


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
):

    protocol = normalize_protocol(protocol)

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):
        port = DEFAULT_PORT

    uid = generate_uuid()

    clean_label = sanitize_config_name((label or "").strip() or random_config_name())
    project_prefix = f"{APP_NAME}-"
    if not clean_label.lower().startswith(project_prefix.lower()):
        clean_label = f"{project_prefix}{clean_label}"

    record = {
        "label":
            clean_label[:40],

        "limit_bytes":
            max(
                0,
                int(limit_bytes),
            ),

        "used_bytes":
            0,

        "created_at":
            datetime.now().isoformat(),

        "active":
            True,

        "expires_at":
            expires_at,

        "note":
            (
                note
                or ""
            ).strip()[:500],

        "sub_id":
            sub_id,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "alpn":
            (
                alpn
                or ""
            ).strip()[:100],

        "port":
            port,

        "ip_limit":
            max(
                0,
                int(ip_limit),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(speed_limit_bytes),
            ),

        "connection_limit":
            max(
                0,
                int(connection_limit),
            ),

        "fragment":
            (
                fragment
                or "off"
            ).strip().lower(),

        "security_profile": "balanced",
        "multi_login": False,
        "protocol_label": PROTOCOL_LABELS.get(protocol, protocol),
        "clean_ips": list(clean_ips or []),
        "alarm_enabled": bool(alarm_enabled),
        "category_id": str(category_id or "0"),
        "config_count": max(1, min(40, int(config_count or 1))),
        "usage_history": [],
    }

    async with LINKS_LOCK:
        LINKS[uid] = record

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return uid, record


async def remove_link(
    uid: str,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

        sub_id = LINKS[
            uid
        ].get(
            "sub_id"
        )

        del LINKS[uid]

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"حذف شد"
        ),
        "warn",
    )

    return label


async def set_link_active(
    uid: str,
    active: bool,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        LINKS[
            uid
        ][
            "active"
        ] = bool(active)

        record = LINKS[uid]

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"{'فعال' if active else 'غیرفعال'} شد"
        ),
        "ok"
        if active
        else "warn",
    )

    return record


# ============================================================
# SUB GROUPS
# ============================================================

async def create_sub_group(
    name: str = "گروه جدید",
    desc: str = "",
    password: str = "",
):

    name = (
        name
        or "گروه جدید"
    ).strip()[:60]

    desc = (
        desc
        or ""
    ).strip()[:200]

    password = (
        password
        or ""
    ).strip()

    sub_id = generate_uuid()

    uuid_key = secrets.token_urlsafe(16)

    record = {
        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(password)
                if password
                else None
            ),

        "uuid_key":
            uuid_key,

        "created_at":
            datetime.now().isoformat(),

        "link_ids":
            [],
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = record

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return (
        sub_id,
        record,
    )


async def set_link_sub(
    uid: str,
    sub_id: str | None,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return False

        old_sub = LINKS[
            uid
        ].get(
            "sub_id"
        )

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

    if sub_id is not None:

        async with SUBS_LOCK:

            if sub_id not in SUBS:
                return False

    async with SUBS_LOCK:

        if (
            old_sub
            and old_sub in SUBS
        ):

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(uid)

        if (
            sub_id
            and sub_id in SUBS
        ):

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:
                ids.append(uid)

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"{'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}"
        ),
        "info",
    )

    return True


async def remove_sub_group(
    sub_id: str,
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            return None

        name = SUBS[
            sub_id
        ].get(
            "name",
            sub_id,
        )

        del SUBS[sub_id]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get("sub_id")
                == sub_id
            ):
                link["sub_id"] = None

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"حذف شد"
        ),
        "warn",
    )

    return name


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    limits = httpx.Limits(
        max_connections=500,
        max_keepalive_connections=100,
    )

    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()
    await save_state()

    await ensure_default_categories()
    await remove_legacy_default_links()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            f"راه‌اندازی شد"
        ),
        "ok",
    )

    logger.info(
        "%s v%s started on 0.0.0.0:%s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:
        await http_client.aclose()


# ============================================================
# LANDING
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>PX Panel</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
rel="stylesheet">

<style>
*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:20px;
    color:#fff;
    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(37,99,235,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(59,130,246,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:580px;
    padding:32px;
    border-radius:28px;

    border:1px solid rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.07),
            rgba(255,255,255,.025)
        );

    backdrop-filter:blur(28px) saturate(150%);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.logo{
    width:48px;
    height:48px;
    border-radius:15px;

    display:flex;
    justify-content:center;
    align-items:center;

    font-size:18px;
    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.brand-name{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:4px;
    font-size:11px;
    color:#60a5fa;
}

.status{
    display:inline-block;
    margin-top:23px;
    padding:7px 11px;
    border-radius:999px;

    color:#86efac;
    background:rgba(34,197,94,.07);
    border:1px solid rgba(34,197,94,.15);

    font-size:11px;
}

h1{
    margin:18px 0 0;
    font-size:28px;
    line-height:1.55;
}

.desc{
    margin-top:12px;
    color:rgba(255,255,255,.52);
    line-height:2;
    font-size:13px;
}

.path{
    margin-top:22px;
    padding:15px;
    border-radius:15px;

    background:rgba(0,0,0,.18);
    border:1px solid rgba(255,255,255,.07);

    direction:ltr;
    text-align:left;
    font-family:Consolas,monospace;
    color:#93c5fd;
}

.actions{
    display:flex;
    gap:10px;
    margin-top:20px;
}

.btn{
    flex:1;
    padding:13px;
    border-radius:14px;
    text-align:center;
    text-decoration:none;

    font-size:12px;
    font-weight:800;
}

.primary{
    color:#fff;
    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.secondary{
    color:#fff;
    background:rgba(255,255,255,.035);
    border:1px solid rgba(255,255,255,.08);
}

.footer{
    margin-top:22px;
    padding-top:16px;
    border-top:1px solid rgba(255,255,255,.07);

    display:flex;
    justify-content:space-between;

    font-size:10px;
    color:rgba(255,255,255,.35);
}

.support{
    color:#60a5fa;
    text-decoration:none;
}



/* ONEX responsive system */
html{scroll-behavior:smooth} body{overflow-x:hidden} button,input,select,textarea{touch-action:manipulation} .modal{overscroll-behavior:contain}


@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}

/* Toggle switch */
.switch{position:relative;display:inline-block;width:42px;height:24px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(255,255,255,.12);border-radius:24px;transition:.2s}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}


.conn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:20px;padding:0 7px;border-radius:8px;font-size:10px;font-weight:800}
.conn-badge.green{background:rgba(34,197,94,.18);color:#4ade80}
.conn-badge.gray{background:rgba(148,163,184,.15);color:#94a3b8}
.conn-badge.orange{background:rgba(245,158,11,.18);color:#fbbf24}
.conn-badge.red{background:rgba(239,68,68,.18);color:#f87171}


.bottom-bulk{position:fixed;left:0;right:0;bottom:0;z-index:400;display:none;padding:12px 16px;background:var(--card);border-top:1px solid var(--card-b);backdrop-filter:blur(12px)}
.bottom-bulk.show{display:block}
.bottom-bulk-inner{max-width:960px;margin:0 auto;display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:center}
.bottom-bulk select{padding:8px 10px;border-radius:10px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:12px}

table th:first-child, table td:first-child{overflow:visible}
.cfg-chk{accent-color:var(--accent)}
#page-donate .page-title{width:100%}

</style>
</head>

<body>

<div class="card">

<div class="brand">

<div class="logo">P</div>

<div>
<div class="brand-name">
PX Panel
</div>

<div class="version">
13.8.0
</div>
</div>

</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<div class="desc">
این صفحه، درگاه عمومی PX Panel است.
برای دسترسی به داشبورد مدیریت از مسیر ورود استفاده کنید.
</div>

<div class="path">
/login
</div>

<div class="actions">

<a
href="/login"
class="btn primary"
>
ورود به پنل
</a>

<a
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
class="btn secondary"
>
پشتیبانی
</a>

</div>

<div class="footer">

<span>
PX Panel · 13.8.0
</span>

<a
href="https://t.me/Pixonal"
target="_blank"
class="support"
>
@Pixonal
</a>

</div>

</div>


<div id="bottomBulkBar" class="bottom-bulk">
  <div class="bottom-bulk-inner">
    <span id="bulkCount">0 انتخاب</span>
    <select id="bulkGroup"></select>
    <button class="btn btn-sm" onclick="bulkMoveGroup()">انتقال به گروه</button>
    <button class="btn btn-sm btn-d" onclick="bulkDelete()">حذف انتخاب‌شده</button>
    <button class="btn btn-sm" onclick="clearSelection()">لغو</button>
  </div>
</div>
</body>
</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(connections),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#050b18">
<title>ONEX | ورود به پنل</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&family=Inter:wght@500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#020712;
  --panel:rgba(5,13,27,.72);
  --panel2:rgba(8,19,38,.58);
  --line:rgba(88,180,255,.22);
  --text:#f8fbff;
  --muted:#8fa7c3;
  --blue:#168cff;
  --cyan:#29d7ff;
  --shadow:0 30px 100px rgba(0,0,0,.55);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%;background:var(--bg)}
body{
  min-height:100vh;overflow-x:hidden;color:var(--text);font-family:'Vazirmatn',sans-serif;
  background:
    radial-gradient(circle at 18% 22%,rgba(0,126,255,.17),transparent 28%),
    radial-gradient(circle at 85% 15%,rgba(0,207,255,.12),transparent 24%),
    linear-gradient(145deg,#020712 0%,#061329 52%,#02050d 100%);
}
body:before,body:after{content:"";position:fixed;inset:0;pointer-events:none}
body:before{opacity:.38;background-image:radial-gradient(#7bdcff 1px,transparent 1px);background-size:90px 90px;animation:stars 22s linear infinite}
body:after{background:radial-gradient(circle at 50% 55%,transparent 0,rgba(0,0,0,.08) 45%,rgba(0,0,0,.52) 100%)}
@keyframes stars{to{transform:translate3d(90px,90px,0)}}
.scene{min-height:100vh;display:grid;grid-template-columns:minmax(0,1.08fr) minmax(390px,.92fr);position:relative;z-index:1}
.hero{position:relative;display:flex;align-items:center;justify-content:center;padding:48px;overflow:hidden;perspective:1200px}
.hero:before{content:"";position:absolute;left:5%;right:5%;bottom:12%;height:34%;border-radius:50%;background:radial-gradient(ellipse,rgba(13,140,255,.22),transparent 68%);filter:blur(16px)}
.grid-floor{position:absolute;left:-15%;right:-15%;bottom:-13%;height:44%;transform:perspective(600px) rotateX(65deg);background-image:linear-gradient(rgba(24,143,255,.15) 1px,transparent 1px),linear-gradient(90deg,rgba(24,143,255,.15) 1px,transparent 1px);background-size:55px 55px;mask-image:linear-gradient(to top,black,transparent);animation:gridMove 7s linear infinite}
@keyframes gridMove{to{background-position:0 55px,55px 0}}
.hero-content{text-align:center;position:relative;z-index:2;transform-style:preserve-3d;animation:heroFloat 5s ease-in-out infinite}
@keyframes heroFloat{0%,100%{transform:translateY(0) rotateX(0deg)}50%{transform:translateY(-12px) rotateX(1.5deg)}}
.logo-orbit{width:330px;height:330px;position:relative;margin:0 auto 10px;transform-style:preserve-3d;animation:logoTilt 8s ease-in-out infinite}
@keyframes logoTilt{0%,100%{transform:rotateY(-8deg) rotateX(4deg)}50%{transform:rotateY(8deg) rotateX(-3deg)}}
.orbit{position:absolute;inset:58px;border:2px solid rgba(31,167,255,.78);border-radius:50%;box-shadow:0 0 20px rgba(0,157,255,.55),inset 0 0 18px rgba(0,157,255,.18);transform:rotateX(68deg) rotateZ(-18deg);animation:spin 5s linear infinite}
.orbit.o2{inset:40px;border-color:rgba(64,223,255,.36);transform:rotateY(68deg) rotateZ(24deg);animation-duration:8s;animation-direction:reverse}
.orbit:after{content:"";position:absolute;width:12px;height:12px;border-radius:50%;background:#8ff5ff;box-shadow:0 0 18px 7px #16a8ff;left:8%;top:15%}
@keyframes spin{to{transform:rotateX(68deg) rotateZ(342deg)}}
.logo3d{position:absolute;left:50%;top:50%;width:145px;height:145px;transform:translate(-50%,-50%) rotateX(-7deg) rotateY(-14deg);transform-style:preserve-3d;filter:drop-shadow(0 25px 25px rgba(0,112,255,.35))}
.logo3d .face{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;border-radius:38px 52px 38px 52px;font-family:Inter,sans-serif;font-size:108px;font-weight:900;line-height:1;color:white;background:linear-gradient(145deg,#63edff 0%,#0c9cff 42%,#123cf0 100%);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 3px 0 rgba(0,44,150,.7),0 0 28px rgba(16,174,255,.55);animation:facePulse 2.8s ease-in-out infinite}
.logo3d .depth{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:Inter,sans-serif;font-size:108px;font-weight:900;color:#063fa8;transform:translateZ(-18px) translate(9px,10px);opacity:.7;filter:blur(.2px)}
@keyframes facePulse{50%{filter:brightness(1.22) saturate(1.2)}}
.brand{font-family:Inter,sans-serif;font-size:78px;font-weight:900;letter-spacing:8px;background:linear-gradient(90deg,#f8fbff 0%,#dbeeff 48%,#22b7ff 100%);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 10px 35px rgba(0,132,255,.3)}
.tagline{margin-top:5px;letter-spacing:8px;color:#b4c7df;font-family:Inter,sans-serif;font-size:15px}
.tagline b{color:#25baff}
.hero-sub{margin-top:18px;color:#8da9c7;font-size:14px}
.credits{display:flex;justify-content:center;gap:45px;margin-top:65px;color:#7f98b5;font-size:12px}
.credits strong{display:block;color:#f3f8ff;margin-top:5px;font-size:13px;direction:ltr}
.credits a{color:#27c6ff;text-decoration:none}
.login-side{display:flex;align-items:center;justify-content:center;padding:45px 6vw 45px 35px;position:relative}
.login-card{width:min(500px,100%);padding:34px;border:1px solid var(--line);border-radius:30px;background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68));box-shadow:var(--shadow),0 0 80px rgba(0,119,255,.10);backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px);position:relative;overflow:hidden;transform-style:preserve-3d;transition:transform .25s ease,box-shadow .25s ease}
.login-card:before{content:"";position:absolute;inset:-2px;background:linear-gradient(120deg,transparent 25%,rgba(43,198,255,.25),transparent 50%);transform:translateX(-100%);animation:sheen 5s ease-in-out infinite;pointer-events:none}
@keyframes sheen{55%,100%{transform:translateX(120%)}}
.login-logo{width:76px;height:76px;margin:0 auto 12px;border-radius:24px;display:grid;place-items:center;background:linear-gradient(145deg,#087cff,#21d5ff);box-shadow:0 0 35px rgba(0,153,255,.38);transform-style:preserve-3d;animation:miniLogo 4s ease-in-out infinite}
.login-logo span{font-family:Inter,sans-serif;font-size:55px;font-weight:900;color:white;text-shadow:4px 5px 0 rgba(0,51,150,.55);transform:translateZ(18px) rotateY(-8deg)}
@keyframes miniLogo{50%{transform:rotateY(12deg) rotateX(6deg) translateY(-4px)}}
.login-title{text-align:center;font-size:25px;font-weight:900}.login-title b{color:#24c4ff}.login-desc{text-align:center;color:var(--muted);font-size:12px;margin-top:7px;margin-bottom:27px}
.field{position:relative;margin-bottom:15px}.field svg{position:absolute;right:15px;top:50%;transform:translateY(-50%);width:21px;height:21px;color:#5f9dd8;pointer-events:none}.field input{width:100%;height:58px;padding:0 50px 0 44px;border-radius:17px;border:1px solid rgba(122,180,235,.14);background:rgba(2,11,24,.62);color:#fff;font-family:inherit;font-size:14px;outline:none;direction:ltr;text-align:left;transition:.25s}.field input::placeholder{color:#617a98}.field input:focus{border-color:#168cff;box-shadow:0 0 0 4px rgba(22,140,255,.10),0 0 30px rgba(22,140,255,.10)}
.eye{position:absolute;left:12px;top:50%;transform:translateY(-50%);border:0;background:transparent;color:#6485a9;cursor:pointer;padding:7px;display:grid;place-items:center}.eye svg{position:static;transform:none;width:20px;height:20px}
.primary{width:100%;height:58px;margin-top:5px;border:0;border-radius:17px;color:#fff;font-family:inherit;font-weight:900;font-size:15px;cursor:pointer;background:linear-gradient(100deg,#086cff,#12a7ff 55%,#1ad8ff);box-shadow:0 12px 28px rgba(0,115,255,.24);position:relative;overflow:hidden;transition:transform .2s,filter .2s}.primary:before{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 20%,rgba(255,255,255,.28),transparent 70%);transform:translateX(-120%);animation:buttonSheen 3.5s infinite}.primary:hover{transform:translateY(-2px);filter:brightness(1.08)}.primary:disabled{opacity:.55;cursor:not-allowed;transform:none}.primary span{position:relative;z-index:1}
@keyframes buttonSheen{50%,100%{transform:translateX(120%)}}
.row{display:flex;align-items:center;justify-content:space-between;margin:15px 2px 0;font-size:11px;color:#728ba8}.remember{display:flex;align-items:center;gap:7px}.remember input{accent-color:#129cff}.forgot{color:#19b9ff}
.telegram{margin-top:23px;padding:14px 15px;border-radius:18px;border:1px solid rgba(43,191,255,.25);background:linear-gradient(120deg,rgba(0,115,255,.08),rgba(20,211,255,.05));display:flex;align-items:center;gap:13px;text-decoration:none;color:#fff;position:relative;overflow:hidden}.telegram:before{content:"";position:absolute;inset:0;background:linear-gradient(100deg,transparent,rgba(37,198,255,.14),transparent);transform:translateX(-120%);animation:telegramSheen 3s infinite}.telegram-icon{width:45px;height:45px;border-radius:50%;display:grid;place-items:center;flex:0 0 45px;background:linear-gradient(145deg,#23aaff,#0878ff);box-shadow:0 0 25px rgba(0,147,255,.35);animation:tgPulse 2.2s ease-in-out infinite;position:relative;z-index:1}.telegram-icon svg{width:24px}.telegram-text{position:relative;z-index:1}.telegram-text small{display:block;color:#7894b2;font-size:10px}.telegram-text b{display:block;color:#23c7ff;font-family:Inter,sans-serif;font-size:14px;margin-top:2px;direction:ltr;text-align:right}.tg-arrow{margin-right:auto;color:#3dbfff;font-size:23px;position:relative;z-index:1;animation:arrowPulse 1.8s ease-in-out infinite}@keyframes telegramSheen{50%,100%{transform:translateX(120%)}}@keyframes tgPulse{50%{transform:translateY(-3px) rotate(-7deg);box-shadow:0 0 34px rgba(0,181,255,.6)}}@keyframes arrowPulse{50%{transform:translateX(-4px)}}
.err,.error{display:none;margin-bottom:13px;padding:11px 13px;border-radius:13px;background:rgba(239,68,68,.10);border:1px solid rgba(239,68,68,.28);color:#ff9d9d;font-size:12px;line-height:1.7}.err.show,.error.show{display:block}.warn{margin-bottom:16px;padding:12px;border-radius:13px;background:rgba(245,158,11,.09);border:1px solid rgba(245,158,11,.25);color:#fbbf24;font-size:11px;line-height:1.9}.warn code{background:rgba(0,0,0,.35);padding:2px 5px;border-radius:5px;color:#9ed4ff;font-family:ui-monospace,monospace}.hidden{display:none!important}
.footer{text-align:center;color:#526b88;font-size:10px;margin-top:20px}.footer a{color:#2ac8ff;text-decoration:none}
.setup-title{font-size:21px;font-weight:900;margin-bottom:5px;text-align:center}.setup-desc{text-align:center;color:#819ab7;font-size:11px;margin-bottom:20px}













/* ============================================================
   ONEX LOGIN — PHONE LAYOUT
   Compact, centered and touch-friendly on mobile screens.
   ============================================================ */
@media (max-width:700px){
  html,body{width:100%;min-width:0;overflow-x:hidden;}
  .scene{min-height:100svh;display:block;}
  .hero{display:none!important;}
  .login-side{
    min-height:100svh;
    width:100%;
    padding:14px 12px 18px;
    align-items:center;
    justify-content:center;
  }
  .login-card{
    width:100%;
    max-width:430px;
    padding:24px 18px 20px;
    border-radius:24px;
    background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68));
    box-shadow:var(--shadow),0 0 55px rgba(0,119,255,.12);
    backdrop-filter:blur(25px);
    -webkit-backdrop-filter:blur(25px);
  }
  .login-logo{width:66px;height:66px;border-radius:21px;margin-bottom:10px;}
  .login-logo span{font-size:48px;}
  .login-title{font-size:22px;line-height:1.65;}
  .login-desc{font-size:11px;line-height:1.8;margin-top:3px;margin-bottom:19px;}
  .field{margin-bottom:12px;}
  .field input{height:54px;border-radius:15px;font-size:16px;padding-right:47px;padding-left:43px;}
  .field svg{right:14px;width:20px;height:20px;}
  .eye{left:9px;padding:7px;}
  .eye svg{width:20px;height:20px;}
  .primary{height:55px;border-radius:15px;font-size:15px;margin-top:4px;}
  .row{margin-top:12px;font-size:10px;gap:8px;}
  .telegram{margin-top:17px;padding:11px 12px;border-radius:16px;gap:10px;}
  .telegram-icon{width:42px;height:42px;flex-basis:42px;}
  .telegram-icon svg{width:22px;}
  .telegram-text small{font-size:9px;}
  .telegram-text b{font-size:13px;}
  .tg-arrow{font-size:21px;}
  .footer{font-size:9px;margin-top:15px;}
}
@media (max-width:380px){
  .login-side{padding:9px 9px 12px;}
  .login-card{padding:19px 14px 16px;border-radius:21px;}
  .login-logo{width:58px;height:58px;border-radius:18px;}
  .login-logo span{font-size:42px;}
  .login-title{font-size:19px;}
  .login-desc{font-size:10px;margin-bottom:15px;}
  .field input{height:51px;}
  .primary{height:52px;}
  .telegram{margin-top:14px;}
  .telegram-icon{width:38px;height:38px;flex-basis:38px;}
  .telegram-icon svg{width:20px;}
  .footer{font-size:8px;margin-top:12px;}
}


/* FINAL MOBILE LOGIN FIT */
@media (max-width:700px){
  html,body{width:100%;min-width:0;overflow-x:hidden;}
  .scene{display:block;min-height:100dvh;width:100%;}
  .hero{display:none !important;}
  .login-side{width:100%;min-height:100dvh;height:auto;padding:18px 12px 22px;display:flex;align-items:center;justify-content:center;}
  .login-card{width:min(100%,440px);max-height:calc(100dvh - 28px);overflow-y:auto;padding:22px 17px 18px;border-radius:23px;
    background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;
    border:1px solid rgba(88,180,255,.22);
    box-shadow:0 30px 100px rgba(0,0,0,.55),0 0 55px rgba(0,119,255,.10);
    backdrop-filter:blur(25px);-webkit-backdrop-filter:blur(25px);
  }
  .login-logo{width:62px;height:62px;border-radius:19px;margin-bottom:9px;}
  .login-logo span{font-size:45px;}
  .login-title{font-size:21px;line-height:1.5;}
  .login-desc{font-size:10.5px;line-height:1.7;margin:3px 0 16px;}
  .field{margin-bottom:11px;}
  .field input{height:53px;border-radius:14px;font-size:16px;}
  .primary{height:53px;border-radius:14px;font-size:14px;}
  .row{margin-top:10px;font-size:9.5px;}
  .telegram{margin-top:15px;padding:10px 11px;border-radius:15px;}
  .telegram-icon{width:40px;height:40px;flex-basis:40px;}
  .telegram-text small{font-size:8.5px}.telegram-text b{font-size:12.5px}.tg-arrow{font-size:20px}
  .footer{font-size:8.5px;margin-top:12px;}
}
@media (max-width:380px){
  .login-side{padding:10px 8px 14px;}
  .login-card{padding:18px 13px 15px;border-radius:20px;}
  .login-logo{width:56px;height:56px;border-radius:17px}.login-logo span{font-size:40px}
  .login-title{font-size:19px}.login-desc{font-size:10px;margin-bottom:13px}
  .field input{height:50px}.primary{height:51px}
}
</style>
</head>
<body>
<div class="scene">
  <section class="hero">
    <div class="grid-floor"></div>
    <div class="hero-content">
      <div class="logo-orbit" aria-hidden="true">
        <div class="orbit"></div><div class="orbit o2"></div>
        <div class="logo3d"><div class="depth">N</div><div class="face">N</div></div>
      </div>
      <div class="brand">ONEX</div>
      <div class="tagline">FAST <b>•</b> SECURE <b>•</b> STABLE</div>
      <div class="hero-sub">اتصال سریع، پایدار و امن بدون محدودیت</div>
      <div class="credits">
        <div>Designed by<strong><a href="https://t.me/Mehtif" target="_blank" rel="noopener">@Mehtif</a></strong></div>
        <div>Telegram Channel<strong><a href="https://t.me/V2rayTun0" target="_blank" rel="noopener">@V2rayTun0</a></strong></div>
      </div>
    </div>
  </section>

  <main class="login-side">
    <div class="login-card" id="loginCard">
      <div class="login-logo" aria-hidden="true"><span>N</span></div>
      <div class="login-title">به پنل <b>ONEX</b> خوش آمدید</div>
      <div class="login-desc">برای ادامه، اطلاعات حساب کاربری خود را وارد کنید</div>

      <div id="loginBox">
        <div class="err" id="loginErr"></div>
        <form id="loginForm">
          <div class="field"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 21a8 8 0 0 0-16 0"/><circle cx="12" cy="7" r="4"/></svg><input type="text" id="loginUser" value="admin" placeholder="نام کاربری ادمین" autocomplete="username"></div>
          <div class="field"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="5" y="10" width="14" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg><input type="password" id="loginPw" value="admin" placeholder="رمز عبور" autocomplete="current-password" required><button class="eye" type="button" onclick="togglePassword()" aria-label="نمایش رمز"><svg id="eyeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="2.5"/></svg></button></div>
          <button class="primary" type="submit" id="loginBtn"><span>ورود به پنل</span></button>
          <div class="row"><label class="remember"><input type="checkbox" checked> مرا به خاطر بسپار</label><span class="forgot">دسترسی امن به پنل</span></div>
        </form>
      </div>

      <a class="telegram" href="https://t.me/V2rayTun0" target="_blank" rel="noopener">
        <div class="telegram-icon"><svg viewBox="0 0 24 24" fill="white"><path d="M21.4 3.5 2.9 10.6c-1.3.5-1.3 1.2-.2 1.5l4.7 1.5 1.8 5.7c.2.6.1.8.8.8.5 0 .7-.2 1-.5l2.3-2.2 4.8 3.5c.9.5 1.6.3 1.8-.9l3.1-14.6c.3-1.5-.5-2.2-1.8-1.6Zm-12.9 9.8 9.9-6.2c.5-.3 1-.1.6.2l-8 7.2-.3 3.2-1.4-4.4-3.4-1.1c-.7-.2-.7-.5.1-.8Z"/></svg></div>
        <div class="telegram-text"><small>کانال رسمی تلگرام</small><b>@V2rayTun0</b></div>
        <div class="tg-arrow">‹</div>
      </a>
      <div class="footer">© 2026 ONEX &nbsp;|&nbsp; Designed by <a href="https://t.me/Mehtif" target="_blank" rel="noopener">@Mehtif</a></div>
    </div>
  </main>
</div>
<script>
const card=document.getElementById('loginCard');
if(window.matchMedia('(pointer:fine)').matches){
  document.addEventListener('mousemove',e=>{
    const r=card.getBoundingClientRect();
    const x=(e.clientX-r.left)/r.width-.5;
    const y=(e.clientY-r.top)/r.height-.5;
    if(e.clientX>=r.left-120&&e.clientX<=r.right+120&&e.clientY>=r.top-120&&e.clientY<=r.bottom+120){
      card.style.transform=`perspective(1000px) rotateX(${(-y*2.8).toFixed(2)}deg) rotateY(${(x*3.2).toFixed(2)}deg) translateZ(3px)`;
    }
  });
  document.addEventListener('mouseleave',()=>card.style.transform='');
}
function togglePassword(){
  const input=document.getElementById('loginPw');
  input.type=input.type==='password'?'text':'password';
}
document.getElementById('loginPw').focus();
document.getElementById('loginForm').addEventListener('submit',async e=>{
  e.preventDefault();
  const err=document.getElementById('loginErr');err.classList.remove('show');
  const btn=document.getElementById('loginBtn');btn.disabled=true;
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('loginPw').value,username:document.getElementById('loginUser').value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'رمز اشتباه است');}
    location.href='/dashboard';
  }catch(e){err.textContent=e.message||'خطا در ورود';err.classList.add('show');btn.disabled=false;}
});
</script>
</body>
</html>
"""




def login_error_html(
    message: str,
):
    safe_message = escape_html(
        message
    )

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe_message}
            </div>
            </form>
            """
        ),
    )



# ============================================================
# FIRST-RUN SETUP
# ============================================================

@app.get("/api/setup/status")
async def setup_status():
    return {
        "password_configured": True,
        "needs_setup": False,
        "username": AUTH.get("username", "admin"),
    }


@app.post("/api/setup/password")
async def setup_password(request: Request):
    raise HTTPException(status_code=410, detail="راه‌اندازی اولیه حذف شده است؛ از تنظیمات پنل استفاده کنید")
    if AUTH.get("password_configured") and AUTH.get("password_hash"):
        raise HTTPException(status_code=400, detail="رمز قبلاً تنظیم شده است")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="اطلاعات نامعتبر")
    pw = str(body.get("password") or "")
    rp = str(body.get("repeat_password") or body.get("confirm") or "")
    if len(pw) < 6:
        raise HTTPException(status_code=400, detail="رمز باید حداقل ۶ کاراکتر باشد")
    if pw != rp:
        raise HTTPException(status_code=400, detail="تکرار رمز یکسان نیست")
    AUTH["password_hash"] = hash_password(pw)
    AUTH["password_configured"] = True
    await save_state()
    token = await create_session()
    response = JSONResponse({"ok": True, "message": "رمز تنظیم شد"})
    set_auth_cookie(response, request, token)
    log_activity("auth", "رمز اولیه پنل تنظیم شد", "ok")
    return response


@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML
    )


@app.post("/login")
async def login_form(
    request: Request,
):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        return HTMLResponse(login_error_html("ورود با نام کاربری و رمز عبور انجام می‌شود"))


    try:

        content_type = (
            request.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        if "application/json" in content_type:

            body = await request.json()

            username = str(body.get("username", "")).strip().lower()
            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

        else:

            raw = await request.body()

            parsed = parse_qs(
                raw.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            username = (
                parsed.get(
                    "username",
                    [""],
                )[0]
                .strip().lower()
            )
            password = (
                parsed.get(
                    "password",
                    [""],
                )[0]
                .strip()
            )

    except Exception as exc:

        logger.exception(
            "Login parser error: %s",
            exc,
        )

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        minutes = max(1, (retry_after + 59) // 60)
        return HTMLResponse(
            login_error_html(
                f"به دلیل تلاش‌های ناموفق متعدد، ورود موقتاً مسدود شده است. حدود {minutes} دقیقه دیگر دوباره تلاش کنید."
            ),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if not username or not password:
        register_login_failure(ip)
        return HTMLResponse(
            login_error_html(
                "نام کاربری و رمز عبور را وارد کنید."
            ),
            status_code=400,
        )

    if username != AUTH.get("username", "admin") or hash_password(password) != AUTH["password_hash"]:

        locked, value = register_login_failure(ip)
        if locked:
            return HTMLResponse(
                login_error_html(
                    "تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد."
                ),
                status_code=429,
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        remaining = value
        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{remaining} تلاش باقی مانده"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                f"رمز عبور اشتباه است. {remaining} تلاش دیگر باقی مانده است."
            ),
            status_code=401,
        )

    clear_login_failures(ip)

    token = await create_session()

    response = RedirectResponse(
        "/dashboard?login=1",
        status_code=303,
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {client_ip(request)}"
        ),
        "ok",
    )

    return response


@app.post("/api/login")
async def api_login(request: Request):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        raise HTTPException(status_code=400, detail="ورود نیاز به حساب کاربری دارد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر است")
    password = str(body.get("password", "")).strip()
    username = str(body.get("username", "")).strip().lower()
    ip = client_ip(request)
    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        raise HTTPException(status_code=429, detail=f"ورود موقتاً مسدود است. حدود {max(1, (retry_after + 59) // 60)} دقیقه دیگر تلاش کنید.", headers={"Retry-After": str(retry_after)})
    if not password:
        register_login_failure(ip)
        raise HTTPException(status_code=400, detail="رمز عبور الزامی است")
    meta = {"role": "owner", "admin_id": None, "username": AUTH.get("username", "admin")}
    ok = False
    if username and username == AUTH.get("username", "admin"):
        if hash_password(password) == AUTH["password_hash"]:
            ok = True
    elif username:
        aid, admin = find_admin_by_username(username)
        if admin and admin.get("password_hash") == hash_password(password):
            if not admin_is_valid(admin):
                raise HTTPException(status_code=403, detail="حساب مسدود یا منقضی شده است")
            ok = True
            meta = {"role": "admin", "admin_id": aid, "username": username}
    if not ok:
        locked, value = register_login_failure(ip)
        if locked:
            raise HTTPException(status_code=429, detail="تعداد تلاش بیش از حد. ۱۵ دقیقه صبر کنید.", headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)})
        raise HTTPException(status_code=401, detail=f"نام کاربری یا رمز اشتباه است. {value} تلاش باقی‌مانده")
    clear_login_failures(ip)
    token = await create_session(meta)
    response = JSONResponse({"ok": True, "role": meta["role"], "username": meta["username"]})
    set_auth_cookie(response, request, token)
    log_activity("auth", f"ورود موفق ({meta['username']}) از {ip}", "ok")
    return response


@app.post("/api/logout")
async def api_logout(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response





# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    current_password = str(
        body.get(
            "current_password",
            "",
        )
    )
    new_username = str(body.get("new_username") or AUTH.get("username", "admin")).strip().lower()

    if (
        hash_password(current_password)
        != AUTH["password_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است",
        )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    repeat_password = str(
        body.get(
            "repeat_password",
            "",
        )
    )

    if not new_username or len(new_username) < 3 or len(new_username) > 32 or not new_username.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="نام کاربری باید ۳ تا ۳۲ کاراکتر و فقط شامل حروف، عدد، _ یا - باشد")

    if len(new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز جدید باید حداقل ۶ کاراکتر باشد",
        )

    if new_password != repeat_password:
        raise HTTPException(
            status_code=400,
            detail="تکرار رمز عبور یکسان نیست",
        )

    AUTH[
        "username"
    ] = new_username
    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )
    AUTH["password_configured"] = True
    AUTH["credentials_version"] = 1

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    await save_state()

    log_activity(
        "auth",
        "رمز عبور پنل تغییر کرد",
        "ok",
    )

    return {
        "ok": True
    }


# ============================================================
# CREATE LINK
# ============================================================

@app.post("/api/links")
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()

        if not isinstance(body, dict):
            raise ValueError(
                "body is not object"
            )

    except Exception as exc:

        logger.exception(
            "Create link JSON error: %s",
            exc,
        )

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ارسال‌شده معتبر نیست.",
        )

    limit_value = safe_float(
        body.get(
            "limit_value",
            0,
        )
    )

    limit_unit = str(
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    ).upper()

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    expires_days = safe_int(
        body.get(
            "expires_days",
            0,
        ),
        minimum=0,
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()
        if expires_days > 0
        else None
    )

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT,
        ),
        default=DEFAULT_PORT,
        minimum=MIN_PORT,
        maximum=MAX_PORT,
    )

    ip_limit = safe_int(
        body.get(
            "ip_limit",
            0,
        ),
        minimum=0,
    )

    speed_value = safe_float(
        body.get(
            "speed_limit_value",
            0,
        )
    )

    speed_unit = str(
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    ).upper()

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    connection_limit = safe_int(
        body.get(
            "connection_limit",
            0,
        ),
        minimum=0,
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
        or DEFAULT_PROTOCOL
    ).strip()

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment = str(
        body.get(
            "fragment",
            "off",
        )
        or "off"
    ).strip().lower()

    allowed_fragments = {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }

    if fragment not in allowed_fragments:
        fragment = "off"

    raw_clean = body.get("clean_ips") or body.get("clean_ip") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    alarm_enabled = bool(body.get("alarm_enabled", False))
    category_id = str(body.get("category_id") or "0")
    if category_id not in CATEGORIES:
        category_id = "0"
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    cat = CATEGORIES.get(category_id) or {}
    if cat.get("limit_bytes") and limit_bytes <= 0:
        limit_bytes = int(cat["limit_bytes"])
    if cat.get("expires_days") and expires_days <= 0:
        expires_days = int(cat["expires_days"])
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if cat.get("connection_limit") and connection_limit <= 0:
        connection_limit = int(cat["connection_limit"])
    if cat.get("speed_limit_bytes") and speed_bytes <= 0:
        speed_bytes = int(cat["speed_limit_bytes"])
    if cat.get("ip_limit") and ip_limit <= 0:
        ip_limit = int(cat["ip_limit"])
    if cat.get("clean_ips") and not clean_ips:
        clean_ips = list(cat["clean_ips"])
    if cat.get("single_user"):
        if ip_limit == 0: ip_limit = 1
        if connection_limit == 0: connection_limit = 1
    label_val = body.get("label", "")
    if cat.get("random_name") or not str(label_val).strip():
        label_val = project_config_name()
    else:
        label_val = sanitize_config_name(str(label_val))

    uid, link = await make_link(
        label=label_val,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=protocol,
        fingerprint=fingerprint,
        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
    )

    host = get_host(request)

    result = {
        **get_link_info(
            link,
            uid,
            host,
        ),
        "ok": True,
    }

    return result


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict): body = {}
    host = get_host(request)
    protocol = normalize_protocol(body.get("protocol", DEFAULT_PROTOCOL))
    profile = str(body.get("profile", "balanced")).strip().lower()
    profiles = {
        "normal": {"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},
        "balanced": {"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},
        "gaming": {"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},
        "maximum": {"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"},
    }
    cfg = profiles.get(profile, profiles["balanced"])
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    uid, link = await make_link(
        label=project_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by ONEX | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
        config_count=config_count,
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    return {"protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS], "default": DEFAULT_PROTOCOL}


@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    result = []

    for uid, link in snapshot.items():

        info = get_link_info(
            link,
            uid,
            host,
        )

        result.append(
            {
                **info,

                "created_at":
                    link.get(
                        "created_at"
                    ),

                "expired":
                    is_link_expired(
                        link
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

                "info_url":
                    f"https://{host}/info/{uid}",

                "connected_ips":
                    len(
                        unique_ips_for_uuid(
                            uid
                        )
                    ),
            }
        )

    result = sorted(
        result,
        key=lambda item: (
            -int(item.get("sort_order") or 0),
            str(item.get("created_at") or ""),
        ),
    )

    return {
        "links": result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get("/api/links/{uid}/info")
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(link)

    host = get_host(request)

    return {
        "ok": True,
        **get_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================



@app.post("/api/links/reorder")
async def reorder_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    order = body.get("order") or body.get("ids") or []
    if not isinstance(order, list):
        raise HTTPException(400, detail="order باید آرایه باشد")
    # first item = highest priority
    n = len(order)
    async with LINKS_LOCK:
        for i, uid in enumerate(order):
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["sort_order"] = n - i
    await save_state()
    return {"ok": True, "count": n}


@app.post("/api/links/bulk-delete")
async def bulk_delete_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(400, detail="ids خالی است")
    deleted = []
    for uid in ids:
        uid = str(uid)
        if uid in LINKS:
            await remove_link(uid)
            deleted.append(uid)
    log_activity("link", f"حذف گروهی {len(deleted)} کانفیگ", "warn")
    return {"ok": True, "deleted": len(deleted)}


@app.post("/api/links/bulk-category")
async def bulk_category(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    cid = str(body.get("category_id") or "0")
    if cid not in CATEGORIES:
        cid = "0"
    n = 0
    async with LINKS_LOCK:
        for uid in ids:
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["category_id"] = cid
                n += 1
    await save_state()
    return {"ok": True, "updated": n}


@app.patch("/api/links/{uid}")
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[uid]

        old_sub = link.get(
            "sub_id"
        )

        label = link.get(
            "label",
            uid,
        )

        if "active" in body:
            link["active"] = bool(
                body["active"]
            )

        if "category_id" in body:
            cid = str(body.get("category_id") or "0")
            if cid not in CATEGORIES:
                cid = "0"
            link["category_id"] = cid

        if "sort_order" in body:
            try:
                link["sort_order"] = int(body.get("sort_order") or 0)
            except Exception:
                pass

        if "label" in body:

            value = str(
                body["label"]
            ).strip()

            if value:
                link["label"] = value[:60]

        if "note" in body:

            link["note"] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]

        if "reset_usage" in body:

            if body.get(
                "reset_usage"
            ):
                link[
                    "used_bytes"
                ] = 0


        if "limit_value" in body:

            value = safe_float(
                body.get(
                    "limit_value",
                    0,
                )
            )

            unit = str(
                body.get(
                    "limit_unit",
                    "GB",
                )
                or "GB"
            )

            link[
                "limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_size_to_bytes(
                    value,
                    unit,
                )
            )

        if "expires_days" in body:

            days = safe_int(
                body.get(
                    "expires_days",
                    0,
                ),
                minimum=0,
            )

            link[
                "expires_at"
            ] = (
                (
                    datetime.now()
                    + timedelta(
                        days=days
                    )
                ).isoformat()
                if days > 0
                else None
            )

        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            link[
                "fingerprint"
            ] = (
                fingerprint
                if fingerprint in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link["alpn"] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            p = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )

            link["port"] = p

        if "ip_limit" in body:

            link["ip_limit"] = safe_int(
                body.get(
                    "ip_limit",
                    0,
                ),
                minimum=0,
            )

        if "connection_limit" in body:

            link[
                "connection_limit"
            ] = safe_int(
                body.get(
                    "connection_limit",
                    0,
                ),
                minimum=0,
            )

        if "speed_limit_value" in body:

            speed_value = safe_float(
                body.get(
                    "speed_limit_value",
                    0,
                )
            )

            speed_unit = str(
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                )
                or "MBIT"
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if speed_value <= 0
                else parse_speed_to_bytes(
                    speed_value,
                    speed_unit,
                )
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            link["protocol"] = (
                protocol
                if protocol in PROTOCOLS
                else DEFAULT_PROTOCOL
            )

        if "fragment" in body:

            fragment = str(
                body.get(
                    "fragment",
                    "off",
                )
                or "off"
            ).strip().lower()

            if fragment not in {
                "off",
                "safe",
                "balanced",
                "aggressive",
            }:
                fragment = "off"

            link["fragment"] = fragment

        if "sub_id" in body:

            link[
                "sub_id"
            ] = (
                body.get(
                    "sub_id"
                )
                or None
            )

        new_sub = body.get(
            "sub_id",
            "UNCHANGED",
        )

    if new_sub != "UNCHANGED":

        async with SUBS_LOCK:

            if (
                old_sub
                and old_sub in SUBS
            ):

                ids = SUBS[
                    old_sub
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

            if (
                new_sub
                and new_sub in SUBS
            ):

                ids = SUBS[
                    new_sub
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"ویرایش شد"
        ),
        "info",
    )

    return {
        "ok": True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_link_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link["used_bytes"] = 0

        label = link.get(
            "label",
            uid,
        )

    await save_state()

    log_activity(
        "link",
        (
            f"مصرف کانفیگ "
            f"«{label}» ریست شد"
        ),
        "info",
    )

    return {
        "ok": True,
        "uuid": uid,
        "used_bytes": 0,
    }


# ============================================================
# LINK ACTION
# ============================================================

@app.post(
    "/api/links/{uid}/action"
)
async def link_action(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    action = str(
        body.get(
            "action",
            "",
        )
    ).strip().lower()

    if action == "reset":

        await reset_link_usage(
            uid,
            _
        )

        return {
            "ok": True,
            "action": "reset",
        }

    if action == "enable":

        result = await set_link_active(
            uid,
            True,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "enable",
        }

    if action == "disable":

        result = await set_link_active(
            uid,
            False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "disable",
        }

    raise HTTPException(
        status_code=400,
        detail="unknown action",
    )


# ============================================================
# DELETE LINK
# ============================================================

@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(uid)

    if label is None:
        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }




def subscription_metadata_headers(used_bytes: int, limit_bytes: int, expires_at, host: str, info_url: str, title: str):
    """Standard subscription headers understood by v2rayNG/v2rayN/Hiddify and similar clients."""
    used_bytes = max(0, int(used_bytes or 0))
    limit_bytes = max(0, int(limit_bytes or 0))

    expire_unix = 0
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IRAN_TZ) if IRAN_TZ else dt
            expire_unix = max(0, int(dt.timestamp()))
        except Exception:
            expire_unix = 0

    userinfo = f"upload=0; download={used_bytes}; total={limit_bytes}; expire={expire_unix}"

    return {
        "profile-title": quote(title, safe=""),
        "profile-web-page-url": info_url,
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
        "subscription-userinfo": userinfo,
        "content-disposition": 'inline; filename="subscription.txt"',
    }

# ============================================================
# SINGLE SUB
# ============================================================

@app.get("/sub/{uuid}")
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )

    host = get_host(request)
    clean_ips = link.get("clean_ips") or []
    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)} (باقی {fmt_bytes(remaining)})" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expires_at = link.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(exp_dt.tzinfo) if getattr(exp_dt, "tzinfo", None) else datetime.now()
            secs = int((exp_dt - now_dt).total_seconds())
            if secs <= 0:
                time_text = "منقضی"
            else:
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                time_text = f"{days}د {hours}س" if days else (f"{hours}س {mins}د" if hours else f"{mins}د")
        except Exception:
            time_text = str(expires_at)[:16]
    else:
        time_text = "∞"
    label = str(link.get("label") or "Config")
    stats_remark = f"{label} | {volume_text} | {time_text}"
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT))
    lines = [stats_line]
    used_names = set()
    cfg_count = max(1, min(40, int(link.get("config_count") or 1)))
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            name = project_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, cip, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    else:
        for i in range(cfg_count):
            name = project_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, host, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    profile_title = f"0.0.0.0 | {stats_remark}"
    headers = subscription_metadata_headers(
        used,
        limit,
        link.get("expires_at"),
        host,
        f"https://{host}/info/{uuid}",
        profile_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )

# ============================================================
# SUB ALL
# ============================================================

@app.get("/sub-all")
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:

        lines = [
            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(link)
        ]

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    return Response(
        content=content,
        media_type="text/plain",
    )


# ============================================================
# INFO PAGE
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
    request: Request,
):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse("<html lang=\"fa\" dir=\"rtl\"><body style=\"margin:0;background:#07070a;color:#fff;font-family:sans-serif;padding:40px\"><h2>کانفیگ پیدا نشد</h2></body></html>", status_code=404)
        snapshot = dict(link)

    host = get_host(request)
    vless_url = vless_link_for_link(snapshot, uid, host)
    sub_url = f"https://{host}/sub/{uid}"
    used = int(snapshot.get("used_bytes", 0) or 0)
    limit = int(snapshot.get("limit_bytes", 0) or 0)
    if limit > 0:
        usage_percent = max(0, min(100, round((used / limit) * 100, 1)))
        usage_value = f"{fmt_bytes(used)} / {fmt_bytes(limit)}"
        remaining_value = fmt_bytes(max(0, limit - used))
    else:
        usage_percent = 0
        usage_value = f"{fmt_bytes(used)} / نامحدود"
        remaining_value = "نامحدود"

    expires_at = snapshot.get("expires_at")
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(expiry_dt.tzinfo) if expiry_dt.tzinfo else datetime.now()
            seconds = int((expiry_dt - now_dt).total_seconds())
            if seconds <= 0:
                expiry_remaining = "منقضی شده"
            else:
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                expiry_remaining = f"{days} روز و {hours} ساعت" if days else (f"{hours} ساعت و {minutes} دقیقه" if hours else f"{minutes} دقیقه")
        except Exception:
            expiry_remaining = "نامشخص"
        expiry_display = str(expires_at)
    else:
        expiry_remaining = "نامحدود"
        expiry_display = "نامحدود"

    status_text = "فعال" if is_link_allowed(snapshot) else "غیرفعال"
    status_class = "good" if status_text == "فعال" else "bad"
    ip_limit = "نامحدود" if not snapshot.get("ip_limit", 0) else str(snapshot.get("ip_limit"))
    connection_limit = "نامحدود" if not snapshot.get("connection_limit", 0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes", 0) else fmt_bytes(snapshot.get("speed_limit_bytes", 0)) + "/s"

    usage_history = snapshot.get("usage_history", [])
    svg_points = "0,50 300,50"
    if usage_history and len(usage_history) > 1:
        max_hist = max(usage_history) if max(usage_history) > 0 else 1
        pts = []
        step = 300 / (len(usage_history) - 1)
        for i, val in enumerate(usage_history):
            x = i * step
            y = 60 - min(60, max(4, (val / max_hist) * 52))
            pts.append(f"{x:.1f},{y:.1f}")
        svg_points = " ".join(pts)
    elif usage_history and len(usage_history) == 1:
        svg_points = f"0,50 300,{60 - min(60, max(4, (usage_history[0] / (limit if limit > 0 else max(used, 1))) * 52)):.1f}"

    status_badge_html = 'text-emerald-300 border border-emerald-400/25 bg-emerald-400/10' if status_class == 'good' else 'text-rose-300 border border-rose-400/25 bg-rose-400/10'
    label_escaped = escape_html(snapshot.get("label", "PXpanel"))
    uid_escaped = escape_html(uid)
    app_version_str = escape_html(str(APP_VERSION))
    used_bytes_str = escape_html(fmt_bytes(used))
    limit_bytes_str = escape_html(fmt_bytes(limit)) if limit > 0 else '∞'
    remaining_value_escaped = escape_html(remaining_value)
    expiry_remaining_escaped = escape_html(expiry_remaining)
    expiry_display_escaped = escape_html(expiry_display)
    ip_limit_escaped = escape_html(ip_limit)
    connection_limit_escaped = escape_html(connection_limit)
    speed_limit_escaped = escape_html(speed_limit)
    protocol_escaped = escape_html(snapshot.get("protocol", "vless-ws"))
    fingerprint_escaped = escape_html(snapshot.get("fingerprint", "chrome"))
    vless_url_escaped = escape_html(vless_url)
    sub_url_escaped = escape_html(sub_url)
    dash_calc_offset = f"{339.29 - (339.29 * min(usage_percent, 100) / 100):.1f}"

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{label_escaped} | INFO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
  tailwind.config = {{
    theme: {{
      extend: {{
        fontFamily: {{ vazir: ['Vazirmatn','system-ui','sans-serif'] }}
      }}
    }}
  }}
</script>
<style>
  :root {{
    --bg-main: #05060a;
    --bg-card: rgba(255, 255, 255, 0.04);
    --bg-card-hover: rgba(255, 255, 255, 0.07);
    --border-color: rgba(255, 255, 255, 0.1);
    --text-main: #f1f5f9;
    --text-muted: rgba(255, 255, 255, 0.4);
    --bg-sub-card: rgba(0, 0, 0, 0.2);
    --grad-1: rgba(96,165,250,.16);
    --grad-2: rgba(96,165,250,.13);
    --grad-3: rgba(52,211,153,.08);
  }}

  body.theme-lighter {{
    --bg-main: #131722;
    --bg-card: rgba(255, 255, 255, 0.075);
    --bg-card-hover: rgba(255, 255, 255, 0.115);
    --border-color: rgba(255, 255, 255, 0.16);
    --text-main: #ffffff;
    --text-muted: rgba(255, 255, 255, 0.6);
    --bg-sub-card: rgba(0, 0, 0, 0.35);
    --grad-1: rgba(96,165,250,.24);
    --grad-2: rgba(96,165,250,.20);
    --grad-3: rgba(52,211,153,.13);
  }}

  html,body{{background:var(--bg-main); transition: background 0.3s ease, color 0.3s ease;}}
  body{{
    background:
      radial-gradient(ellipse 80% 50% at 10% -10%, var(--grad-1), transparent 50%),
      radial-gradient(ellipse 60% 40% at 95% 15%, var(--grad-2), transparent 45%),
      radial-gradient(ellipse 55% 35% at 60% 100%, var(--grad-3), transparent 40%),
      var(--bg-main);
  }}
  .status-dot{{box-shadow:0 0 10px currentColor}}
  ::-webkit-scrollbar{{width:8px;height:8px}}
  ::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.12);border-radius:99px}}
  * {{ box-shadow: none !important; }}
  .copy-btn svg{{transition:none}}
  
  .dynamic-card {{
    background-color: var(--bg-card);
    border-color: var(--border-color);
    transition: background-color 0.3s ease, border-color 0.3s ease;
  }}
  .dynamic-card:hover {{
    background-color: var(--bg-card-hover);
  }}
  .sub-box {{
    background-color: var(--bg-sub-card);
  }}

  /* ============================================================
     V2rayTun0 TELEGRAM HERO — PLAN 1 / 3D NEON
     ============================================================ */
  .tg-hero{{position:relative;overflow:hidden;isolation:isolate;min-height:168px;border:1px solid rgba(0,174,255,.35);border-radius:28px;background:radial-gradient(circle at 18% 50%,rgba(0,174,255,.18),transparent 28%),radial-gradient(circle at 82% 50%,rgba(139,92,246,.18),transparent 30%),linear-gradient(135deg,rgba(5,16,35,.98),rgba(7,8,20,.98));box-shadow:0 0 0 1px rgba(70,120,255,.08) inset,0 0 34px rgba(0,153,255,.10),0 0 70px rgba(124,58,237,.07);transform:translateZ(0);}}
  .tg-hero::before{{content:"";position:absolute;inset:-2px;border-radius:30px;padding:1px;background:linear-gradient(110deg,transparent 5%,rgba(0,198,255,.85) 28%,rgba(124,58,237,.9) 55%,rgba(236,72,153,.8) 78%,transparent 95%);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:tgBorder 5s linear infinite;pointer-events:none;}}
  .tg-hero::after{{content:"";position:absolute;inset:0;background:linear-gradient(115deg,transparent 0%,rgba(255,255,255,.055) 45%,transparent 58%);transform:translateX(-120%);animation:tgSweep 5.5s ease-in-out infinite;pointer-events:none;}}
  .tg-hero-inner{{position:relative;z-index:2;display:grid;grid-template-columns:150px 1fr auto;align-items:center;gap:24px;padding:22px 28px;min-height:168px;}}
  .tg-visual{{position:relative;width:124px;height:124px;display:grid;place-items:center;justify-self:center;perspective:800px;}}
  .tg-orbit{{position:absolute;inset:3px;border:1px solid rgba(0,191,255,.48);border-radius:50%;transform:rotateX(68deg) rotateZ(-15deg);animation:tgOrbit 7s linear infinite;box-shadow:0 0 16px rgba(0,174,255,.18);}}
  .tg-orbit::before,.tg-orbit::after{{content:"";position:absolute;inset:-8px;border:1px solid rgba(96,165,250,.22);border-radius:50%;}}
  .tg-orbit::after{{inset:9px;border-color:rgba(168,85,247,.28);transform:rotate(55deg);}}
  .tg-logo-wrap{{position:relative;width:84px;height:84px;border-radius:27px;display:grid;place-items:center;color:#fff;background:linear-gradient(145deg,#21a7ff 0%,#1677ee 48%,#6844f5 100%);border:1px solid rgba(255,255,255,.32);box-shadow:-9px 10px 0 rgba(4,45,110,.55),0 12px 28px rgba(0,136,255,.45),0 0 34px rgba(0,174,255,.38);transform:rotateX(8deg) rotateY(-10deg) translateZ(20px);animation:tgFloat 3.8s ease-in-out infinite;}}
  .tg-logo-wrap::before{{content:"";position:absolute;inset:6px;border-radius:21px;border:1px solid rgba(255,255,255,.22);background:linear-gradient(135deg,rgba(255,255,255,.18),transparent 45%);pointer-events:none;}}
  .tg-logo-wrap svg{{position:relative;width:49px;height:49px;filter:drop-shadow(0 3px 4px rgba(0,0,0,.35));}}
  .tg-copy{{min-width:0;direction:rtl;}}
  .tg-kicker{{font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;color:#67d9ff;margin-bottom:6px;}}
  .tg-title{{font-size:clamp(18px,2.4vw,25px);font-weight:900;color:#f8fbff;line-height:1.5;}}
  .tg-title em{{font-style:normal;color:#52c7ff;text-shadow:0 0 18px rgba(0,174,255,.28);}}
  .tg-desc{{margin-top:7px;font-size:11px;color:rgba(226,232,240,.52);line-height:1.8;}}
  .tg-handle{{display:inline-flex;align-items:center;gap:7px;margin-top:11px;padding:7px 12px;border-radius:999px;color:#c4b5fd;background:rgba(124,58,237,.10);border:1px solid rgba(167,139,250,.25);font-size:12px;font-weight:900;direction:ltr;box-shadow:0 0 18px rgba(124,58,237,.10);}}
  .tg-handle-dot{{width:7px;height:7px;border-radius:50%;background:#38bdf8;box-shadow:0 0 10px #38bdf8;animation:tgPulse 1.8s ease-in-out infinite;}}
  .tg-join{{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:10px;min-width:188px;padding:14px 19px;border-radius:17px;text-decoration:none;color:#fff;font-size:13px;font-weight:900;background:linear-gradient(110deg,#168cff,#3b63ff 52%,#a43cff);border:1px solid rgba(255,255,255,.28);box-shadow:0 8px 0 rgba(25,45,130,.52),0 12px 28px rgba(37,99,235,.34),0 0 30px rgba(139,92,246,.20);transform:translateY(-3px);transition:transform .22s ease,filter .22s ease,box-shadow .22s ease;overflow:hidden;white-space:nowrap;}}
  .tg-join::before{{content:"";position:absolute;inset:0;background:linear-gradient(100deg,transparent 20%,rgba(255,255,255,.28) 48%,transparent 72%);transform:translateX(-120%);animation:tgButtonSweep 3.2s ease-in-out infinite;}}
  .tg-join:hover{{transform:translateY(-6px) scale(1.015);filter:saturate(1.12);box-shadow:0 11px 0 rgba(25,45,130,.45),0 18px 38px rgba(37,99,235,.42),0 0 38px rgba(139,92,246,.28);}}
  .tg-join:active{{transform:translateY(1px);box-shadow:0 3px 0 rgba(25,45,130,.45),0 8px 18px rgba(37,99,235,.25);}}
  .tg-join svg{{width:19px;height:19px;position:relative;z-index:1;}}
  .tg-join span{{position:relative;z-index:1;}}
  .tg-bell{{position:absolute;right:28px;top:20px;color:#8be9ff;opacity:.65;animation:tgBell 2.6s ease-in-out infinite;filter:drop-shadow(0 0 8px rgba(0,191,255,.55));}}
  .tg-particle{{position:absolute;border-radius:50%;pointer-events:none;opacity:.75;}}
  .tg-p1{{width:5px;height:5px;left:42%;top:17%;background:#22d3ee;box-shadow:0 0 12px #22d3ee;animation:tgParticle1 5s ease-in-out infinite;}}
  .tg-p2{{width:3px;height:3px;left:62%;bottom:18%;background:#a78bfa;box-shadow:0 0 10px #a78bfa;animation:tgParticle2 4s ease-in-out infinite;}}
  .tg-p3{{width:4px;height:4px;right:19%;top:62%;background:#f472b6;box-shadow:0 0 12px #f472b6;animation:tgParticle3 6s ease-in-out infinite;}}
  @keyframes tgFloat{{0%,100%{{transform:rotateX(8deg) rotateY(-10deg) translate3d(0,0,20px)}}50%{{transform:rotateX(-5deg) rotateY(8deg) translate3d(0,-8px,28px)}}}}
  @keyframes tgOrbit{{to{{transform:rotateX(68deg) rotateZ(345deg)}}}}
  @keyframes tgBorder{{to{{filter:hue-rotate(360deg)}}}}
  @keyframes tgSweep{{0%,30%{{transform:translateX(-120%)}}65%,100%{{transform:translateX(120%)}}}}
  @keyframes tgButtonSweep{{0%,35%{{transform:translateX(-130%)}}70%,100%{{transform:translateX(130%)}}}}
  @keyframes tgPulse{{0%,100%{{opacity:.45;transform:scale(.8)}}50%{{opacity:1;transform:scale(1.2)}}}}
  @keyframes tgBell{{0%,75%,100%{{transform:rotate(0)}}80%{{transform:rotate(10deg)}}85%{{transform:rotate(-10deg)}}90%{{transform:rotate(6deg)}}95%{{transform:rotate(-4deg)}}}}
  @keyframes tgParticle1{{0%,100%{{transform:translate(0,0);opacity:.2}}50%{{transform:translate(30px,16px);opacity:1}}}}
  @keyframes tgParticle2{{0%,100%{{transform:translate(0,0);opacity:.25}}50%{{transform:translate(-22px,-12px);opacity:1}}}}
  @keyframes tgParticle3{{0%,100%{{transform:translate(0,0);opacity:.25}}50%{{transform:translate(12px,20px);opacity:1}}}}
  @media (max-width:700px){{.tg-hero{{min-height:unset;border-radius:22px;}}.tg-hero-inner{{grid-template-columns:76px minmax(0,1fr);gap:13px;padding:16px 14px;min-height:126px;}}.tg-visual{{width:70px;height:70px;}}.tg-logo-wrap{{width:54px;height:54px;border-radius:18px;box-shadow:-5px 6px 0 rgba(4,45,110,.5),0 8px 20px rgba(0,136,255,.4),0 0 24px rgba(0,174,255,.3);}}.tg-logo-wrap svg{{width:32px;height:32px;}}.tg-orbit{{inset:2px;}}.tg-kicker{{font-size:8px;margin-bottom:2px;}}.tg-title{{font-size:15px;line-height:1.5;}}.tg-desc{{font-size:9px;margin-top:3px;line-height:1.6;}}.tg-handle{{margin-top:6px;padding:5px 9px;font-size:10px;}}.tg-join{{grid-column:1 / -1;width:100%;min-width:0;padding:11px 14px;border-radius:14px;font-size:12px;transform:none;box-shadow:0 6px 0 rgba(25,45,130,.5),0 10px 22px rgba(37,99,235,.26);}}.tg-bell{{right:10px;top:10px;transform:scale(.72);}}}}
  @media (prefers-reduced-motion:reduce){{.tg-hero::before,.tg-hero::after,.tg-orbit,.tg-logo-wrap,.tg-join::before,.tg-handle-dot,.tg-bell,.tg-particle{{animation:none!important;}}}}

  /* ============================================================
     ONEX PREMIUM GLASS SYSTEM — SUBSCRIPTION PAGE
     Deep 3D glass, luminous edges, reflections and animated depth
     ============================================================ */
  .w-full.max-w-4xl.mx-auto.space-y-5{{position:relative;}}
  .w-full.max-w-4xl.mx-auto.space-y-5::before{{
    content:"";position:fixed;inset:-25%;pointer-events:none;z-index:-1;
    background:
      radial-gradient(circle at 15% 22%,rgba(0,174,255,.13),transparent 24%),
      radial-gradient(circle at 85% 38%,rgba(124,58,237,.12),transparent 25%),
      radial-gradient(circle at 52% 86%,rgba(16,185,129,.08),transparent 22%);
    filter:blur(28px);animation:pageAura 12s ease-in-out infinite alternate;
  }}

  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card{{
    position:relative;isolation:isolate;overflow:hidden;
    border-radius:24px !important;
    background:
      linear-gradient(145deg,rgba(28,52,88,.70),rgba(8,17,34,.78) 48%,rgba(19,12,43,.70)) !important;
    border:1px solid rgba(94,183,255,.30) !important;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.14),
      inset 0 -1px 0 rgba(0,0,0,.35),
      inset 0 0 55px rgba(45,125,255,.08),
      0 18px 45px rgba(0,0,0,.28),
      0 0 30px rgba(37,99,235,.07) !important;
    backdrop-filter:blur(24px) saturate(150%);-webkit-backdrop-filter:blur(24px) saturate(150%);
    transform:translateZ(0);transition:transform .35s ease,border-color .35s ease,box-shadow .35s ease;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::before{{
    content:"";position:absolute;inset:0;z-index:-1;pointer-events:none;border-radius:inherit;
    background:
      radial-gradient(ellipse at 8% 15%,rgba(0,198,255,.18),transparent 28%),
      radial-gradient(ellipse at 92% 85%,rgba(124,58,237,.17),transparent 30%),
      linear-gradient(120deg,transparent 0%,rgba(255,255,255,.045) 42%,transparent 58%);
    background-size:auto,auto,220% 100%;
    animation:glassFlow 9s ease-in-out infinite;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::after{{
    content:"";position:absolute;top:-120%;left:-35%;width:34%;height:340%;z-index:3;pointer-events:none;
    background:linear-gradient(90deg,transparent,rgba(255,255,255,.12),transparent);
    transform:rotate(22deg);animation:glassSweep 7s ease-in-out infinite;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:hover{{
    transform:translateY(-3px);
    border-color:rgba(86,190,255,.48) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.18),inset 0 0 65px rgba(45,125,255,.11),0 24px 55px rgba(0,0,0,.34),0 0 38px rgba(37,99,235,.12) !important;
  }}

  /* Different glass tones, like the reference concept */
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(2){{
    background:linear-gradient(145deg,rgba(8,73,91,.68),rgba(7,27,47,.80),rgba(5,17,31,.78)) !important;
    border-color:rgba(34,211,238,.30) !important;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(3){{
    background:linear-gradient(145deg,rgba(30,50,96,.72),rgba(10,24,53,.80),rgba(30,15,62,.68)) !important;
    border-color:rgba(96,165,250,.32) !important;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(4){{
    background:linear-gradient(145deg,rgba(12,66,76,.66),rgba(8,28,45,.80),rgba(7,18,35,.80)) !important;
    border-color:rgba(45,212,191,.27) !important;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(5){{
    background:linear-gradient(145deg,rgba(39,26,82,.72),rgba(17,19,50,.80),rgba(8,25,48,.76)) !important;
    border-color:rgba(168,85,247,.34) !important;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(6){{
    background:linear-gradient(145deg,rgba(12,59,75,.68),rgba(8,25,44,.80),rgba(12,18,39,.78)) !important;
    border-color:rgba(45,212,191,.28) !important;
  }}

  .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box{{
    position:relative;overflow:hidden;
    background:linear-gradient(145deg,rgba(28,58,99,.55),rgba(7,18,37,.72)) !important;
    border:1px solid rgba(94,170,255,.22) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.075),inset 0 0 28px rgba(59,130,246,.06),0 8px 24px rgba(0,0,0,.12) !important;
    transition:transform .28s ease,border-color .28s ease,box-shadow .28s ease,background .28s ease;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box::before{{
    content:"";position:absolute;inset:0;pointer-events:none;
    background:linear-gradient(115deg,transparent 25%,rgba(255,255,255,.055) 48%,transparent 68%);
    transform:translateX(-120%);animation:subBoxShine 6s ease-in-out infinite;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box:hover{{
    transform:translateY(-2px) perspective(700px) rotateX(1deg);
    border-color:rgba(83,180,255,.42) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.11),inset 0 0 34px rgba(59,130,246,.09),0 12px 28px rgba(0,0,0,.20),0 0 20px rgba(37,99,235,.08) !important;
  }}

  /* Give text/value blocks more luminous depth */
  .w-full.max-w-4xl.mx-auto.space-y-5 .text-purple-300{{text-shadow:0 0 14px rgba(168,85,247,.22);}}
  .w-full.max-w-4xl.mx-auto.space-y-5 .text-blue-300{{text-shadow:0 0 14px rgba(96,165,250,.22);}}
  .w-full.max-w-4xl.mx-auto.space-y-5 .text-emerald-300{{text-shadow:0 0 14px rgba(52,211,153,.20);}}
  .w-full.max-w-4xl.mx-auto.space-y-5 .text-amber-300{{text-shadow:0 0 14px rgba(251,191,36,.18);}}

  @keyframes pageAura{{0%{{transform:translate3d(-1%,0,0) scale(1)}}100%{{transform:translate3d(1%,-1%,0) scale(1.05)}}}}
  @keyframes glassFlow{{0%,100%{{background-position:center,center,0% 0}}50%{{background-position:center,center,120% 0}}}}
  @keyframes glassSweep{{0%,55%{{left:-35%;opacity:0}}65%{{opacity:1}}100%{{left:120%;opacity:0}}}}
  @keyframes subBoxShine{{0%,58%{{transform:translateX(-120%);opacity:0}}68%{{opacity:1}}100%{{transform:translateX(120%);opacity:0}}}}

  @media (max-width:700px){{
    .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card{{
      border-radius:20px !important;
      box-shadow:inset 0 1px 0 rgba(255,255,255,.12),inset 0 0 42px rgba(45,125,255,.075),0 14px 34px rgba(0,0,0,.26) !important;
    }}
    .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:hover{{transform:none;}}
    .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box:hover{{transform:none;}}
  }}
  @media (prefers-reduced-motion:reduce){{
    .w-full.max-w-4xl.mx-auto.space-y-5::before,.w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::before,.w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::after,.w-full.max-w-4xl.mx-auto.space-y-5 .sub-box::before{{animation:none!important;}}
  }}


  /* ============================================================
     GLASS PANELS — COLORFUL NEON GLASS (PLAN 1 FINAL)
     ============================================================ */
  .dynamic-card{{
    position:relative;
    overflow:hidden;
    background:
      radial-gradient(120% 150% at 100% 0%,rgba(72,115,255,.105),transparent 46%),
      radial-gradient(100% 130% at 0% 100%,rgba(139,92,246,.075),transparent 48%),
      linear-gradient(135deg,rgba(18,25,43,.78),rgba(8,11,21,.82));
    border-color:rgba(105,145,255,.18);
    box-shadow:inset 0 1px 0 rgba(255,255,255,.055),inset 0 0 35px rgba(72,115,255,.025),0 14px 40px rgba(0,0,0,.16) !important;
    backdrop-filter:blur(22px) saturate(125%);
  }}
  .dynamic-card::before{{
    content:"";position:absolute;inset:0;pointer-events:none;border-radius:inherit;
    background:linear-gradient(115deg,rgba(255,255,255,.045),transparent 22%,transparent 72%,rgba(96,165,250,.055));
    opacity:.9;
  }}
  .dynamic-card:nth-of-type(2n){{
    background:
      radial-gradient(110% 150% at 0% 0%,rgba(0,174,255,.10),transparent 45%),
      radial-gradient(100% 130% at 100% 100%,rgba(37,99,235,.075),transparent 48%),
      linear-gradient(135deg,rgba(14,25,43,.80),rgba(7,11,20,.84));
    border-color:rgba(56,189,248,.17);
  }}
  .dynamic-card:nth-of-type(3n){{
    background:
      radial-gradient(120% 140% at 100% 10%,rgba(168,85,247,.105),transparent 44%),
      radial-gradient(100% 130% at 0% 100%,rgba(52,211,153,.055),transparent 46%),
      linear-gradient(135deg,rgba(24,20,43,.80),rgba(9,10,21,.84));
    border-color:rgba(167,139,250,.17);
  }}
  .sub-box{{
    background:
      linear-gradient(135deg,rgba(20,27,45,.66),rgba(9,12,22,.72));
    border-color:rgba(110,145,220,.12) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.028),inset 0 0 22px rgba(96,165,250,.025) !important;
  }}
  .dynamic-card:hover{{
    background:
      radial-gradient(120% 150% at 100% 0%,rgba(72,115,255,.14),transparent 46%),
      radial-gradient(100% 130% at 0% 100%,rgba(139,92,246,.10),transparent 48%),
      linear-gradient(135deg,rgba(21,29,49,.84),rgba(8,11,21,.88));
    border-color:rgba(96,165,250,.25);
  }}
  @media (max-width:700px){{
    .dynamic-card{{
      background:
        radial-gradient(120% 140% at 100% 0%,rgba(72,115,255,.095),transparent 44%),
        radial-gradient(100% 120% at 0% 100%,rgba(139,92,246,.065),transparent 46%),
        linear-gradient(135deg,rgba(17,24,40,.80),rgba(7,10,19,.86));
      border-color:rgba(96,140,245,.17);
    }}
    .sub-box{{background:linear-gradient(135deg,rgba(19,26,43,.62),rgba(8,11,20,.70));}}
  }}

  /* FORCE VISIBLE GLASS COLOR - SUBSCRIPTION PAGE */
  .dynamic-card{{
    background:
      linear-gradient(135deg,rgba(24,58,105,.72) 0%,rgba(18,31,61,.68) 45%,rgba(18,12,42,.72) 100%) !important;
    border:1px solid rgba(83,150,255,.38) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.12),inset 0 0 45px rgba(45,120,255,.10),0 12px 35px rgba(0,0,0,.22) !important;
    backdrop-filter:blur(24px) saturate(145%);
    -webkit-backdrop-filter:blur(24px) saturate(145%);
  }}
  .dynamic-card:nth-of-type(2n){{
    background:
      linear-gradient(135deg,rgba(20,74,94,.70) 0%,rgba(12,38,65,.68) 48%,rgba(11,22,43,.74) 100%) !important;
    border-color:rgba(34,211,238,.34) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.11),inset 0 0 45px rgba(34,211,238,.09),0 12px 35px rgba(0,0,0,.22) !important;
  }}
  .dynamic-card:nth-of-type(3n){{
    background:
      linear-gradient(135deg,rgba(55,34,91,.72) 0%,rgba(30,24,62,.69) 50%,rgba(18,15,42,.74) 100%) !important;
    border-color:rgba(168,85,247,.36) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.11),inset 0 0 45px rgba(139,92,246,.10),0 12px 35px rgba(0,0,0,.22) !important;
  }}
  .sub-box{{
    background:linear-gradient(135deg,rgba(27,49,82,.72),rgba(12,20,39,.78)) !important;
    border-color:rgba(96,165,250,.24) !important;
    box-shadow:inset 0 1px 0 rgba(255,255,255,.07),inset 0 0 28px rgba(59,130,246,.07) !important;
  }}
  .dynamic-card .text-white\/40{{color:rgba(226,232,240,.58) !important;}}
  .dynamic-card .text-white\/45{{color:rgba(226,232,240,.68) !important;}}
  .dynamic-card .text-white\/35{{color:rgba(226,232,240,.55) !important;}}
  @media (max-width:700px){{
    .dynamic-card{{
      background:linear-gradient(135deg,rgba(23,56,100,.76),rgba(13,27,54,.72),rgba(25,15,51,.76)) !important;
      border-color:rgba(83,150,255,.40) !important;
    }}
    .dynamic-card:nth-of-type(2n){{
      background:linear-gradient(135deg,rgba(18,69,88,.75),rgba(11,35,60,.73),rgba(8,20,38,.78)) !important;
      border-color:rgba(34,211,238,.36) !important;
    }}
    .dynamic-card:nth-of-type(3n){{
      background:linear-gradient(135deg,rgba(53,32,88,.76),rgba(28,22,58,.73),rgba(17,14,39,.78)) !important;
      border-color:rgba(168,85,247,.38) !important;
    }}
    .sub-box{{background:linear-gradient(135deg,rgba(26,48,79,.72),rgba(10,18,36,.80)) !important;}}
  }}

  /* ============================================================
     ONEX GLASS PERFORMANCE PATCH
     Keep the 3D/glass look, but avoid expensive blur/compositor work.
     The Telegram hero keeps its richer animation; dashboard cards stay
     visually rich but render immediately and cheaply on mobile.
     ============================================================ */
  .w-full.max-w-4xl.mx-auto.space-y-5::before{{
    background:
      radial-gradient(circle at 12% 18%,rgba(0,174,255,.12),transparent 24%),
      radial-gradient(circle at 88% 35%,rgba(124,58,237,.10),transparent 25%),
      radial-gradient(circle at 50% 88%,rgba(16,185,129,.07),transparent 22%);
    filter:none !important;
    animation:none !important;
    opacity:.9;
  }}

  /* Realistic glass without backdrop-filter: much faster to paint. */
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card,
  .dynamic-card{{
    -webkit-backdrop-filter:none !important;
    backdrop-filter:none !important;
    background:
      linear-gradient(145deg,rgba(40,78,125,.64) 0%,rgba(16,35,65,.72) 42%,rgba(12,17,37,.82) 100%) !important;
    border:1px solid rgba(107,190,255,.34) !important;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.17),
      inset 0 -1px 0 rgba(0,0,0,.38),
      inset 12px 0 38px rgba(40,170,255,.055),
      inset -12px 0 38px rgba(124,58,237,.045),
      0 16px 42px rgba(0,0,0,.30),
      0 0 26px rgba(37,140,255,.07) !important;
    transform:translateZ(0);
    contain:paint;
  }}

  /* Static glossy reflection = no continuous repainting. */
  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::before,
  .dynamic-card::before{{
    content:"";
    position:absolute;
    inset:0;
    pointer-events:none;
    border-radius:inherit;
    background:
      linear-gradient(118deg,rgba(255,255,255,.10) 0%,transparent 16%,transparent 68%,rgba(74,170,255,.055) 100%),
      radial-gradient(80% 80% at 0% 0%,rgba(76,190,255,.10),transparent 55%);
    opacity:1;
    animation:none !important;
  }}

  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::after{{
    animation:none !important;
    opacity:0 !important;
  }}

  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(2),
  .dynamic-card:nth-of-type(2n){{
    background:
      linear-gradient(145deg,rgba(18,102,123,.60) 0%,rgba(10,48,70,.70) 44%,rgba(7,21,39,.82) 100%) !important;
    border-color:rgba(46,211,238,.34) !important;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.16),
      inset 0 0 48px rgba(34,211,238,.07),
      0 16px 42px rgba(0,0,0,.30),0 0 28px rgba(34,211,238,.07) !important;
  }}

  .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:nth-of-type(3),
  .dynamic-card:nth-of-type(3n){{
    background:
      linear-gradient(145deg,rgba(61,46,119,.64) 0%,rgba(31,30,72,.70) 46%,rgba(13,15,38,.82) 100%) !important;
    border-color:rgba(167,139,250,.36) !important;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.16),
      inset 0 0 48px rgba(139,92,246,.075),
      0 16px 42px rgba(0,0,0,.30),0 0 28px rgba(139,92,246,.07) !important;
  }}

  .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box{{
    -webkit-backdrop-filter:none !important;
    backdrop-filter:none !important;
    background:
      linear-gradient(145deg,rgba(35,76,122,.48),rgba(12,27,51,.70)) !important;
    border:1px solid rgba(103,181,255,.24) !important;
    box-shadow:
      inset 0 1px 0 rgba(255,255,255,.10),
      inset 0 -10px 24px rgba(0,0,0,.14),
      0 8px 24px rgba(0,0,0,.16) !important;
    contain:paint;
  }}
  .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box::before{{
    animation:none !important;
    background:linear-gradient(115deg,rgba(255,255,255,.07),transparent 24%,transparent 72%,rgba(96,165,250,.05));
    transform:none !important;
    opacity:1 !important;
  }}

  /* Mobile: no blur, no continuous card animation, same premium glass depth. */
  @media (max-width:700px){{
    .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card,
    .dynamic-card{{
      -webkit-backdrop-filter:none !important;
      backdrop-filter:none !important;
      border-radius:20px !important;
      box-shadow:
        inset 0 1px 0 rgba(255,255,255,.15),
        inset 0 -1px 0 rgba(0,0,0,.32),
        inset 0 0 38px rgba(45,140,255,.065),
        0 12px 30px rgba(0,0,0,.28) !important;
    }}
    .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card:hover,
    .dynamic-card:hover,
    .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box:hover{{
      transform:none !important;
    }}
  }}

  @media (prefers-reduced-motion:reduce){{
    .w-full.max-w-4xl.mx-auto.space-y-5 > section.dynamic-card::before,
    .dynamic-card::before,
    .w-full.max-w-4xl.mx-auto.space-y-5 .sub-box::before{{animation:none!important;}}
  }}

</style>
</head>
<body class="font-vazir text-slate-100 antialiased min-h-screen py-8 px-3 sm:px-4 md:py-14">

<div class="w-full max-w-4xl mx-auto space-y-5 sm:space-y-6 md:space-y-8">

  <!-- Top Bar Theme Toggle Button -->
  <div class="flex justify-end">
    <button type="button" onclick="toggleTheme()" class="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-extrabold text-amber-300 border border-amber-400/30 bg-amber-400/10 hover:bg-amber-400/20 transition-colors shadow-lg">
      <svg id="themeIcon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      تغییر تم
    </button>
  </div>

  <!-- Telegram Channel Hero -->
  <section class="tg-hero" aria-label="عضویت در کانال تلگرام">
    <div class="tg-particle tg-p1"></div><div class="tg-particle tg-p2"></div><div class="tg-particle tg-p3"></div>
    <div class="tg-bell" aria-hidden="true"><svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg></div>
    <div class="tg-hero-inner">
      <div class="tg-visual" aria-hidden="true"><div class="tg-orbit"></div><div class="tg-logo-wrap"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.6 3.1 18.2 19c-.26 1.16-.95 1.45-1.92.9l-5.22-3.84-2.52 2.43c-.28.28-.51.51-1.05.51l.37-5.32 9.68-8.75c.42-.37-.09-.58-.65-.21L4.92 12.86.14 11.34c-1.04-.33-1.06-1.04.22-1.54L19.04 2.56c.88-.33 1.65.2 1.56.54Z"/></svg></div></div>
      <div class="tg-copy"><div class="tg-kicker">OFFICIAL TELEGRAM CHANNEL</div><div class="tg-title">به کانال تلگرام <em>ما بپیوندید</em></div><div class="tg-desc">آخرین اخبار، آپدیت‌ها و اطلاع‌رسانی‌ها را مستقیم دریافت کنید.</div><div class="tg-handle"><span class="tg-handle-dot"></span>@V2rayTun0</div></div>
      <a class="tg-join" href="https://t.me/V2rayTun0" target="_blank" rel="noopener noreferrer" aria-label="عضویت در کانال تلگرام V2rayTun0"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.6 3.1 18.2 19c-.26 1.16-.95 1.45-1.92.9l-5.22-3.84-2.52 2.43c-.28.28-.51.51-1.05.51l.37-5.32 9.68-8.75c.42-.37-.09-.58-.65-.21L4.92 12.86.14 11.34c-1.04-.33-1.06-1.04.22-1.54L19.04 2.56c.88-.33 1.65.2 1.56.54Z"/></svg><span>عضویت در کانال</span></a>
    </div>
  </section>

  <!-- Hero -->
  <section class="rounded-[26px] sm:rounded-[28px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-8">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-5">
      <div class="flex items-center gap-4">
        <div class="w-13 h-13 sm:w-14 sm:h-14 shrink-0 rounded-2xl grid place-items-center bg-gradient-to-br from-blue-400/20 to-purple-400/10 border border-blue-400/25 text-blue-300">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5.2-3.4 9-8 10-4.6-1-8-4.8-8-10V6l8-4z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>
        </div>
        <div class="min-w-0">
          <h1 class="text-lg sm:text-xl md:text-2xl font-black tracking-tight truncate">{label_escaped}</h1>
          <p class="mt-1.5 text-[10.5px] sm:text-[11px] text-white/40 break-all">UUID: {uid_escaped}</p>
        </div>
      </div>
      <div class="flex items-center gap-2.5 self-start md:self-auto flex-wrap">
        <button type="button" onclick="openQrModal()" class="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-extrabold text-purple-300 border border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/20 transition-colors">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          QR Code
        </button>
        <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-extrabold {status_badge_html}">
          <span class="status-dot w-2 h-2 rounded-full bg-current"></span>
          {status_text}
        </div>
      </div>
    </div>
  </section>

  <!-- Usage overview -->
  <section class="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-5 sm:gap-6">

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><path d="M3 3v18h18"/><path d="M7 15l4-6 3 3 4-7"/></svg>
        <div>
          <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Traffic Overview</p>
          <p class="mt-0.5 text-sm font-black">مصرف سرویس</p>
        </div>
      </div>

      <div class="mt-6 flex flex-col sm:flex-row items-center sm:items-start gap-6">
        <div class="relative shrink-0 w-[128px] h-[128px]">
          <svg width="128" height="128" viewBox="0 0 132 132" class="-rotate-90">
            <circle cx="66" cy="66" r="54" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="10"/>
            <circle cx="66" cy="66" r="54" fill="none" stroke="url(#usageRingGradient)" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="339.29" stroke-dashoffset="{dash_calc_offset}"/>
            <defs>
              <linearGradient id="usageRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#34d399"/>
                <stop offset="100%" stop-color="#f59e0b"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="absolute inset-0 grid place-items-center">
            <div class="text-center">
              <p class="text-xl font-black leading-none">{usage_percent}%</p>
              <p class="mt-1.5 text-[10px] text-white/40">مصرف‌شده</p>
            </div>
          </div>
        </div>

        <div class="flex-1 w-full min-w-0">
          <div class="text-xl sm:text-2xl font-black tracking-tight">
            {used_bytes_str}
            <span class="text-sm font-semibold text-white/40"> / {limit_bytes_str}</span>
          </div>

          <div class="mt-4 rounded-xl border border-white/[0.05] sub-box px-3 pt-3 pb-1.5">
            <p class="flex items-center gap-1.5 text-[10px] text-white/35 mb-1">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M17 7h4v4"/></svg>
              روند مصرف
            </p>
            <svg viewBox="0 0 300 64" class="w-full h-14" preserveAspectRatio="none">
              <defs>
                <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.35"/>
                  <stop offset="100%" stop-color="#60a5fa" stop-opacity="0"/>
                </linearGradient>
              </defs>
              <path d="M0,64 L{svg_points} L300,64 Z" fill="url(#trendFill)"/>
              <path d="M{svg_points}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>

          <div class="mt-4 flex items-center justify-between text-[11px] text-white/40 flex-wrap gap-2">
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
              باقی‌مانده: <b class="text-white/70 font-bold">{remaining_value_escaped}</b>
            </span>
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
              زمان: <b class="text-white/70 font-bold">{expiry_remaining_escaped}</b>
            </span>

          </div>
        </div>
      </div>
    </div>

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/></svg>
        <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Service</p>
      </div>
      <div class="mt-4 divide-y divide-white/[0.06]">
        <div class="flex items-center justify-between py-3 first:pt-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
            انقضا
          </span>
          <span class="text-xs font-extrabold">{expiry_display_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><path d="M12 20h.01"/></svg>
            IP Limit
          </span>
          <span class="text-xs font-extrabold">{ip_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/><rect x="2" y="9" width="20" height="8" rx="2"/><path d="M6 17v2M18 17v2"/></svg>
            Connection
          </span>
          <span class="text-xs font-extrabold">{connection_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3 last:pb-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
            Speed
          </span>
          <span class="text-xs font-extrabold">{speed_limit_escaped}</span>
        </div>
      </div>
    </div>

  </section>

  <!-- Stats -->
  <section class="grid grid-cols-2 md:grid-cols-4 gap-3.5 sm:gap-4 md:gap-5">

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-emerald-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-emerald-400/10 border border-emerald-400/20 text-emerald-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 9l-5 5-3-3-4 4"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">مصرف فعلی</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-emerald-300 break-words">{used_bytes_str}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-amber-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-amber-400/10 border border-amber-400/20 text-amber-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-amber-300 break-words">{remaining_value_escaped}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-blue-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 4v16M4 9h16"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">اتصالات فعال</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-blue-300 break-words">{len(unique_ips_for_uuid(uid))}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-purple-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-purple-400/10 border border-purple-400/20 text-purple-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l9 4.5v6c0 5-3.6 8.7-9 9.5-5.4-.8-9-4.5-9-9.5v-6L12 2z"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">زمان باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-purple-300 break-words">{expiry_remaining_escaped}</p>
    </div>

  </section>

  <!-- Technical details -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M4 21v-7M4 10V3M12 21v-11M12 6V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        جزئیات فنی
      </p>
      <p class="text-[11px] text-white/40">Configuration Details</p>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Protocol</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{protocol_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Fingerprint</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{fingerprint_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">IP Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{ip_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Connection Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{connection_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Speed Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{speed_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">تاریخ انقضا</p>
        <p class="mt-2 text-xs font-bold text-white/85">{expiry_display_escaped}</p>
      </div>
    </div>
  </section>

  <!-- Links -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.5"/><path d="M14 11a5 5 0 0 0-7.07 0l-2.83 2.83a5 5 0 0 0 7.07 7.07l1.41-1.41"/></svg>
        لینک‌های سرویس
      </p>
      <p class="text-[11px] text-white/40">Copy / Import</p>
    </div>

    <div class="space-y-3">
      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">VLESS</p>
          <p id="vlessLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{vless_url_escaped}</p>
        </div>
        <button id="vlessCopyBtn" type="button" onclick="pxCopy('vlessLinkText','vlessCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>

      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">SUBSCRIPTION</p>
          <p id="subLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{sub_url_escaped}</p>
        </div>
        <button id="subCopyBtn" type="button" onclick="pxCopy('subLinkText','subCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>
    </div>
  </section>

  <!-- Downloads -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
        دانلود برنامه‌ها
      </p>
      <p class="text-[11px] text-white/40">Official Releases</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
      <a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">NG</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayNG</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android</p>
        </div>
      </a>
      <a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">N</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayN</p>
          <p class="mt-0.5 text-[10px] text-white/40">Windows / macOS / Linux</p>
        </div>
      </a>
      <a href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">H</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">Hiddify</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android / Windows / macOS / Linux</p>
        </div>
      </a>
    </div>
  </section>


</div>

<!-- QR Code Modal Popup -->
<div id="qrModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md hidden">
  <div class="w-full max-w-sm rounded-[24px] border border-white/15 bg-[#0b0c14] p-6 text-center shadow-2xl relative">
    <button type="button" onclick="closeQrModal()" class="absolute top-4 left-4 w-8 h-8 rounded-full bg-white/5 border border-white/10 grid place-items-center text-white/60 hover:text-white">✕</button>
    <p class="text-sm font-black text-white/90 mb-2">QR Code اسکن کانفیگ</p>
    <p class="text-[11px] text-white/40 mb-4">برای اتصال سریع با گوشی موبایل</p>
    <div id="qrcodeContainer" class="bg-white p-4 rounded-2xl inline-block mx-auto mb-4 border border-white/10"></div>
    <p id="qrModalText" class="text-[10px] text-purple-300 break-all max-h-16 overflow-y-auto px-2" dir="ltr"></p>
  </div>
</div>

<script>
const vlessUrlData = "{vless_url}";

// Theme toggle logic with localStorage support (2 themes total)
function toggleTheme() {{
  const body = document.body;
  body.classList.toggle('theme-lighter');
  const isLighter = body.classList.contains('theme-lighter');
  localStorage.setItem('px_theme', isLighter ? 'lighter' : 'dark');
}}

// Initialize saved theme on load
(function() {{
  if (localStorage.getItem('px_theme') === 'lighter') {{
    document.body.classList.add('theme-lighter');
  }}
}})();

function openQrModal() {{
  var modal = document.getElementById('qrModal');
  var container = document.getElementById('qrcodeContainer');
  var txtEl = document.getElementById('qrModalText');
  container.innerHTML = "";
  txtEl.textContent = vlessUrlData;
  modal.classList.remove('hidden');
  try {{
    var typeNumber = 0;
    var errorCorrectionLevel = 'L';
    var qr = qrcode(typeNumber, errorCorrectionLevel);
    qr.addData(vlessUrlData);
    qr.make();
    container.innerHTML = qr.createImgTag(5, 8);
  }} catch (e) {{
    container.innerHTML = "<p class='text-xs text-black'>خطا در تولید QR Code</p>";
  }}
}}

function closeQrModal() {{
  document.getElementById('qrModal').classList.add('hidden');
}}

document.getElementById('qrModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQrModal();
}});

function pxCopy(textId, btnId) {{
  var el = document.getElementById(textId);
  var btn = document.getElementById(btnId);
  if (!el || !btn) return;
  var text = el.textContent.textContext || el.textContent.trim();
  var done = function() {{
    var original = btn.getAttribute('data-original');
    if (!original) {{
      original = btn.innerHTML;
      btn.setAttribute('data-original', original);
    }}
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><span>کپی شد</span>';
    btn.classList.add('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    setTimeout(function() {{
      btn.innerHTML = original;
      btn.classList.remove('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    }}, 1700);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallbackCopy(text, done); }});
  }} else {{
    fallbackCopy(text, done);
  }}
}}
function fallbackCopy(text, cb) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand('copy'); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (cb) cb();
}}
</script>
</body>
</html>"""
    return HTMLResponse(info_html)
# ============================================================
# SUB GROUP API
# ============================================================

@app.post("/api/subs")
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    sub_id, sub = await create_sub_group(
        name=body.get(
            "name",
            "گروه جدید",
        ),
        desc=body.get(
            "desc",
            "",
        ),
        password=body.get(
            "password",
            "",
        ),
    )

    host = get_host(request)

    return {
        "sub_id":
            sub_id,

        **sub,

        "password_hash":
            None,

        "public_url":
            (
                f"https://{host}"
                f"/p/{sub['uuid_key']}"
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{sub['uuid_key']}"
            ),
    }


@app.get("/api/subs")
async def list_subs_api(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with SUBS_LOCK:
        snapshot_subs = dict(SUBS)

    async with LINKS_LOCK:
        snapshot_links = dict(LINKS)

    result = []

    for sid, sub in snapshot_subs.items():

        link_ids = sub.get(
            "link_ids",
            [],
        )

        active_count = sum(
            1
            for lid in link_ids
            if is_link_allowed(
                snapshot_links.get(
                    lid
                )
            )
        )

        total_used = sum(
            snapshot_links[
                lid
            ].get(
                "used_bytes",
                0,
            )

            for lid in link_ids

            if lid in snapshot_links
        )

        result.append(
            {
                "sub_id":
                    sid,

                **sub,

                "password_hash":
                    None,

                "has_password":
                    sub.get(
                        "password_hash"
                    ) is not None,

                "links_count":
                    len(link_ids),

                "active_count":
                    active_count,

                "total_used_bytes":
                    total_used,

                "total_used_fmt":
                    fmt_bytes(
                        total_used
                    ),

                "public_url":
                    (
                        f"https://{host}"
                        f"/p/{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub-group/{sub['uuid_key']}"
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "subs": result
    }


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            raise HTTPException(
                status_code=404,
                detail="sub not found",
            )

        sub = SUBS[sub_id]

        if "name" in body:
            sub["name"] = str(
                body["name"]
            )[:60]

        if "desc" in body:
            sub["desc"] = str(
                body["desc"]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub["password_hash"] = (
                hash_password(password)
                if password
                else None
            )

        if "link_ids" in body:

            sub["link_ids"] = list(
                body["link_ids"]
            )

    await save_state()

    return {
        "ok": True
    }


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(
    sub_id: str,
    _=Depends(require_auth),
):

    name = await remove_sub_group(
        sub_id
    )

    if name is None:
        raise HTTPException(
            status_code=404,
            detail="sub not found",
        )

    return {
        "ok": True,
        "deleted": sub_id,
    }


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    link_id = str(
        body.get(
            "link_id",
            "",
        )
    )

    action = str(
        body.get(
            "action",
            "add",
        )
    )

    if action == "add":

        success = await set_link_sub(
            link_id,
            sub_id,
        )

    else:

        success = await set_link_sub(
            link_id,
            None,
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="link or sub not found",
        )

    return {
        "ok": True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub = next(
            (
                item
                for item
                in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if sub.get(
        "password_hash"
    ):

        password = (
            request.query_params.get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub["password_hash"]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )

    host = get_host(request)

    async with LINKS_LOCK:

        lines = []

        for link_id in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                link_id
            )

            if (
                link
                and is_link_allowed(
                    link
                )
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    )
                )

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    total_used = 0
    total_limit = 0
    expiries = []
    valid_ids = list(sub.get("link_ids", []))

    async with LINKS_LOCK:
        for link_id in valid_ids:
            link = LINKS.get(link_id)
            if not link or not is_link_allowed(link):
                continue
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            if link.get("expires_at"):
                expiries.append(str(link.get("expires_at")))

    # For a group subscription, expose aggregate usage/expiry in standard headers.
    group_limit = total_limit if total_limit > 0 else 0
    group_expiry = None
    if expiries:
        try:
            group_expiry = min(
                expiries,
                key=lambda x: datetime.fromisoformat(x)
            )
        except Exception:
            group_expiry = expiries[0]

    group_volume_text = (
        f"{fmt_bytes(total_used)}/{fmt_bytes(group_limit)}"
        if group_limit > 0
        else f"{fmt_bytes(total_used)}/∞"
    )
    group_expiry_text = group_expiry or "∞"
    group_title = (
        f"0.0.0.0 | {group_volume_text} | {group_expiry_text} | "
        f"{sub['name']} | کانال تلگرام: logic_sec"
    )
    headers = subscription_metadata_headers(
        total_used,
        group_limit,
        group_expiry,
        host,
        f"https://{host}/public-sub/{uuid_key}",
        group_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


# ============================================================
# PUBLIC GROUP
# ============================================================

PUBLIC_SUB_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>
<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PX Panel
</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    justify-content:center;
    align-items:center;

    padding:20px;

    font-family:Arial,sans-serif;

    color:#fff;

    background:
        radial-gradient(
            circle at top right,
            rgba(37,99,235,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:560px;

    padding:28px;
    border-radius:25px;

    background:rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:blur(25px);
}

h1{
    margin-top:0;
}

.text{
    color:rgba(255,255,255,.55);
    line-height:2;
    font-size:13px;
}

.url{
    margin-top:20px;
    padding:14px;

    border-radius:13px;

    background:rgba(0,0,0,.22);

    color:#93c5fd;

    direction:ltr;
    word-break:break-all;

    font-family:Consolas,monospace;
}

.support{
    display:inline-block;
    margin-top:18px;

    color:#60a5fa;
    text-decoration:none;
}

.version{
    color:#60a5fa;
    font-size:11px;
}

</style>
</head>

<body>

<div class="card">

<h1>
PX Panel
</h1>

<div class="version">
13.8.0
</div>

<div class="text">
اشتراک شما آماده است.
</div>

<div
class="url"
id="subUrl"
></div>

<a
class="support"
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
>
پشتیبانی @Pixonal
</a>

</div>

<script>

const url =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = url;

</script>

</body>
</html>
"""


@app.get(
    "/p/{uuid_key}",
    response_class=HTMLResponse,
)
async def public_sub_page(
    uuid_key: str,
):

    async with SUBS_LOCK:

        exists = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            """
            <h2
            style="
            font-family:sans-serif;
            padding:40px;
            "
            >
            گروه پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        entry = next(
            (
                (
                    sid,
                    item,
                )

                for sid, item
                in SUBS.items()

                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    _, sub = entry

    has_password = (
        sub.get(
            "password_hash"
        ) is not None
    )

    if has_password:

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub["name"],
                }
            )

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    links_out = []

    active_connections = 0

    for link_id in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            link_id
        )

        if not link:
            continue

        allowed = is_link_allowed(
            link
        )

        connection_count = sum(
            1
            for item in connections.values()
            if item.get("uuid") == link_id
        )

        active_connections += (
            connection_count
        )

        links_out.append(
            {
                "uuid":
                    link_id,

                "label":
                    link.get(
                        "label"
                    ),

                "active":
                    allowed,

                "protocol":
                    link.get(
                        "protocol",
                        DEFAULT_PROTOCOL,
                    ),

                "used_bytes":
                    link.get(
                        "used_bytes",
                        0,
                    ),

                "used_fmt":
                    fmt_bytes(
                        link.get(
                            "used_bytes",
                            0,
                        )
                    ),

                "limit_bytes":
                    link.get(
                        "limit_bytes",
                        0,
                    ),

                "limit_fmt":
                    (
                        "∞"
                        if not link.get(
                            "limit_bytes",
                            0,
                        )
                        else fmt_bytes(
                            link[
                                "limit_bytes"
                            ]
                        )
                    ),

                "expires_at":
                    link.get(
                        "expires_at"
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub/{link_id}"
                    ),

                "info_url":
                    (
                        f"https://{host}"
                        f"/info/{link_id}"
                    ),

                "connections":
                    connection_count,

                "ip_limit":
                    link.get(
                        "ip_limit",
                        0,
                    ),

                "speed_limit_bytes":
                    link.get(
                        "speed_limit_bytes",
                        0,
                    ),

                "connection_limit":
                    link.get(
                        "connection_limit",
                        0,
                    ),
            }
        )

    total_used = sum(
        item["used_bytes"]
        for item in links_out
    )

    return {
        "locked": False,

        "name":
            sub["name"],

        "desc":
            sub.get(
                "desc",
                "",
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "support":
            SUPPORT_USERNAME,

        "links":
            links_out,
    }




@app.post("/api/mix-sub")
async def mix_subscription(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    ids = body.get("link_ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        raise HTTPException(status_code=400, detail="حداقل ۲ کانفیگ انتخاب کنید")
    if len(ids) > 40:
        raise HTTPException(status_code=400, detail="حداکثر ۴۰ کانفیگ")
    host = get_host(request)
    lines = []
    used_names = set()
    total_used = 0
    total_limit = 0
    labels = []
    async with LINKS_LOCK:
        for lid in ids:
            link = LINKS.get(lid)
            if not link or not is_link_allowed(link):
                continue
            labels.append(str(link.get("label") or lid[:8]))
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            name = project_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(
                lid, host, remark=name,
                protocol=link.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=link.get("alpn"),
                port=link.get("port", DEFAULT_PORT),
            ))
    if not lines:
        raise HTTPException(status_code=400, detail="هیچ کانفیگ معتبری انتخاب نشده")
    # stats first line
    vol = f"{fmt_bytes(total_used)}/{fmt_bytes(total_limit)}" if total_limit > 0 else f"{fmt_bytes(total_used)}/∞"
    mix_label = f"{APP_NAME}-Mix-{random_config_name()[:6]}"
    stats = f"{mix_label} | {vol} | {len(lines)} configs"
    first = generate_vless_link(ids[0], "127.0.0.1", remark=stats, protocol="vless-ws")
    content = base64.b64encode(("\n".join([first] + lines)).encode()).decode()
    # store as a sub group for reuse
    sub_id, sub = await create_sub_group(name=mix_label, desc="مخلوط‌سازی کانفیگ‌ها")
    async with SUBS_LOCK:
        if sub_id in SUBS:
            SUBS[sub_id]["link_ids"] = list(ids)
    await save_state()
    return {
        "ok": True,
        "sub_url": f"https://{host}/sub-group/{sub['uuid_key']}",
        "name": mix_label,
        "count": len(lines),
        "content_preview": stats,
    }


@app.get("/api/categories")
async def list_categories(_=Depends(require_auth)):
    items = [{**cat, "id": cid} for cid, cat in CATEGORIES.items()]
    items.sort(key=lambda x: int(x.get("number", 0)))
    return {"categories": items}

@app.post("/api/categories")
async def create_category(request: Request, _=Depends(require_auth)):
    if len(CATEGORIES) >= 50:
        raise HTTPException(status_code=400, detail="حداکثر ۵۰ گروه")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    name = str(body.get("name") or "دسته جدید").strip()[:40]
    used = {int(x.get("number", 0)) for x in CATEGORIES.values()}
    num = 0
    while num in used:
        num += 1
    cid = str(num)
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    speed_value = safe_float(body.get("speed_limit_value", 0))
    speed_bytes = 0 if speed_value <= 0 else parse_speed_to_bytes(speed_value, "MBIT")
    raw_clean = body.get("clean_ips") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    record = {
        "id": cid, "name": name, "number": num,
        "limit_bytes": limit_bytes,
        "expires_days": safe_int(body.get("expires_days", 0), minimum=0),
        "connection_limit": safe_int(body.get("connection_limit", 0), minimum=0),
        "speed_limit_bytes": speed_bytes,
        "ip_limit": safe_int(body.get("ip_limit", 0), minimum=0),
        "clean_ips": clean_ips,
        "random_name": bool(body.get("random_name", False)),
        "single_user": bool(body.get("single_user", False)),
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES[cid] = record
    await save_state()
    return {"ok": True, **record}


@app.patch("/api/categories/{cid}")
async def update_category(cid: str, request: Request, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    cat = CATEGORIES[cid]
    if "name" in body:
        cat["name"] = str(body.get("name") or cat["name"]).strip()[:40]
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        unit = str(body.get("limit_unit") or "GB").upper()
        cat["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, unit)
    if "expires_days" in body:
        cat["expires_days"] = safe_int(body.get("expires_days", 0), minimum=0)
    if "connection_limit" in body:
        cat["connection_limit"] = safe_int(body.get("connection_limit", 0), minimum=0)
    if "speed_limit_value" in body:
        sv = safe_float(body.get("speed_limit_value", 0))
        cat["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, "MBIT")
    if "ip_limit" in body:
        cat["ip_limit"] = safe_int(body.get("ip_limit", 0), minimum=0)
    if "clean_ips" in body:
        raw = body.get("clean_ips") or ""
        if isinstance(raw, list):
            cat["clean_ips"] = [str(x).strip() for x in raw if str(x).strip()]
        else:
            cat["clean_ips"] = [x.strip() for x in str(raw).replace(",", "\n").splitlines() if x.strip()]
    if "random_name" in body:
        cat["random_name"] = bool(body.get("random_name"))
    if "single_user" in body:
        cat["single_user"] = bool(body.get("single_user"))
    await save_state()
    return {"ok": True, **cat}

@app.delete("/api/categories/{cid}")
async def delete_category(cid: str, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    del CATEGORIES[cid]
    for link in LINKS.values():
        if str(link.get("category_id")) == cid:
            link["category_id"] = "0"
    await save_state()
    return {"ok": True}

# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(connections),

        "total_traffic_mb":
            round(
                stats[
                    "total_bytes"
                ]
                / (
                    1024 ** 2
                ),
                2,
            ),

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "uptime":
            uptime(),

        "timestamp":
            datetime.now().isoformat(),

        "hourly":
            dict(
                hourly_traffic
            ),

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(snapshot),

        "active_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_expired(
                    link
                )
            ),

        "subs_count":
            len(SUBS),
    }


@app.get("/api/activity")
async def get_activity(
    _=Depends(require_auth),
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# CONNECTIONS
# ============================================================

@app.get("/api/connections")
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    grouped = {}

    for connection in connections.values():

        ip = connection.get(
            "ip",
            "نامشخص",
        )

        link = snapshot.get(
            connection.get(
                "uuid"
            )
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "نامشخص"
        )

        group = grouped.get(ip)

        if group is None:

            group = {
                "ip":
                    ip,

                "sessions":
                    0,

                "bytes":
                    0,

                "labels":
                    set(),

                "transports":
                    set(),

                "first_connected_at":
                    connection.get(
                        "connected_at"
                    ),

                "last_connected_at":
                    connection.get(
                        "connected_at"
                    ),
            }

            grouped[ip] = group

        group["sessions"] += 1

        group["bytes"] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )

        group["labels"].add(
            label
        )

        group["transports"].add(
            connection.get(
                "transport",
                DEFAULT_PROTOCOL,
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip":
                    group["ip"],

                "sessions":
                    group["sessions"],

                "labels":
                    sorted(
                        group["labels"]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group["labels"]
                            )
                        )
                        if group["labels"]
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group["transports"]
                    ),

                "bytes":
                    group["bytes"],

                "bytes_fmt":
                    fmt_bytes(
                        group["bytes"]
                    ),

                "connected_at":
                    group[
                        "first_connected_at"
                    ],

                "last_connected_at":
                    group[
                        "last_connected_at"
                    ],
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "last_connected_at"
            )
            or "",
        reverse=True,
    )

    return {
        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

# ============================================================
# IMPORTANT:
# DO NOT REPLACE THIS VLESS CORE.
# ============================================================

try:

    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel,
    )

    logger.info(
        "VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# XHTTP
# ============================================================

try:

    from xhttp_siz10 import (
        router as xhttp_router
    )

    app.include_router(
        xhttp_router
    )

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )



# ============================================================

@app.get("/api/me")
async def api_me_info(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    return {
        "ok": True,
        "role": meta.get("role"),
        "username": meta.get("username"),
        "permissions": meta.get("permissions") or {p: True for p in ALL_PERMS},
        "uptime": uptime(),
    }


@app.get("/api/admins")
async def api_admins_list(token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    out = []
    for aid, a in ADMIN_ACCOUNTS.items():
        out.append({
            "id": aid,
            "username": a.get("username"),
            "label": a.get("label"),
            "limit_bytes": int(a.get("limit_bytes") or 0),
            "used_bytes": int(a.get("used_bytes") or 0),
            "expires_at": a.get("expires_at"),
            "active": bool(a.get("active", True)),
            "blocked": bool(a.get("blocked")),
            "permissions": a.get("permissions") or {},
            "created_at": a.get("created_at"),
            "valid": admin_is_valid(a),
        })
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"admins": out}


@app.post("/api/admins")
async def api_admins_create(request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    username = str(body.get("username") or "").strip().lower()
    password = str(body.get("password") or "")
    repeat = str(body.get("repeat_password") or body.get("confirm") or "")
    if not username or len(username) < 3:
        raise HTTPException(400, detail="نام کاربری حداقل ۳ کاراکتر")
    if not username.isalnum():
        raise HTTPException(400, detail="نام کاربری فقط حروف و عدد انگلیسی")
    if username in ("owner", "admin", "root"):
        raise HTTPException(400, detail="این نام کاربری رزرو شده است")
    if find_admin_by_username(username)[0]:
        raise HTTPException(400, detail="نام کاربری تکراری است")
    if len(password) < 6:
        raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
    if password != repeat:
        raise HTTPException(400, detail="تکرار رمز یکسان نیست")
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    days = safe_int(body.get("expires_days", 0), minimum=0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    perms_in = body.get("permissions") or {}
    permissions = {p: bool(perms_in.get(p, False)) for p in ALL_PERMS}
    rec = default_admin_record(username, password, limit_bytes=limit_bytes, expires_at=expires_at, permissions=permissions, label=body.get("label") or username)
    ADMIN_ACCOUNTS[rec["id"]] = rec
    await save_state()
    log_activity("admin", f"اکانت ادمین «{username}» ساخته شد", "ok")
    return {"ok": True, "id": rec["id"], "username": username}


@app.patch("/api/admins/{aid}")
async def api_admins_patch(aid: str, request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    if aid not in ADMIN_ACCOUNTS:
        raise HTTPException(404, detail="یافت نشد")
    body = await request.json()
    a = ADMIN_ACCOUNTS[aid]
    if "blocked" in body:
        a["blocked"] = bool(body["blocked"])
    if "active" in body:
        a["active"] = bool(body["active"])
    if "label" in body:
        a["label"] = str(body["label"])[:40]
    if "permissions" in body and isinstance(body["permissions"], dict):
        a["permissions"] = {p: bool(body["permissions"].get(p, False)) for p in ALL_PERMS}
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        lu = str(body.get("limit_unit") or "GB").upper()
        a["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    if "expires_days" in body:
        days = safe_int(body.get("expires_days", 0), minimum=0)
        a["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    if body.get("password"):
        pw = str(body["password"])
        if len(pw) < 6:
            raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
        a["password_hash"] = hash_password(pw)
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» ویرایش شد", "ok")
    return {"ok": True}


@app.delete("/api/admins/{aid}")
async def api_admins_delete(aid: str, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    a = ADMIN_ACCOUNTS.pop(aid, None)
    if not a:
        raise HTTPException(404, detail="یافت نشد")
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» حذف شد", "warn")
    return {"ok": True}


NEWS_FILE = Path(__file__).resolve().parent / "news.json"


@app.get("/api/news")
async def api_news(token=Depends(require_auth)):
    try:
        if NEWS_FILE.exists():
            data = json.loads(NEWS_FILE.read_text(encoding="utf-8"))
        else:
            data = {"enabled": False, "title": "", "message": "", "updated_at": ""}
        return {"ok": True, **data}
    except Exception as e:
        return {"ok": False, "enabled": False, "title": "", "message": str(e), "updated_at": ""}




# ============================================================
# BACKUP / RESTORE
# ============================================================


@app.get("/api/security/status")
async def security_status(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    now = time.time()
    locked = []
    for ip, until in list(LOGIN_LOCKED_UNTIL.items()):
        if until > now:
            locked.append({"ip": ip, "remaining_sec": int(until - now)})
    return {
        "ok": True,
        "max_attempts": LOGIN_MAX_ATTEMPTS,
        "window_seconds": LOGIN_WINDOW_SECONDS,
        "lockout_seconds": LOGIN_LOCKOUT_SECONDS,
        "locked_ips": locked,
        "tracked_ips": len(LOGIN_FAILURES),
    }


@app.post("/api/security/unlock")
async def security_unlock(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip = str((body or {}).get("ip") or "").strip()
    if ip:
        LOGIN_FAILURES.pop(ip, None)
        LOGIN_LOCKED_UNTIL.pop(ip, None)
    else:
        LOGIN_FAILURES.clear()
        LOGIN_LOCKED_UNTIL.clear()
    log_activity("auth", f"رفع مسدودی brute-force ({ip or 'all'})", "ok")
    return {"ok": True}


@app.get("/api/backup/users")
async def backup_users(token=Depends(require_auth)):
    meta = get_session_meta(token)
    # owner always; admin needs settings perm
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    payload = {
        "type": "pxpanel_users_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "links": dict(LINKS),
        "subs": dict(SUBS),
        "categories": dict(CATEGORIES),
        "admin_accounts": dict(ADMIN_ACCOUNTS),
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="pxpanel-users-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.get("/api/backup/bot")
async def backup_bot(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    data = {}
    try:
        if TG_FILE.exists():
            data = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    payload = {
        "type": "pxpanel_bot_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "telegram": data,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="pxpanel-bot-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.post("/api/restore/users")
async def restore_users(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    if not isinstance(body, dict):
        raise HTTPException(400, detail="فرمت نامعتبر")
    # accept either wrapper or raw state
    links = body.get("links")
    if links is None and body.get("type") == "pxpanel_users_backup":
        raise HTTPException(400, detail="لینک‌ها در بک‌آپ نیست")
    if links is None:
        raise HTTPException(400, detail="فایل بک‌آپ کاربران نیست")
    if not isinstance(links, dict):
        raise HTTPException(400, detail="links نامعتبر")
    mode = str(body.get("mode") or "merge").lower()  # merge | replace
    async with LINKS_LOCK:
        if mode == "replace":
            LINKS.clear()
            SUBS.clear()
            CATEGORIES.clear()
            ADMIN_ACCOUNTS.clear()
        LINKS.update(links)
        if isinstance(body.get("subs"), dict):
            SUBS.update(body["subs"])
        if isinstance(body.get("categories"), dict):
            CATEGORIES.update(body["categories"])
        if isinstance(body.get("admin_accounts"), dict):
            ADMIN_ACCOUNTS.update(body["admin_accounts"])
        for uid, link in list(LINKS.items()):
            if not isinstance(link, dict):
                LINKS.pop(uid, None)
                continue
            link.setdefault("protocol", DEFAULT_PROTOCOL)
            link.setdefault("fingerprint", DEFAULT_FINGERPRINT)
            link.setdefault("used_bytes", 0)
            link.setdefault("active", True)
            link.setdefault("config_count", 1)
    await save_state()
    log_activity("backup", f"بازیابی کاربران ({mode}) — {len(links)} کانفیگ", "ok")
    return {"ok": True, "links": len(LINKS), "subs": len(SUBS), "mode": mode}


@app.post("/api/restore/bot")
async def restore_bot(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    tg = body.get("telegram") if isinstance(body, dict) else None
    if tg is None and isinstance(body, dict) and (body.get("token") or body.get("admin_ids") is not None):
        tg = body
    if not isinstance(tg, dict):
        raise HTTPException(400, detail="فایل بک‌آپ ربات نیست")
    # merge with existing
    current = {}
    try:
        if TG_FILE.exists():
            current = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        current = {}
    current.update({k: v for k, v in tg.items() if v is not None})
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    # try activate
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(current.get("token") or "", current.get("admin_ids") or "")
        host = get_host(request)
        if current.get("webhook") and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            await setup_webhook(wh)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")
            await start_bot(mode="polling")
    except Exception as exc:
        logger.warning("restore bot activate: %s", exc)
        log_activity("backup", f"بک‌آپ ربات ذخیره شد (فعال‌سازی: {exc})", "warn")
        return {"ok": True, "warning": str(exc)}
    log_activity("backup", "بازیابی تنظیمات ربات انجام شد", "ok")
    return {"ok": True, "message": "ربات بازیابی و فعال شد"}



# TELEGRAM SETTINGS API
# ============================================================

def load_tg_settings():
    try:
        if TG_FILE.exists():
            return json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {
        "token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        "admin_ids": os.environ.get("TELEGRAM_ADMIN_IDS", "").strip(),
        "webhook": False,
        "enabled": False,
    }


def save_tg_settings(data: dict):
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


@app.get("/api/telegram/settings")
async def api_tg_get(_=Depends(require_auth)):
    s = load_tg_settings()
    token = s.get("token") or ""
    masked = (token[:8] + "…" + token[-4:]) if len(token) > 14 else ("••••" if token else "")
    return {
        "token_masked": masked,
        "has_token": bool(token),
        "admin_ids": s.get("admin_ids") or "",
        "webhook": bool(s.get("webhook")),
        "enabled": bool(s.get("enabled")),
    }


@app.post("/api/telegram/settings")
async def api_tg_save(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="invalid json")
    s = load_tg_settings()
    token = str(body.get("token") or "").strip()
    admin_ids = str(body.get("admin_ids") or "").strip()
    use_webhook = bool(body.get("webhook", True))
    if token:
        s["token"] = token
    if admin_ids is not None:
        s["admin_ids"] = admin_ids
    s["webhook"] = use_webhook
    s["enabled"] = True
    save_tg_settings(s)
    # apply runtime
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(s.get("token") or "", s.get("admin_ids") or "")
        host = get_host(request)
        if use_webhook and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            ok = await setup_webhook(wh)
            s["webhook_url"] = wh
            s["webhook_ok"] = bool(ok)
            save_tg_settings(s)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")  # delete webhook -> polling
            await start_bot(mode="polling")
        log_activity("telegram", "ربات تلگرام پیکربندی و فعال شد", "ok")
        return {"ok": True, "webhook": use_webhook, "message": "ربات فعال شد"}
    except Exception as exc:
        logger.warning("telegram activate error: %s", exc)
        return {"ok": True, "warning": str(exc), "message": "تنظیمات ذخیره شد"}


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    try:
        from telegram_bot import process_update
        data = await request.json()
        await process_update(data)
    except Exception as exc:
        logger.warning("webhook error: %s", exc)
    return {"ok": True}


# ============================================================
# TELEGRAM
# ============================================================

try:

    from telegram_bot import (
        start_bot as _tg_start_bot,
        stop_bot as _tg_stop_bot,
    )

except Exception:

    async def _tg_start_bot():
        return None

    async def _tg_stop_bot():
        return None


@app.on_event("startup")
async def start_optional_telegram():

    try:

        await _tg_start_bot()

        logger.info(
            "Telegram module initialized."
        )

    except Exception as exc:

        logger.warning(
            "Telegram bot disabled/error: %s",
            exc,
        )


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{target_url:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
)
async def http_proxy(
    target_url: str,
    request: Request,
):

    if not target_url.startswith("http"):
        target_url = (
            "https://"
            + target_url
        )

    if http_client is None:
        raise HTTPException(
            status_code=503,
            detail="HTTP client not ready",
        )

    try:

        body = await request.body()

        headers = {
            key: value
            for key, value
            in request.headers.items()
            if (
                key.lower()
                not in _HOP
            )
            and (
                key.lower()
                != "host"
            )
        }

        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        stats["total_bytes"] += len(
            response.content
        )

        stats["total_requests"] += 1

        hourly_traffic[
            now_ir().strftime(
                "%H:00"
            )
        ] += len(
            response.content
        )

        output_headers = {
            key: value
            for key, value
            in response.headers.items()
            if key.lower() not in _HOP
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
        )

        logger.exception(
            "Proxy error: %s",
            target_url,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Proxy error: "
                f"{exc}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl" id="htmlRoot">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>پنل مدیریت</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06060b;--bg2:#0b0b12;--bg3:#12121c;--card:rgba(18,18,28,.92);--card-b:rgba(255,255,255,.08);
  --accent:#3b82f6;--accent2:#60a5fa;--purple:#8b5cf6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;
  --t1:#f8fafc;--t2:rgba(248,250,252,.72);--t3:rgba(248,250,252,.42);
  --sb:252px;--sb-c:74px;--radius:18px;--shadow:0 12px 40px rgba(0,0,0,.45);
  --input-bg:rgba(0,0,0,.4);--hover:rgba(59,130,246,.12);
  --glow:0 0 40px rgba(59,130,246,.12);--glass:blur(16px);
}
html.light{
  --bg:#eef1f8;--bg2:#ffffff;--bg3:#f1f4fa;--card:#ffffff;--card-b:rgba(15,23,42,.09);
  --accent:#2563eb;--accent2:#3b82f6;--purple:#7c3aed;--green:#16a34a;--red:#dc2626;--amber:#d97706;
  --t1:#0f172a;--t2:#475569;--t3:#94a3b8;
  --shadow:0 10px 32px rgba(15,23,42,.08);
  --input-bg:#f8fafc;--hover:rgba(37,99,235,.08);
  --glow:0 0 32px rgba(37,99,235,.08);--glass:blur(12px);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--t1);display:flex;min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(59,130,246,.14), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(139,92,246,.10), transparent 45%);
}
html.light body::before{
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(37,99,235,.08), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(124,58,237,.06), transparent 45%);
}
.sidebar,.main,.mob-bar,.modal-bg,.toast{position:relative;z-index:1}
.sidebar{z-index:300}.mob-bar{z-index:250}.modal-bg{z-index:500}.toast{z-index:999}
body.en{font-family:'Inter',system-ui,sans-serif}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--t3);border-radius:99px}

.sidebar{position:fixed;right:0;top:0;bottom:0;width:var(--sb);background:var(--bg2);border-left:1px solid var(--card-b);display:flex;flex-direction:column;z-index:300;transition:width .28s cubic-bezier(.4,0,.2,1),transform .28s,background .3s;box-shadow:var(--shadow);backdrop-filter:var(--glass)}
.sidebar.collapsed{width:var(--sb-c)}
.sb-toggle{position:absolute;left:-15px;top:50%;transform:translateY(-50%);width:30px;height:30px;border-radius:8px;background:var(--accent);border:2px solid var(--bg);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:310;box-shadow:0 4px 14px rgba(37,99,235,.4);transition:.2s}
.sb-toggle:hover{filter:brightness(1.1);transform:translateY(-50%) scale(1.05)}
.sb-toggle svg{width:14px;height:14px;transition:transform .28s}
.sidebar.collapsed .sb-toggle svg{transform:rotate(180deg)}
.sb-logo{display:flex;align-items:center;justify-content:center;padding:18px 14px;border-bottom:1px solid var(--card-b)}
.sb-logo-icon{position:relative;width:54px;height:54px;border-radius:16px;display:grid;place-items:center;flex-shrink:0;font-size:0;font-weight:900;color:#fff;isolation:isolate;transform:perspective(260px) rotateX(7deg) rotateY(-8deg);background:linear-gradient(145deg,#0ea5e9 0%,#2563eb 48%,#7c3aed 100%);border:1px solid rgba(255,255,255,.22);box-shadow:0 16px 30px rgba(37,99,235,.35),inset 0 1px rgba(255,255,255,.32);animation:onexLogoFloat 3.2s ease-in-out infinite}
.sb-logo-icon:before{content:'';position:absolute;inset:5px;border-radius:12px;background:linear-gradient(145deg,rgba(255,255,255,.28),rgba(255,255,255,.03) 45%,rgba(0,0,0,.18));border:1px solid rgba(255,255,255,.16);box-shadow:inset 0 -8px 16px rgba(0,0,0,.14),0 0 22px rgba(32,200,255,.18);z-index:-1}
.sb-logo-icon:after{content:'N';position:absolute;inset:0;display:grid;place-items:center;font:900 25px/1 Inter,system-ui,sans-serif;color:#fff;letter-spacing:-.08em;text-shadow:3px 3px 0 rgba(29,78,216,.95),6px 6px 0 rgba(30,41,59,.55),0 0 18px rgba(255,255,255,.38);transform:translateZ(18px);animation:onexLogoGlow 2.8s ease-in-out infinite}
.sb-logo-text,.sb-logo-name,.sb-logo-ver{display:none!important}
.sidebar.collapsed .sb-logo{justify-content:center;padding:14px 8px}
.sidebar.collapsed .sb-logo-icon{margin:0 auto}
@keyframes onexLogoFloat{0%,100%{transform:perspective(260px) rotateX(7deg) rotateY(-8deg) translateY(0)}50%{transform:perspective(260px) rotateX(10deg) rotateY(-13deg) translateY(-4px)}}
@keyframes onexLogoGlow{0%,100%{filter:brightness(1);text-shadow:3px 3px 0 rgba(29,78,216,.95),6px 6px 0 rgba(30,41,59,.55),0 0 18px rgba(255,255,255,.38)}50%{filter:brightness(1.18);text-shadow:4px 4px 0 rgba(29,78,216,.95),7px 7px 0 rgba(30,41,59,.5),0 0 26px rgba(32,200,255,.75)}}
.sidebar.collapsed .sb-logo-text,
.sidebar.collapsed .nav-label,
.sidebar.collapsed .nav-sec,
.sidebar.collapsed .sb-foot span{display:none!important}
.sidebar.collapsed .sb-logo{justify-content:center;padding:16px 8px}
.sidebar.collapsed .sb-logo-icon{margin:0 auto}
.nav{flex:1;overflow-y:auto;padding:10px 0}
.nav-sec{padding:14px 18px 6px;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);font-weight:700}
.nav-item{display:flex;align-items:center;gap:11px;padding:11px 16px;margin:2px 10px;border-radius:12px;color:var(--t3);cursor:pointer;transition:.15s;border:none;background:transparent;width:calc(100% - 20px);font-family:inherit;font-size:13px;font-weight:500}
.nav-item svg{width:18px;height:18px;min-width:18px;min-height:18px;flex-shrink:0;display:block}
.nav-item:hover{background:var(--hover);color:var(--t2)}
.nav-item.on{background:var(--hover);color:var(--accent2);font-weight:700;box-shadow:inset -3px 0 0 var(--accent)}
.sidebar.collapsed .nav-item{justify-content:center;align-items:center;padding:12px 0;margin:3px 10px;width:calc(100% - 20px);gap:0}
.sidebar.collapsed .nav-item svg{margin:0 auto}
.sidebar.collapsed .nav-item.on{box-shadow:none}
.sidebar.collapsed .sb-foot button,.sidebar.collapsed .sb-foot a.btn{padding:10px 0;gap:0}
.sidebar.collapsed .sb-foot button svg,.sidebar.collapsed .sb-foot a.btn svg{margin:0 auto;display:block}
.sb-foot{padding:12px;border-top:1px solid var(--card-b);display:flex;flex-direction:column;gap:7px}
.sb-foot button,.sb-foot a.btn{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;width:100%;text-decoration:none;font-weight:600;transition:.15s}
.sb-foot button:hover,.sb-foot a.btn:hover{background:var(--hover);color:var(--t1)}
.sb-foot a.danger{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:var(--red)}

.main{margin-right:var(--sb);flex:1;min-width:0;padding:28px 24px 60px;transition:margin .28s}
.main.expanded{margin-right:var(--sb-c)}
.page{display:none;animation:fadeIn .25s ease}
.page.on{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.page-title{font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px;letter-spacing:-.02em}
.page-title svg{width:22px;height:22px;color:var(--accent2)}
.page-sub{font-size:12px;color:var(--t3);margin-top:5px}

.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.metric{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);transition:.25s;backdrop-filter:var(--glass)}
.metric:hover{border-color:rgba(59,130,246,.25)}
.metric-label{font-size:11px;color:var(--t3);margin-bottom:8px;display:flex;align-items:center;gap:6px;font-weight:600}
.metric-val{font-size:24px;font-weight:800;letter-spacing:-.03em}
.card{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:20px;margin-bottom:14px;box-shadow:var(--shadow);backdrop-filter:var(--glass);transition:border-color .2s,box-shadow .2s}
.card-title{font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title svg{width:16px;height:16px;color:var(--accent2)}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.action-card{cursor:pointer;transition:.2s;border:1px solid var(--card-b)}
.action-card:hover{border-color:rgba(59,130,246,.4);transform:translateY(-2px);box-shadow:0 12px 28px rgba(59,130,246,.12)}
.action-card.purple:hover{border-color:rgba(139,92,246,.45)}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 16px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;font-weight:600;transition:.15s}
.btn:hover{color:var(--t1);border-color:var(--accent)}
.btn-p{background:linear-gradient(135deg,#3b82f6,#6366f1);border:none;color:#fff;box-shadow:0 6px 20px rgba(59,130,246,.35)}
.btn-p:hover{filter:brightness(1.08);color:#fff}
.btn-d{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.25);color:var(--red)}
.btn-sm{padding:7px 11px;font-size:11px;border-radius:9px}
.btn svg{width:15px;height:15px}

.table-wrap{overflow-x:auto;border-radius:14px;border:1px solid var(--card-b)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:right;padding:12px 14px;background:var(--bg3);color:var(--t3);font-weight:700;white-space:nowrap}
td{padding:12px 14px;border-top:1px solid var(--card-b);vertical-align:middle}
tr:hover td{background:var(--hover)}
.ops{display:flex;gap:5px;flex-wrap:wrap;align-items:center}

.range-tabs{display:flex;gap:4px;background:var(--bg3);padding:4px;border-radius:12px;border:1px solid var(--card-b)}
.range-tab{padding:7px 13px;border-radius:9px;font-size:11px;font-weight:700;color:var(--t3);cursor:pointer;border:none;background:transparent;font-family:inherit;transition:.15s}
.range-tab.on{background:var(--accent);color:#fff;box-shadow:0 2px 8px rgba(37,99,235,.35)}

.field{margin-bottom:14px}
.field label{display:block;font-size:11px;color:var(--t3);margin-bottom:6px;font-weight:700}
.field input,.field select,.field textarea{width:100%;padding:11px 13px;border-radius:11px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:13px;outline:none;transition:.15s}
.field input:focus,.field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.support-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.support-tile{display:flex;align-items:center;gap:14px;padding:20px;background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);text-decoration:none;color:inherit;transition:.2s;box-shadow:var(--shadow)}
.support-tile:hover{border-color:rgba(59,130,246,.35);transform:translateY(-3px)}
.support-icon{width:48px;height:48px;border-radius:14px;background:var(--hover);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.support-icon svg{width:22px;height:22px;color:var(--accent2)}
.support-label{font-size:11px;color:var(--t3);font-weight:600}
.support-val{font-size:13px;font-weight:700;margin-top:3px}

.log-item{padding:12px 0;border-bottom:1px solid var(--card-b);font-size:12px;display:flex;gap:12px;align-items:flex-start}
.log-time{color:var(--t3);font-size:10px;white-space:nowrap;min-width:72px;font-weight:600}
.log-msg{color:var(--t2);flex:1;line-height:1.5}

.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);z-index:500;display:none;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--card-b);border-radius:20px;width:min(520px,100%);max-height:90vh;overflow-y:auto;padding:24px;box-shadow:0 24px 64px rgba(0,0,0,.4)}
.modal-title{font-size:17px;font-weight:800;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap}
.link-box{background:var(--input-bg);border:1px solid var(--card-b);border-radius:12px;padding:12px;font-size:11px;word-break:break-all;color:var(--t2);margin:8px 0 12px;font-family:ui-monospace,monospace;line-height:1.6;max-height:90px;overflow:auto}

.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(90px);background:var(--bg2);border:1px solid var(--card-b);color:var(--t1);padding:13px 22px;border-radius:14px;font-size:13px;font-weight:600;z-index:999;opacity:0;transition:.3s;pointer-events:none;box-shadow:var(--shadow)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

.switch{position:relative;display:inline-block;width:44px;height:26px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(148,163,184,.35);border-radius:26px;transition:.2s}
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}

.mob-bar{display:none;position:fixed;top:0;left:0;right:0;height:56px;background:var(--bg2);border-bottom:1px solid var(--card-b);z-index:250;align-items:center;justify-content:space-between;padding:0 16px;box-shadow:var(--shadow)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:290;display:none}
.overlay.show{display:block}



.spin{width:36px;height:36px;border:3px solid var(--card-b);border-top-color:var(--accent);border-radius:50%;margin:0 auto;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.conn-badge{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:20px;padding:0 7px;border-radius:8px;font-size:10px;font-weight:800}
.conn-badge.green{background:rgba(34,197,94,.18);color:#4ade80}
.conn-badge.gray{background:rgba(148,163,184,.15);color:#94a3b8}
.conn-badge.orange{background:rgba(245,158,11,.18);color:#fbbf24}
.conn-badge.red{background:rgba(239,68,68,.18);color:#f87171}
.spin{width:36px;height:36px;border:3px solid var(--card-b);border-top-color:var(--accent);border-radius:50%;margin:0 auto;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* =========================================================
   ONEX DASHBOARD REDESIGN
   ========================================================= */
.mob-brand{display:flex;align-items:center;gap:9px}
.mob-brand-mark{position:relative;width:38px;height:38px;border-radius:12px;display:grid;place-items:center;color:#fff;font-size:0;font-weight:900;isolation:isolate;background:linear-gradient(145deg,#0ea5e9,#2563eb 52%,#7c3aed);border:1px solid rgba(255,255,255,.22);box-shadow:0 10px 24px rgba(37,99,235,.35),inset 0 1px rgba(255,255,255,.28);transform:perspective(220px) rotateX(7deg) rotateY(-8deg);animation:onexLogoFloat 3.2s ease-in-out infinite}
.mob-brand-mark:before{content:'';position:absolute;inset:4px;border-radius:9px;background:linear-gradient(145deg,rgba(255,255,255,.25),rgba(255,255,255,.03) 50%,rgba(0,0,0,.18));z-index:-1}
.mob-brand-mark:after{content:'N';position:absolute;inset:0;display:grid;place-items:center;font:900 18px/1 Inter,system-ui,sans-serif;color:#fff;text-shadow:2px 2px 0 rgba(29,78,216,.95),4px 4px 0 rgba(30,41,59,.5),0 0 13px rgba(255,255,255,.35);transform:translateZ(12px)}
.onex-topbar{height:66px;display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px;padding:10px 14px 10px 16px;border:1px solid rgba(96,165,250,.14);border-radius:20px;background:linear-gradient(180deg,rgba(17,24,39,.82),rgba(8,12,23,.72));backdrop-filter:blur(18px);box-shadow:0 12px 35px rgba(0,0,0,.28),inset 0 1px rgba(255,255,255,.04)}
/* ONEX floating glass control dock */
.onex-control-dock{position:relative;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:-4px 0 18px;padding:9px;border:1px solid rgba(148,163,184,.16);border-radius:22px;background:linear-gradient(135deg,rgba(15,23,42,.72),rgba(9,13,25,.58));backdrop-filter:blur(22px) saturate(135%);-webkit-backdrop-filter:blur(22px) saturate(135%);box-shadow:0 18px 45px rgba(0,0,0,.22),inset 0 1px rgba(255,255,255,.07)}
.onex-control-dock:before{content:"";position:absolute;inset:0;border-radius:22px;background:linear-gradient(90deg,transparent,rgba(96,165,250,.08),transparent);background-size:220% 100%;animation:dockSweep 5s linear infinite;pointer-events:none}
.onex-3d-control{position:relative;min-height:62px;border:1px solid rgba(148,163,184,.18);border-radius:17px;background:linear-gradient(145deg,rgba(30,41,59,.88),rgba(15,23,42,.66));color:var(--t1);display:flex;align-items:center;justify-content:center;gap:10px;padding:10px 14px;cursor:pointer;font-family:inherit;font-size:12px;font-weight:800;overflow:hidden;transform:translateY(0) perspective(700px) rotateX(0deg);transition:transform .22s ease,box-shadow .22s ease,border-color .22s ease,background .22s ease;box-shadow:0 9px 0 rgba(2,6,23,.7),0 16px 25px rgba(0,0,0,.24),inset 0 1px rgba(255,255,255,.08)}
.onex-3d-control:after{content:"";position:absolute;top:-60%;left:-25%;width:45%;height:220%;transform:rotate(24deg);background:linear-gradient(90deg,transparent,rgba(255,255,255,.14),transparent);animation:controlShine 3.8s ease-in-out infinite}
.onex-3d-control:hover{transform:translateY(-4px) perspective(700px) rotateX(3deg);border-color:rgba(96,165,250,.45);box-shadow:0 13px 0 rgba(2,6,23,.7),0 22px 35px rgba(37,99,235,.16),inset 0 1px rgba(255,255,255,.1)}
.onex-3d-control:active{transform:translateY(2px) perspective(700px) rotateX(0deg);box-shadow:0 5px 0 rgba(2,6,23,.7),0 10px 18px rgba(0,0,0,.2)}
.onex-3d-control .control-icon{width:39px;height:39px;flex:0 0 39px;display:grid;place-items:center;border-radius:13px;background:linear-gradient(145deg,#3b82f6,#7c3aed);box-shadow:inset 2px 2px 4px rgba(255,255,255,.22),inset -3px -4px 7px rgba(0,0,0,.28),0 7px 18px rgba(59,130,246,.28);transform:translateZ(18px);animation:iconFloat 2.8s ease-in-out infinite}
.onex-3d-control:nth-child(2) .control-icon{background:linear-gradient(145deg,#06b6d4,#2563eb);box-shadow:inset 2px 2px 4px rgba(255,255,255,.22),inset -3px -4px 7px rgba(0,0,0,.28),0 7px 18px rgba(6,182,212,.24);animation-delay:.35s}
.onex-3d-control:nth-child(3) .control-icon{background:linear-gradient(145deg,#10b981,#059669);box-shadow:inset 2px 2px 4px rgba(255,255,255,.22),inset -3px -4px 7px rgba(0,0,0,.28),0 7px 18px rgba(16,185,129,.24);animation-delay:.7s}
.onex-3d-control svg{width:19px;height:19px;filter:drop-shadow(0 2px 2px rgba(0,0,0,.28))}
.onex-3d-control .control-copy{display:flex;flex-direction:column;align-items:flex-start;gap:3px;line-height:1.2}
.onex-3d-control .control-title{font-size:12px}.onex-3d-control .control-sub{font-size:9px;color:var(--t3);font-weight:600;letter-spacing:.3px}
@keyframes controlShine{0%,45%{left:-45%;opacity:0}55%{opacity:1}100%{left:120%;opacity:0}}
@keyframes iconFloat{0%,100%{transform:translateY(0) translateZ(18px) rotate(-1deg)}50%{transform:translateY(-3px) translateZ(18px) rotate(1deg)}}
@keyframes dockSweep{0%{background-position:200% 0}100%{background-position:-20% 0}}


.top-server{display:flex;align-items:center;gap:12px;min-width:0}.top-dot{width:10px;height:10px;border-radius:50%;background:#22c55e;box-shadow:0 0 14px #22c55e;animation:pulseDot 1.8s ease-in-out infinite}.top-server b{font-size:13px}.top-server small{color:var(--t3);font-size:11px}.top-sep{width:1px;height:24px;background:var(--card-b)}
.top-actions{display:flex;align-items:center;gap:8px}.top-chip{display:flex;align-items:center;gap:7px;padding:9px 12px;border:1px solid var(--card-b);border-radius:12px;background:rgba(255,255,255,.025);color:var(--t2);font-size:11px}.top-avatar{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,#3b82f6,#8b5cf6);font-weight:900;color:#fff;box-shadow:0 0 24px rgba(59,130,246,.3)}
.dashboard-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin:0 2px 18px}.hero-kicker{font-size:10px;letter-spacing:.2em;color:#60a5fa;font-weight:800;text-transform:uppercase}.hero-title{font-size:27px;font-weight:900;line-height:1.25;margin-top:6px}.hero-title span{color:#60a5fa;text-shadow:0 0 22px rgba(96,165,250,.35)}.hero-sub{margin-top:6px;color:var(--t3);font-size:12px}.hero-actions{display:flex;gap:8px;flex-wrap:wrap}
.onex-metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:16px}.onex-metric{position:relative;overflow:hidden;min-height:122px;padding:17px;border:1px solid rgba(96,165,250,.13);border-radius:20px;background:linear-gradient(145deg,rgba(15,25,45,.92),rgba(8,12,22,.92));box-shadow:0 12px 32px rgba(0,0,0,.28),inset 0 1px rgba(255,255,255,.035);transition:.25s}.onex-metric:hover{transform:translateY(-3px);border-color:rgba(96,165,250,.35);box-shadow:0 16px 40px rgba(37,99,235,.14)}.onex-metric:after{content:'';position:absolute;right:-40px;bottom:-55px;width:140px;height:140px;border-radius:50%;background:rgba(37,99,235,.14);filter:blur(18px)}.metric-icon{width:42px;height:42px;border-radius:14px;display:grid;place-items:center;background:rgba(37,99,235,.14);border:1px solid rgba(96,165,250,.24);color:#60a5fa;box-shadow:0 0 20px rgba(37,99,235,.15)}.metric-icon svg{width:21px;height:21px}.onex-metric .metric-label{margin:10px 0 3px}.onex-metric .metric-val{font-size:25px}.metric-trend{position:absolute;left:15px;bottom:16px;font-size:10px;color:#34d399;font-weight:800}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(260px,.72fr);gap:14px;align-items:stretch}.dashboard-grid-right{display:grid;grid-template-rows:auto 1fr;gap:14px}.onex-card{background:linear-gradient(145deg,rgba(14,20,34,.92),rgba(7,11,20,.92));border:1px solid rgba(96,165,250,.12);border-radius:20px;box-shadow:0 14px 38px rgba(0,0,0,.3),inset 0 1px rgba(255,255,255,.035);overflow:hidden}.onex-card-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 18px;border-bottom:1px solid rgba(255,255,255,.055)}.onex-card-title{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:800}.onex-card-title svg{color:#60a5fa}.onex-card-body{padding:16px 18px}
.chart-wrap{height:275px;padding:8px 12px 12px;position:relative}.traffic-svg{width:100%;height:100%;display:block}.chart-grid-line{stroke:rgba(148,163,184,.1);stroke-width:1}.chart-fill{fill:url(#trafficFill)}.chart-line{fill:none;stroke:#20c8ff;stroke-width:3;stroke-linecap:round;stroke-linejoin:round;filter:drop-shadow(0 0 7px rgba(32,200,255,.55))}.chart-dot{fill:#fff;stroke:#20c8ff;stroke-width:3;filter:drop-shadow(0 0 6px rgba(32,200,255,.75))}.chart-labels{display:flex;justify-content:space-between;padding:0 10px;color:var(--t3);font-size:9px}.chart-badge{position:absolute;top:18px;right:25%;padding:7px 10px;border:1px solid rgba(32,200,255,.25);background:rgba(5,12,25,.88);border-radius:10px;font-size:10px;color:#bcefff;box-shadow:0 0 18px rgba(32,200,255,.1)}
.range-mini{display:flex;gap:4px;background:rgba(255,255,255,.025);padding:3px;border-radius:10px}.range-mini button{border:0;background:transparent;color:var(--t3);font-family:inherit;font-size:9px;padding:6px 9px;border-radius:8px;cursor:pointer}.range-mini button.on{background:#2563eb;color:#fff;box-shadow:0 4px 12px rgba(37,99,235,.25)}
.health-list{display:grid;gap:14px}.health-row{display:grid;grid-template-columns:34px 1fr 42px;gap:10px;align-items:center}.health-icon{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:rgba(37,99,235,.1);color:#60a5fa}.health-name{font-size:11px;color:var(--t2);margin-bottom:5px}.health-pct{font-size:10px;color:var(--t2);text-align:left;direction:ltr}.health-track{height:7px;border-radius:99px;background:rgba(148,163,184,.1);overflow:hidden}.health-fill{height:100%;width:var(--w);border-radius:99px;background:linear-gradient(90deg,#2563eb,#22d3ee);box-shadow:0 0 12px rgba(34,211,238,.35);animation:healthIn .9s ease both}.xray-state{display:flex;align-items:center;justify-content:space-between;padding:11px 12px;border-radius:13px;background:rgba(34,197,94,.07);border:1px solid rgba(34,197,94,.16);font-size:11px;margin-top:4px}.xray-state span:last-child{color:#34d399;font-weight:800}.xray-dot{width:7px;height:7px;border-radius:50%;background:#22c55e;display:inline-block;box-shadow:0 0 9px #22c55e;margin-left:6px}
.telegram-card{position:relative;min-height:100%;display:flex;flex-direction:column;justify-content:space-between;padding:20px;overflow:hidden;background:radial-gradient(circle at 50% 20%,rgba(37,99,235,.24),transparent 35%),linear-gradient(145deg,rgba(10,23,48,.96),rgba(5,10,21,.96));border:1px solid rgba(59,130,246,.3);border-radius:20px;box-shadow:0 14px 38px rgba(0,0,0,.32),0 0 35px rgba(37,99,235,.08)}.tg-orbit{width:118px;height:118px;border:1px solid rgba(59,130,246,.5);border-radius:50%;margin:5px auto 12px;display:grid;place-items:center;position:relative;animation:orbitSpin 8s linear infinite}.tg-orbit:before,.tg-orbit:after{content:'';position:absolute;border:1px solid rgba(32,200,255,.3);border-radius:50%}.tg-orbit:before{inset:12px;transform:rotate(55deg) scaleX(1.45)}.tg-orbit:after{inset:24px;transform:rotate(-35deg) scaleX(1.55)}.tg-logo{width:66px;height:66px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#28a9ff,#1769ff);box-shadow:0 0 28px rgba(37,99,235,.6);animation:floatY 2.8s ease-in-out infinite}.tg-logo svg{width:34px;height:34px;color:#fff}.tg-title{text-align:center;font-size:13px;color:var(--t2)}.tg-handle{text-align:center;font-size:23px;font-weight:900;color:#20c8ff;margin-top:5px;text-shadow:0 0 18px rgba(32,200,255,.3);direction:ltr}.tg-desc{text-align:center;color:var(--t3);font-size:10px;margin-top:6px}.tg-btn{display:flex;align-items:center;justify-content:center;gap:7px;margin-top:18px;padding:11px;border-radius:13px;text-decoration:none;color:#fff;background:linear-gradient(135deg,#147cff,#3b5bff);box-shadow:0 8px 24px rgba(37,99,235,.3);font-size:11px;font-weight:800}.tg-btn:hover{filter:brightness(1.08)}
.quick-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.quick-item{display:flex;align-items:center;gap:10px;padding:13px;border-radius:15px;background:rgba(255,255,255,.025);border:1px solid var(--card-b);cursor:pointer;transition:.2s}.quick-item:hover{transform:translateY(-2px);border-color:rgba(96,165,250,.3);background:rgba(37,99,235,.07)}.quick-icon{width:38px;height:38px;border-radius:12px;display:grid;place-items:center;background:rgba(37,99,235,.13);color:#60a5fa}.quick-item:nth-child(2) .quick-icon{color:#34d399;background:rgba(34,197,94,.1)}.quick-item:nth-child(3) .quick-icon{color:#a78bfa;background:rgba(139,92,246,.11)}.quick-item:nth-child(4) .quick-icon{color:#22d3ee;background:rgba(34,211,238,.1)}.quick-name{font-size:11px;font-weight:800}.quick-desc{font-size:9px;color:var(--t3);margin-top:3px}
.recent-card{margin-top:14px}.recent-table{width:100%;border-collapse:collapse;font-size:10px}.recent-table th{font-size:9px;padding:10px 12px;background:rgba(255,255,255,.025);color:var(--t3)}.recent-table td{padding:10px 12px;border-top:1px solid rgba(255,255,255,.045);color:var(--t2)}.recent-status{display:inline-flex;align-items:center;gap:5px;color:#34d399}.recent-status i{width:6px;height:6px;border-radius:50%;background:#22c55e;box-shadow:0 0 7px #22c55e}.recent-actions{display:flex;gap:5px}.mini-action{width:27px;height:27px;border:1px solid var(--card-b);border-radius:8px;background:rgba(255,255,255,.025);color:var(--t2);display:grid;place-items:center;cursor:pointer}.mini-action:hover{color:#60a5fa;border-color:rgba(96,165,250,.3)}
.server-info{display:grid;gap:9px}.info-row{display:flex;align-items:center;justify-content:space-between;padding-bottom:9px;border-bottom:1px solid rgba(255,255,255,.045);font-size:10px}.info-row:last-child{border-bottom:0;padding-bottom:0}.info-row span:first-child{color:var(--t3)}.info-row span:last-child{color:var(--t2);font-weight:700}.onex-footer{display:flex;align-items:center;justify-content:space-between;margin-top:14px;padding:12px 4px;color:var(--t3);font-size:9px}.onex-footer b{color:#60a5fa}
@keyframes pulseDot{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(.72);opacity:.65}}@keyframes orbitSpin{to{transform:rotate(360deg)}}@keyframes floatY{0%,100%{transform:translateY(0)}50%{transform:translateY(-5px)}}@keyframes healthIn{from{width:0}}




   The mobile drawer is rebuilt independently from the legacy PX
   sidebar rules. No desktop collapse/width styles are reused.
   ========================================================= */

























/* ============================================================
   ONEX MOBILE FIT — DESKTOP VISUALS, PHONE-SAFE DIMENSIONS
   Same components, colors and visual language. Only dimensions,
   columns and spacing change so every element stays in the viewport.
   ============================================================ */
@media (max-width:768px){
  html,body{width:100%;max-width:100%;min-width:0;overflow-x:hidden}
  body{display:flex;min-height:100vh}

  /* Desktop sidebar kept on the right, proportionally reduced. */
  :root{--sb:128px;--sb-c:46px;--radius:14px}
  .sidebar{width:var(--sb);overflow:hidden}
  .sidebar.collapsed{width:var(--sb-c)}
  .sb-toggle{width:28px;height:28px;left:-14px;border-radius:8px}
  .sb-logo{padding:11px 8px}
  .sb-logo-icon{width:43px;height:43px;border-radius:13px}
  .sb-logo-icon:after{font-size:20px}
  .nav{padding:5px 0}
  .nav-sec{padding:9px 8px 4px;font-size:7px;letter-spacing:.06em}
  .nav-item{gap:5px;padding:8px 6px;margin:2px 5px;width:calc(100% - 10px);border-radius:9px;font-size:8px;line-height:1.35}
  .nav-item svg{width:16px;height:16px;min-width:16px;min-height:16px}
  .sb-foot{padding:7px;gap:5px}
  .sb-foot button,.sb-foot a.btn{padding:8px 4px;border-radius:9px;font-size:8px;gap:4px}
  .sb-foot svg{width:14px;height:14px}

  .main{width:auto;min-width:0;margin-right:var(--sb);padding:12px 9px 38px}
  .main.expanded{margin-right:var(--sb-c)}
  .mob-bar,.overlay{display:none!important}

  /* Top bar: no item is allowed to force the main column wider. */
  .onex-topbar{height:55px;margin-bottom:10px;padding:7px 8px;border-radius:13px;gap:5px;min-width:0}
  .top-server{gap:5px;min-width:0;overflow:hidden}.top-dot{width:7px;height:7px;flex:0 0 auto}
  .top-server b{font-size:9px;white-space:nowrap}.top-server small{font-size:6.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.top-sep{height:18px;flex:0 0 auto}
  .top-actions{gap:3px;flex:0 0 auto}.top-chip{padding:5px 6px;border-radius:8px;font-size:6.5px;gap:3px}.top-avatar{width:28px;height:28px;border-radius:8px;font-size:8px}

  .onex-control-dock{grid-template-columns:repeat(3,minmax(0,1fr));gap:5px;margin:0 0 10px;padding:5px;border-radius:13px;min-width:0}
  .onex-3d-control{min-width:0;min-height:52px;border-radius:10px;gap:3px;padding:6px 3px;overflow:hidden}
  .onex-3d-control .control-icon{width:25px;height:25px;flex:0 0 25px;border-radius:8px}
  .onex-3d-control svg{width:13px;height:13px}.onex-3d-control .control-copy{min-width:0}.onex-3d-control .control-title{font-size:7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.onex-3d-control .control-sub{font-size:5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

  .dashboard-hero{display:flex;align-items:flex-end;justify-content:space-between;gap:5px;margin:0 1px 10px;min-width:0}
  .dashboard-hero>div:first-child{min-width:0}.hero-kicker{font-size:7px;letter-spacing:.14em}.hero-title{font-size:18px;margin-top:3px;line-height:1.25}.hero-sub{font-size:7px;margin-top:3px;white-space:nowrap}.hero-actions{gap:4px;flex:0 0 auto}
  .hero-actions .btn{padding:6px 7px;font-size:7px;border-radius:8px;white-space:nowrap}.hero-actions .btn svg{width:11px;height:11px}

  /* Two columns preserve the desktop card style without crushing text. */
  .onex-metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-bottom:10px}
  .onex-metric{min-width:0;min-height:88px;padding:8px;border-radius:13px}
  .metric-icon{width:27px;height:27px;border-radius:9px}.metric-icon svg{width:14px;height:14px}
  .onex-metric .metric-label{margin:6px 0 2px;font-size:7px;line-height:1.35}.onex-metric .metric-val{font-size:15px;white-space:nowrap}.metric-trend{left:8px;bottom:7px;font-size:6px;white-space:nowrap}

  /* Same desktop dashboard cards, stacked only because the phone is narrow. */
  .dashboard-grid{grid-template-columns:minmax(0,1fr);gap:8px}
  .dashboard-grid-right{grid-template-rows:auto auto;gap:8px}
  .onex-card{min-width:0;border-radius:13px}.onex-card-head{gap:5px;padding:9px 10px}.onex-card-title{gap:5px;font-size:8px}.onex-card-body{padding:9px 10px}
  .chart-wrap{height:145px;padding:5px 6px 8px}.chart-labels{padding:0 5px;font-size:6px}.chart-badge{top:9px;padding:4px 5px;font-size:5.5px}.range-mini{gap:2px;padding:2px;border-radius:7px}.range-mini button{font-size:6px;padding:4px 6px;border-radius:6px}

  .health-list{gap:8px}.health-row{grid-template-columns:24px minmax(0,1fr) 28px;gap:6px}.health-icon{width:24px;height:24px;border-radius:8px}.health-icon svg{width:12px;height:12px}.health-name{font-size:7px;margin-bottom:3px}.health-pct{font-size:6.5px}.health-track{height:5px}.xray-state{padding:7px 8px;border-radius:8px;font-size:7px}
  .telegram-card{padding:10px;border-radius:13px}.tg-orbit{width:68px;height:68px;margin:3px auto 7px}.tg-logo{width:40px;height:40px}.tg-logo svg{width:21px;height:21px}.tg-title{font-size:8px}.tg-handle{font-size:14px}.tg-desc{font-size:6px}.tg-btn{margin-top:8px;padding:7px;border-radius:8px;font-size:7px}
  .quick-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px}.quick-item{gap:6px;padding:8px;border-radius:10px;min-width:0}.quick-icon{width:28px;height:28px;border-radius:8px;flex:0 0 28px}.quick-icon svg{width:14px;height:14px}.quick-name{font-size:7px}.quick-desc{font-size:6px;margin-top:1px}
  .recent-card{margin-top:8px}.recent-table{font-size:7px}.recent-table th{font-size:6px;padding:7px 6px}.recent-table td{padding:7px 6px}.mini-action{width:21px;height:21px;border-radius:6px}
  .server-info{gap:6px}.info-row{padding-bottom:6px;font-size:7px}.onex-footer{margin-top:8px;padding:7px 2px;font-size:6px}

  /* Other pages: same desktop components, safely resized. */
  .page-head{gap:7px;margin-bottom:10px}.page-title{font-size:14px;gap:5px}.page-title svg{width:16px;height:16px}.page-sub{font-size:7px;margin-top:3px}
  .metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-bottom:10px}.metric{padding:9px;border-radius:12px;min-width:0}.metric-label{font-size:7px;margin-bottom:4px}.metric-val{font-size:15px}
  .card{padding:10px;border-radius:12px;margin-bottom:8px}.card-title{font-size:8px;margin-bottom:8px}.card-title svg{width:13px;height:13px}.g2{grid-template-columns:1fr;gap:8px;margin-bottom:8px}
  .support-grid{grid-template-columns:1fr 1fr;gap:6px}.support-tile{gap:6px;padding:8px;border-radius:10px}.support-icon{width:29px;height:29px;border-radius:8px}.support-icon svg{width:14px;height:14px}.support-label{font-size:6.5px}.support-val{font-size:8px;margin-top:2px}
  .log-item{padding:7px 0;font-size:7px;gap:6px}.log-time{font-size:6px;min-width:44px}.btn{padding:7px 8px;border-radius:8px;font-size:7px}.btn-sm{padding:5px 6px;font-size:6.5px}.btn svg{width:11px;height:11px}
  .form-row{grid-template-columns:1fr;gap:0}.field{margin-bottom:8px}.field label{font-size:7px;margin-bottom:4px}.field input,.field select,.field textarea{padding:8px;border-radius:8px;font-size:11px;min-height:34px}
  .table-wrap{width:100%;max-width:100%;overflow-x:auto}table{font-size:7px;min-width:420px}th{padding:7px 6px}td{padding:7px 6px}.ops{gap:3px}.range-tab{padding:5px 6px;font-size:6.5px;border-radius:7px}
  .modal-bg{padding:8px}.modal{width:calc(100vw - 16px);max-width:460px;max-height:92vh;padding:12px;border-radius:13px}.modal-title{font-size:12px;margin-bottom:9px}.modal-actions{gap:5px;margin-top:9px}.link-box{padding:8px;font-size:7px;margin:6px 0 8px;max-height:70px}.toast{bottom:10px;padding:8px 11px;border-radius:9px;font-size:8px}
}

@media (max-width:520px){
  :root{--sb:120px;--sb-c:44px}
  .main{margin-right:var(--sb);padding-left:7px;padding-right:7px}
  .nav-item{font-size:7.5px;padding:8px 5px}
  .onex-topbar{height:52px;padding:6px 7px}.top-chip{display:none}.top-server small{max-width:65px}
  .onex-control-dock{gap:4px}.onex-3d-control{min-height:49px;padding:5px 3px}.onex-3d-control .control-icon{width:23px;height:23px;flex-basis:23px}.onex-3d-control .control-title{font-size:6.5px}.onex-3d-control .control-sub{font-size:4.5px}
  .hero-title{font-size:16px}.hero-kicker{font-size:6.5px}.hero-sub{font-size:6.5px}.hero-actions .btn{padding:5px 6px;font-size:6.5px}
  .onex-metric{min-height:84px;padding:7px}.onex-metric .metric-label{font-size:6.5px}.onex-metric .metric-val{font-size:14px}.metric-trend{font-size:5.5px}
}

@media (max-width:380px){
  :root{--sb:112px;--sb-c:42px}
  .main{padding-left:6px;padding-right:6px}
  .nav-item{font-size:7px}.onex-metrics{gap:5px}.onex-metric{min-height:80px;padding:6px}.onex-metric .metric-val{font-size:13px}
  .dashboard-hero{gap:3px}.hero-title{font-size:15px}.hero-actions .btn{padding:5px;font-size:6px}
}

/* ============================================================
   ONEX PHONE MODE — FULL WIDTH CONTENT + SLIDE-IN NAV DRAWER
   Keeps the exact panel/components; only phone layout changes.
   ============================================================ */
@media (max-width:768px){
  html,body{width:100%;min-width:0;overflow-x:hidden}
  body{display:block;min-height:100vh;padding-top:58px}

  .mob-bar{display:flex!important;position:fixed;top:0;left:0;right:0;height:58px;padding:0 12px;
    background:rgba(11,11,18,.96);border-bottom:1px solid var(--card-b);
    backdrop-filter:blur(16px);box-shadow:0 8px 30px rgba(0,0,0,.35);z-index:1000}
  .mob-menu-btn{width:42px;height:42px;border:1px solid var(--card-b);border-radius:12px;
    background:var(--bg3);color:var(--t1);display:flex;align-items:center;justify-content:center;cursor:pointer}
  .mob-menu-btn svg{width:22px;height:22px}
  .mob-brand{display:flex;align-items:center;gap:9px;margin-right:auto;margin-left:auto;min-width:0}
  .mob-brand-icon{width:36px;height:36px;border-radius:11px;display:grid;place-items:center;flex:0 0 36px;
    background:linear-gradient(145deg,#0ea5e9,#2563eb 50%,#7c3aed);font:900 18px Inter,sans-serif;color:#fff;
    box-shadow:0 7px 20px rgba(37,99,235,.35)}
  .mob-brand-text{min-width:0;line-height:1.05}
  .mob-brand-text b{display:block;font:700 12px Inter,sans-serif;white-space:nowrap}
  .mob-brand-text span{display:block;font-size:8px;color:var(--t3);margin-top:3px;white-space:nowrap}
  .mob-status{display:flex;align-items:center;gap:5px;font-size:8px;color:var(--t2);white-space:nowrap}
  .mob-status i{width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 9px #22c55e}

  .sidebar{position:fixed;top:0;right:0;bottom:0;width:min(84vw,320px)!important;
    max-width:320px;transform:translateX(105%);transition:transform .25s ease;width:min(84vw,320px);
    z-index:1200;box-shadow:-18px 0 50px rgba(0,0,0,.55);overflow-y:auto}
  .sidebar.mobile-open{transform:translateX(0)}
  .sidebar.collapsed{width:min(84vw,320px)!important}
  .sidebar .sb-toggle{display:none}
  .sidebar .sb-logo{padding:18px 14px}
  .sidebar .sb-logo-icon{width:54px;height:54px;border-radius:16px}
  .sidebar .sb-logo-icon:after{font-size:25px}
  .sidebar .nav-item{font-size:13px;padding:11px 16px;margin:2px 10px;width:calc(100% - 20px);gap:11px;border-radius:12px}
  .sidebar .nav-item svg{width:18px;height:18px;min-width:18px}
  .sidebar .nav-sec{padding:14px 18px 6px;font-size:9px}
  .sidebar .sb-foot{padding:12px}
  .sidebar .sb-foot button,.sidebar .sb-foot a.btn{font-size:12px;padding:10px}
  .sidebar .nav-label,.sidebar .sb-foot span,.sidebar .nav-sec,.sidebar .sb-logo-text{display:block!important}
  .sidebar.collapsed .nav-label,.sidebar.collapsed .sb-foot span,.sidebar.collapsed .nav-sec,.sidebar.collapsed .sb-logo-text{display:block!important}
  .overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.58);z-index:1100}
  .overlay.show{display:block!important}

  .main,.main.expanded{width:100%;max-width:100%;min-width:0;margin:0!important;padding:12px 12px 40px}
  .page{width:100%;max-width:100%;min-width:0;overflow:visible}
  .page-head{width:100%;max-width:100%;align-items:flex-start}
  .page-title{font-size:21px;line-height:1.35}
  .page-sub{font-size:11px;line-height:1.7;max-width:100%}

  .onex-topbar{width:100%;max-width:100%;height:auto;min-height:64px;padding:10px 11px;margin-bottom:10px}
  .top-server{min-width:0;flex:1}
  .top-server b{font-size:12px}
  .top-server small{font-size:8px;max-width:120px}
  .top-actions{flex:0 0 auto}
  .top-chip{font-size:8px;padding:6px 7px}
  .top-avatar{width:34px;height:34px;font-size:10px}

  .onex-control-dock{width:100%;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px;padding:7px;margin-bottom:14px}
  .onex-3d-control{min-height:68px;padding:8px 6px;gap:6px}
  .onex-3d-control .control-icon{width:31px;height:31px;flex-basis:31px}
  .onex-3d-control svg{width:16px;height:16px}
  .onex-3d-control .control-title{font-size:9px}
  .onex-3d-control .control-sub{font-size:6px}

  .dashboard-hero{width:100%;margin-bottom:14px;gap:10px;align-items:flex-end}
  .hero-kicker{font-size:9px}.hero-title{font-size:24px}.hero-sub{font-size:9px;white-space:normal;line-height:1.5}
  .hero-actions{flex-wrap:wrap;justify-content:flex-end}.hero-actions .btn{font-size:9px;padding:8px 10px}

  .onex-metrics,.metrics{width:100%;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .onex-metric{min-height:112px;padding:11px}.onex-metric .metric-label{font-size:9px}.onex-metric .metric-val{font-size:20px}
  .metric{padding:12px;min-width:0}.metric-label{font-size:9px}.metric-val{font-size:20px}

  .dashboard-grid,.g2{width:100%;grid-template-columns:1fr;gap:10px}
  .dashboard-grid-right{grid-template-rows:auto}
  .card,.onex-card,.telegram-card{width:100%;max-width:100%;min-width:0}
  .card{padding:14px;border-radius:15px}
  .onex-card-head{padding:12px 13px}.onex-card-body{padding:12px 13px}
  .onex-card-title{font-size:11px}.chart-wrap{height:190px}

  .form-row{grid-template-columns:1fr!important;gap:0}
  .field{min-width:0}.field label{font-size:10px}.field input,.field select,.field textarea{width:100%;min-width:0;min-height:46px;padding:10px 12px;font-size:16px;border-radius:11px}
  .btn{min-height:44px;font-size:10px;padding:9px 12px}.btn-sm{min-height:38px}
  .support-grid{grid-template-columns:1fr!important}
  .quick-grid{grid-template-columns:1fr 1fr}
  .table-wrap{width:100%;max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
  table{min-width:600px;font-size:10px}
  th,td{padding:10px 9px}
  .range-tabs{width:100%;display:grid;grid-template-columns:repeat(4,1fr);gap:5px}
  .range-tab{width:100%;padding:8px 5px;font-size:9px}
  .modal-bg{padding:10px}.modal{width:calc(100vw - 20px);max-width:none;max-height:88vh;overflow:auto}
  .toast{max-width:calc(100vw - 24px);font-size:10px;text-align:center}
}

@media (max-width:480px){
  body{padding-top:56px}
  .mob-bar{height:56px;padding:0 9px}
  .mob-menu-btn{width:40px;height:40px}
  .mob-brand-icon{width:32px;height:32px;flex-basis:32px;font-size:16px}
  .mob-brand-text b{font-size:11px}.mob-brand-text span{font-size:7px}
  .mob-status{font-size:7px}
  .main,.main.expanded{padding:10px 9px 34px}
  .page-title{font-size:20px}.page-sub{font-size:10px}
  .onex-topbar{min-height:60px;padding:8px}.top-chip{display:none}.top-server b{font-size:11px}.top-server small{font-size:7px;max-width:95px}
  .onex-control-dock{gap:5px;padding:5px}.onex-3d-control{min-height:61px;padding:7px 4px}.onex-3d-control .control-icon{width:28px;height:28px;flex-basis:28px}.onex-3d-control .control-title{font-size:8px}.onex-3d-control .control-sub{font-size:5px}
  .hero-title{font-size:22px}.hero-kicker{font-size:8px}.hero-actions{width:100%;justify-content:stretch}.hero-actions .btn{flex:1;font-size:9px}
  .onex-metric{min-height:100px;padding:9px}.onex-metric .metric-label{font-size:8px}.onex-metric .metric-val{font-size:18px}
  .card{padding:12px}.card-title{font-size:10px}.quick-grid{grid-template-columns:1fr}
  .table-wrap table{min-width:560px}
}


/* ============================================================
   ONEX 3D NAV ICONS — polished animated icon set
   ============================================================ */
.nav-item .nav-ico{
  width:21px;height:21px;min-width:21px;min-height:21px;flex:0 0 21px;
  overflow:visible;transform-origin:center;filter:drop-shadow(0 2px 4px rgba(0,0,0,.45));
  transition:transform .28s cubic-bezier(.2,.8,.2,1),filter .28s,color .28s;
}
.nav-item .nav-ico path,.nav-item .nav-ico circle,.nav-item .nav-ico rect{vector-effect:non-scaling-stroke}
.nav-item:hover .nav-ico{transform:perspective(80px) rotateY(-12deg) rotateX(8deg) translateY(-1px) scale(1.08);filter:drop-shadow(0 4px 7px rgba(59,130,246,.42))}
.nav-item.on .nav-ico{transform:perspective(90px) rotateY(-10deg) rotateX(6deg) scale(1.06);filter:drop-shadow(0 3px 8px rgba(59,130,246,.58));animation:navIconFloat 2.8s ease-in-out infinite}
.nav-item.on .nav-ico-dash{animation:navIconPulse 2.6s ease-in-out infinite}
.nav-item.on .nav-ico-telegram{animation:navIconSpinSoft 4s ease-in-out infinite}
.nav-item.on .nav-ico-settings{animation:navIconSpin 5s linear infinite}
.nav-item .nav-ico-create{transform:rotate(-3deg)}
.nav-item:hover .nav-ico-create{transform:perspective(80px) rotateY(-14deg) rotateX(8deg) rotate(-7deg) scale(1.1)}
@keyframes navIconFloat{0%,100%{translate:0 0}50%{translate:0 -2px}}
@keyframes navIconPulse{0%,100%{filter:drop-shadow(0 3px 7px rgba(59,130,246,.35))}50%{filter:drop-shadow(0 5px 13px rgba(59,130,246,.75))}}
@keyframes navIconSpin{from{rotate:0deg}to{rotate:360deg}}
@keyframes navIconSpinSoft{0%,100%{rotate:0deg}35%{rotate:-7deg}65%{rotate:7deg}}
.logout-ico{width:20px!important;height:20px!important;filter:drop-shadow(0 2px 4px rgba(239,68,68,.25));transition:transform .3s cubic-bezier(.2,.8,.2,1),filter .3s}
.sb-foot a.danger:hover .logout-ico{transform:perspective(80px) rotateY(-16deg) rotateX(8deg) scale(1.12) translateX(-2px);filter:drop-shadow(0 4px 9px rgba(239,68,68,.58))}
.sb-foot a.danger .logout-ico{animation:logoutFloat 2.8s ease-in-out infinite}
@keyframes logoutFloat{0%,100%{translate:0 0}50%{translate:-2px -1px}}
@media (max-width:768px){
  .sidebar .nav-item .nav-ico{width:22px;height:22px;min-width:22px;min-height:22px;flex-basis:22px}
  .sidebar .nav-item.on .nav-ico{transform:perspective(80px) rotateY(-8deg) rotateX(5deg) scale(1.04)}
  .sidebar .sb-foot a.danger .logout-ico{width:22px!important;height:22px!important}
}


/* ============================================================
   ONEX MOBILE DRAWER — SAME GLASS AS LOGIN CARD
   The opened dashboard menu intentionally uses the exact same
   glass recipe as .login-card for a consistent visual language.
   ============================================================ */
.sidebar{
  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;
  border-left:1px solid rgba(122,180,235,.14) !important;
  box-shadow:0 18px 55px rgba(0,0,0,.48),0 0 70px rgba(0,119,255,.10) !important;
  backdrop-filter:blur(25px) !important;
  -webkit-backdrop-filter:blur(25px) !important;
  overflow:hidden;
}
.sidebar::before{
  content:"";position:absolute;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(circle at 15% 18%,rgba(36,196,255,.10),transparent 30%),
    linear-gradient(145deg,rgba(255,255,255,.035),transparent 42%,rgba(30,130,255,.055));
}
.sidebar > *{position:relative;z-index:1;}
@media (max-width:768px){
  .sidebar{
    position:fixed !important; top:0 !important; right:0 !important; bottom:0 !important; left:auto !important;
    width:min(86vw,340px) !important; max-width:340px !important; min-width:0 !important;
    transform:translateX(105%) !important;
    transition:transform .24s cubic-bezier(.2,.8,.2,1) !important;
    background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;
    border-left:1px solid rgba(88,180,255,.22) !important;
    border-right:0 !important;
    box-shadow:0 30px 100px rgba(0,0,0,.55),0 0 80px rgba(0,119,255,.10) !important;
    backdrop-filter:blur(25px) !important;
    -webkit-backdrop-filter:blur(25px) !important;
    overflow-y:auto !important;
  }
  .sidebar.mobile-open{transform:translateX(0) !important}
  .sidebar.collapsed{width:min(86vw,340px) !important}
  .mob-bar{display:flex !important;position:fixed !important;top:0;left:0;right:0;height:58px;z-index:1250;
    background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;
    border-bottom:1px solid rgba(88,180,255,.22) !important;
    backdrop-filter:blur(25px) !important;-webkit-backdrop-filter:blur(25px) !important;
    box-shadow:0 12px 35px rgba(0,0,0,.35),0 0 40px rgba(0,119,255,.08) !important;
  }
  .overlay{display:none !important;position:fixed !important;inset:0 !important;background:rgba(1,6,16,.62) !important;backdrop-filter:blur(3px);z-index:1150 !important}
  .overlay.show{display:block !important}
  .main,.main.expanded{width:100% !important;max-width:100% !important;margin:0 !important;padding:70px 12px 40px !important}
}



/* ============================================================
   ONEX GLOBAL THEME SYSTEM — ALL PANEL PAGES
   One visual language for Dashboard / Configs / Create / Stats /
   Logs / Settings / Telegram / News / Admins / Modals / Drawer.
   Dark = ONEX login glass. Light = clean full-white UI.
   ============================================================ */

/* ---------- DARK: same glass language as LOGIN ---------- */
html:not(.light) body{
  background:
    radial-gradient(circle at 18% 22%,rgba(0,126,255,.17),transparent 28%),
    radial-gradient(circle at 85% 15%,rgba(0,207,255,.12),transparent 24%),
    linear-gradient(145deg,#020712 0%,#061329 52%,#02050d 100%) !important;
}
html:not(.light) body::before{
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%,rgba(0,126,255,.14),transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%,rgba(124,58,237,.09),transparent 45%) !important;
}
html:not(.light) .sidebar,
html:not(.light) .mob-bar{
  background:linear-gradient(145deg,rgba(9,22,43,.82),rgba(2,9,20,.72)) !important;
  border-color:rgba(88,180,255,.22) !important;
  box-shadow:0 30px 100px rgba(0,0,0,.45),0 0 80px rgba(0,119,255,.08),inset 0 1px rgba(255,255,255,.08) !important;
  backdrop-filter:blur(25px) saturate(125%) !important;
  -webkit-backdrop-filter:blur(25px) saturate(125%) !important;
}
html:not(.light) .onex-topbar,
html:not(.light) .onex-control-dock,
html:not(.light) .onex-card,
html:not(.light) .onex-metric,
html:not(.light) .card,
html:not(.light) .metric,
html:not(.light) .support-tile,
html:not(.light) .modal,
html:not(.light) .toast{
  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;
  border-color:rgba(88,180,255,.22) !important;
  box-shadow:0 18px 50px rgba(0,0,0,.34),inset 0 1px rgba(255,255,255,.075),inset 0 0 38px rgba(22,140,255,.045) !important;
  backdrop-filter:blur(25px) saturate(125%) !important;
  -webkit-backdrop-filter:blur(25px) saturate(125%) !important;
}
html:not(.light) .onex-control-dock{
  background:linear-gradient(145deg,rgba(9,22,43,.70),rgba(2,9,20,.58)) !important;
}
html:not(.light) .quick-item,
html:not(.light) .top-chip,
html:not(.light) .range-tabs,
html:not(.light) .range-mini,
html:not(.light) .mini-action,
html:not(.light) .sub-box,
html:not(.light) .link-box,
html:not(.light) .table-wrap{
  background:linear-gradient(145deg,rgba(8,20,39,.60),rgba(2,9,20,.48)) !important;
  border-color:rgba(88,180,255,.16) !important;
  box-shadow:inset 0 1px rgba(255,255,255,.055),inset 0 0 28px rgba(22,140,255,.035) !important;
}
html:not(.light) .field input,
html:not(.light) .field select,
html:not(.light) .field textarea,
html:not(.light) #cfgSearch{
  background:linear-gradient(145deg,rgba(2,11,24,.68),rgba(4,14,29,.52)) !important;
  color:#f8fbff !important;
  border-color:rgba(122,180,235,.20) !important;
  box-shadow:inset 0 1px rgba(255,255,255,.035) !important;
}
html:not(.light) th{background:rgba(2,11,24,.58) !important;color:rgba(226,238,255,.62) !important}
html:not(.light) td{border-color:rgba(122,180,235,.11) !important}
html:not(.light) tr:hover td{background:rgba(22,140,255,.055) !important}
html:not(.light) .onex-card-head{border-color:rgba(122,180,235,.12) !important}
html:not(.light) .sb-foot{border-color:rgba(88,180,255,.16) !important}
html:not(.light) .sb-foot button,
html:not(.light) .sb-foot a.btn,
html:not(.light) .btn:not(.btn-p):not(.btn-d){
  background:linear-gradient(145deg,rgba(9,22,43,.70),rgba(2,9,20,.58)) !important;
  border-color:rgba(88,180,255,.18) !important;
  color:var(--t2) !important;
}
html:not(.light) .modal-bg{background:rgba(0,4,12,.68) !important;backdrop-filter:blur(9px) !important}
html:not(.light) .nav-item:hover,
html:not(.light) .nav-item.on{background:rgba(22,140,255,.10) !important}

/* ---------- LIGHT: genuinely white, everywhere ---------- */
html.light body{
  background:#ffffff !important;
  color:#0f172a !important;
}
html.light body::before{background:none !important;opacity:0 !important}
html.light .sidebar,
html.light .mob-bar,
html.light .main,
html.light .onex-topbar,
html.light .onex-control-dock,
html.light .onex-card,
html.light .onex-metric,
html.light .card,
html.light .metric,
html.light .support-tile,
html.light .modal,
html.light .toast,
html.light .quick-item,
html.light .table-wrap,
html.light .sub-box,
html.light .link-box{
  background:#ffffff !important;
  color:#0f172a !important;
  border-color:rgba(15,23,42,.10) !important;
  box-shadow:0 10px 30px rgba(15,23,42,.07),inset 0 1px rgba(255,255,255,.95) !important;
  backdrop-filter:none !important;
  -webkit-backdrop-filter:none !important;
}
html.light .onex-control-dock{background:#ffffff !important}
html.light .onex-3d-control{
  background:linear-gradient(145deg,#ffffff,#f5f8fc) !important;
  color:#0f172a !important;
  border-color:rgba(15,23,42,.10) !important;
  box-shadow:0 7px 0 rgba(15,23,42,.08),0 12px 25px rgba(15,23,42,.08),inset 0 1px #fff !important;
}
html.light .top-chip,
html.light .range-tabs,
html.light .range-mini,
html.light .mini-action{
  background:#ffffff !important;
  color:#334155 !important;
  border-color:rgba(15,23,42,.10) !important;
}
html.light .field input,
html.light .field select,
html.light .field textarea,
html.light #cfgSearch{
  background:#ffffff !important;
  color:#0f172a !important;
  border-color:rgba(15,23,42,.14) !important;
  box-shadow:inset 0 1px 2px rgba(15,23,42,.025) !important;
}
html.light .field input::placeholder,
html.light .field textarea::placeholder{color:#94a3b8 !important}
html.light th{background:#ffffff !important;color:#64748b !important}
html.light td{border-color:rgba(15,23,42,.08) !important;color:#334155 !important}
html.light tr:hover td{background:#f8fafc !important}
html.light .onex-card-head{border-color:rgba(15,23,42,.08) !important}
html.light .sb-foot{border-color:rgba(15,23,42,.08) !important}
html.light .sb-foot button,
html.light .sb-foot a.btn,
html.light .btn:not(.btn-p):not(.btn-d){
  background:#ffffff !important;
  color:#334155 !important;
  border-color:rgba(15,23,42,.12) !important;
}
html.light .nav-item{color:#64748b !important}
html.light .nav-item:hover{background:#f1f5f9 !important;color:#2563eb !important}
html.light .nav-item.on{background:#eff6ff !important;color:#2563eb !important;box-shadow:inset -3px 0 0 #2563eb !important}
html.light .page-title,
html.light .card-title,
html.light .onex-card-title,
html.light .quick-name,
html.light .support-val,
html.light .metric-val,
html.light .onex-metric .metric-val{color:#0f172a !important}
html.light .page-sub,
html.light .field label,
html.light .metric-label,
html.light .quick-desc,
html.light .support-label,
html.light .log-time,
html.light .health-name,
html.light .health-pct{color:#64748b !important}
html.light .log-msg{color:#334155 !important}
html.light .modal-bg{background:rgba(15,23,42,.30) !important;backdrop-filter:blur(7px) !important}
html.light .toast{color:#0f172a !important}

/* Inline utility backgrounds used by the secondary pages: neutralize them
   so every page follows the selected global theme rather than its old color. */
html.light .page [style*="background:rgba(255"],
html.light .page [style*="background: rgba(255"],
html.light .page [style*="background:#0"],
html.light .page [style*="background: #0"]{background:#ffffff !important}
html:not(.light) .page [style*="background:rgba(255"],
html:not(.light) .page [style*="background: rgba(255"],
html:not(.light) .page [style*="background:#0"],
html:not(.light) .page [style*="background: #0"]{
  background:linear-gradient(145deg,rgba(8,20,39,.60),rgba(2,9,20,.48)) !important;
}

/* Keep the primary/danger actions visually meaningful in both themes. */
.btn-p{color:#fff !important}
.btn-d{color:#dc2626 !important}
html:not(.light) .btn-d{color:#ff9b9b !important}

/* Faster theme transition: no page-by-page repaint feeling. */
body,.sidebar,.main,.card,.metric,.onex-card,.onex-metric,.support-tile,.modal,.toast,
.field input,.field select,.field textarea,.table-wrap,.quick-item,.onex-topbar,.onex-control-dock{
  transition:background .16s ease,border-color .16s ease,color .16s ease,box-shadow .16s ease !important;
}
\n/* ============================================================\n   ONEX THEME ENFORCER — SECONDARY PAGES + NESTED COMPONENTS\n   This block intentionally comes last so old hard-coded dashboard\n   colors cannot win over the selected global theme.\n   ============================================================ */\n\n/* DARK: login glass recipe applied to every structural surface. */\nhtml:not(.light) .page .card,\nhtml:not(.light) .page .metric,\nhtml:not(.light) .page .table-wrap,\nhtml:not(.light) .page .support-tile,\nhtml:not(.light) .page .link-box,\nhtml:not(.light) .page .sub-box,\nhtml:not(.light) .page .quick-item,\nhtml:not(.light) .page .range-tabs,\nhtml:not(.light) .page .range-mini,\nhtml:not(.light) .page .mini-action,\nhtml:not(.light) .page .chart-badge,\nhtml:not(.light) .page .health-track,\nhtml:not(.light) .page .xray-state,\nhtml:not(.light) .page .recent-table,\nhtml:not(.light) .page .recent-table th,\nhtml:not(.light) .page .recent-table td,\nhtml:not(.light) .page .field input,\nhtml:not(.light) .page .field select,\nhtml:not(.light) .page .field textarea{\n  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;\n  border-color:rgba(88,180,255,.18) !important;\n  box-shadow:inset 0 1px rgba(255,255,255,.055),inset 0 0 32px rgba(22,140,255,.035),0 14px 38px rgba(0,0,0,.18) !important;\n  backdrop-filter:blur(25px) saturate(120%) !important;\n  -webkit-backdrop-filter:blur(25px) saturate(120%) !important;\n}\nhtml:not(.light) .page .card,\nhtml:not(.light) .page .metric{\n  box-shadow:0 18px 50px rgba(0,0,0,.34),inset 0 1px rgba(255,255,255,.075),inset 0 0 38px rgba(22,140,255,.045) !important;\n}\nhtml:not(.light) .page .field input,\nhtml:not(.light) .page .field select,\nhtml:not(.light) .page .field textarea{\n  background:linear-gradient(145deg,rgba(2,11,24,.68),rgba(4,14,29,.52)) !important;\n  color:#f8fbff !important;\n}\nhtml:not(.light) .page .page-title,\nhtml:not(.light) .page .card-title,\nhtml:not(.light) .page .metric-val,\nhtml:not(.light) .page .quick-name{color:#f8fbff !important}\nhtml:not(.light) .page .page-sub,\nhtml:not(.light) .page .field label,\nhtml:not(.light) .page .metric-label,\nhtml:not(.light) .page .quick-desc{color:rgba(248,250,252,.55) !important}\n\n/* Preserve intentional accent controls/badges in dark mode. */\nhtml:not(.light) .page .btn-p,\nhtml:not(.light) .page .btn-d,\nhtml:not(.light) .page .range-tab.on,\nhtml:not(.light) .page .conn-badge,\nhtml:not(.light) .page .support-icon,\nhtml:not(.light) .page .quick-icon,\nhtml:not(.light) .page .metric-icon{\n  backdrop-filter:none !important;-webkit-backdrop-filter:none !important;\n}\n\n/* LIGHT: every structural panel becomes pure white, not gray. */\nhtml.light .page,\nhtml.light .page.on{color:#0f172a !important}\nhtml.light .page .card,\nhtml.light .page .metric,\nhtml.light .page .table-wrap,\nhtml.light .page .support-tile,\nhtml.light .page .link-box,\nhtml.light .page .sub-box,\nhtml.light .page .quick-item,\nhtml.light .page .range-tabs,\nhtml.light .page .range-mini,\nhtml.light .page .mini-action,\nhtml.light .page .chart-badge,\nhtml.light .page .health-track,\nhtml.light .page .xray-state,\nhtml.light .page .recent-table,\nhtml.light .page .recent-table th,\nhtml.light .page .recent-table td,\nhtml.light .page .field input,\nhtml.light .page .field select,\nhtml.light .page .field textarea,\nhtml.light .page .onex-topbar,\nhtml.light .page .onex-control-dock,\nhtml.light .page .onex-card,\nhtml.light .page .onex-metric{\n  background:#fff !important;\n  color:#0f172a !important;\n  border-color:rgba(15,23,42,.10) !important;\n  box-shadow:0 10px 30px rgba(15,23,42,.07),inset 0 1px rgba(255,255,255,.98) !important;\n  backdrop-filter:none !important;\n  -webkit-backdrop-filter:none !important;\n}\nhtml.light .page .field input,\nhtml.light .page .field select,\nhtml.light .page .field textarea{\n  background:#fff !important;color:#0f172a !important;border-color:rgba(15,23,42,.14) !important;\n}\nhtml.light .page .page-title,\nhtml.light .page .card-title,\nhtml.light .page .metric-val,\nhtml.light .page .quick-name,\nhtml.light .page .support-val{color:#0f172a !important}\nhtml.light .page .page-sub,\nhtml.light .page .field label,\nhtml.light .page .metric-label,\nhtml.light .page .quick-desc,\nhtml.light .page .support-label,\nhtml.light .page .log-time,\nhtml.light .page .health-name,\nhtml.light .page .health-pct{color:#64748b !important}\nhtml.light .page .log-msg{color:#334155 !important}\nhtml.light .page .onex-card-head,\nhtml.light .page .sb-foot{border-color:rgba(15,23,42,.08) !important}\nhtml.light .page th{background:#fff !important;color:#64748b !important}\nhtml.light .page td{background:#fff !important;color:#334155 !important;border-color:rgba(15,23,42,.08) !important}\nhtml.light .page tr:hover td{background:#f8fafc !important}\n\n/* Inline background declarations on secondary pages: normalize containers\n   while leaving action buttons, badges and icons untouched. */\nhtml.light .page div[style*="background:"],\nhtml.light .page section[style*="background:"],\nhtml.light .page article[style*="background:"],\nhtml.light .page aside[style*="background:"]{\n  background:#fff !important;\n  color:inherit;\n}\nhtml:not(.light) .page div[style*="background:"],\nhtml:not(.light) .page section[style*="background:"],\nhtml:not(.light) .page article[style*="background:"],\nhtml:not(.light) .page aside[style*="background:"]{\n  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;\n}\n/* Re-apply accent colors to controls after the broad inline rule. */\nhtml.light .page .btn-p{background:linear-gradient(135deg,#3b82f6,#6366f1) !important;color:#fff !important;border-color:transparent !important}\nhtml.light .page .btn-d{background:rgba(239,68,68,.08) !important;color:#dc2626 !important;border-color:rgba(239,68,68,.20) !important}\nhtml.light .page .range-tab.on{background:#2563eb !important;color:#fff !important}\nhtml.light .page .switch .slider{background:rgba(148,163,184,.35) !important}\nhtml.light .page .switch input:checked + .slider{background:#16a34a !important}\nhtml.light .page .quick-icon,\nhtml.light .page .support-icon,\nhtml.light .page .metric-icon{background:#f1f5f9 !important}\n\n/* Drawer and mobile top bar use exactly the same theme surfaces. */\nhtml.light .sidebar,html.light .mob-bar{\n  background:#fff !important;color:#0f172a !important;border-color:rgba(15,23,42,.10) !important;\n  box-shadow:0 18px 50px rgba(15,23,42,.12) !important;backdrop-filter:none !important;-webkit-backdrop-filter:none !important;\n}\nhtml:not(.light) .sidebar,html:not(.light) .mob-bar{\n  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;\n}\n\n/* Theme switch itself is instant enough that pages never look half-painted. */\nhtml,body,.sidebar,.mob-bar,.main,.page,.page .card,.page .metric,.page .onex-card,.page .onex-metric,\n.page .field input,.page .field select,.page .field textarea,.page .table-wrap,.page .link-box,.page .sub-box{\n  transition:background-color .12s ease,background .12s ease,color .12s ease,border-color .12s ease,box-shadow .12s ease !important;\n}\n/* ============================================================
   3D GLASS PROTOCOL PICKER
   Native select stays in DOM for compatibility; the visible UI is
   a fast custom picker shared by manual + auto create sections.
   ============================================================ */
#page-create select.protocol-native,#page-create .protocol-field select{display:none!important;position:absolute!important;left:-9999px!important;width:1px!important;height:1px!important;opacity:0!important;pointer-events:none!important;visibility:hidden!important}
#page-create .protocol-trigger{isolation:isolate}
#page-create .protocol-trigger:after{content:'⌄';position:absolute;inset-inline-end:10px;top:50%;transform:translateY(-50%);font-size:16px;color:#60a5fa;opacity:.9;pointer-events:none}
#page-create .protocol-trigger .protocol-trigger-arrow{display:none}
#page-create .protocol-trigger{width:100%;min-height:46px;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:8px 12px;border-radius:13px;border:1px solid rgba(96,165,250,.22);background:linear-gradient(145deg,rgba(18,31,58,.88),rgba(7,14,29,.94));color:var(--t1);cursor:pointer;position:relative;overflow:hidden;transition:.2s ease;box-shadow:inset 0 1px rgba(255,255,255,.06),0 8px 22px rgba(0,0,0,.16)}
#page-create .protocol-trigger:before{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 25%,rgba(96,165,250,.10) 50%,transparent 75%);transform:translateX(-120%);transition:.45s ease;pointer-events:none}
#page-create .protocol-trigger:hover{border-color:rgba(96,165,250,.55);transform:translateY(-1px);box-shadow:0 10px 28px rgba(37,99,235,.18),inset 0 1px rgba(255,255,255,.08)}
#page-create .protocol-trigger:hover:before{transform:translateX(120%)}
#page-create .protocol-trigger-main{display:flex;align-items:center;gap:10px;min-width:0;text-align:right}
#page-create .protocol-trigger-icon{width:31px;height:31px;display:grid;place-items:center;border-radius:10px;background:linear-gradient(145deg,rgba(59,130,246,.25),rgba(124,58,237,.20));border:1px solid rgba(147,197,253,.20);font-size:17px;box-shadow:inset 0 1px rgba(255,255,255,.12),0 5px 14px rgba(37,99,235,.18);flex:0 0 auto}
#page-create .protocol-trigger-text{min-width:0;display:flex;flex-direction:column;gap:1px}
#page-create .protocol-trigger-name{font-size:12px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#page-create .protocol-trigger-sub{font-size:9px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#page-create .protocol-trigger-arrow{font-size:14px;color:var(--accent2);transition:transform .2s;flex:0 0 auto}
.protocol-picker-bg{position:fixed;inset:0;z-index:1200;display:none;align-items:center;justify-content:center;padding:16px;background:rgba(1,5,14,.62);backdrop-filter:blur(7px);-webkit-backdrop-filter:blur(7px)}
.protocol-picker-bg.open{display:flex}
.protocol-picker{width:min(620px,calc(100vw - 24px));max-height:min(88vh,760px);overflow:hidden;border-radius:24px;border:1px solid rgba(96,165,250,.35);background:linear-gradient(145deg,rgba(7,19,39,.98),rgba(5,11,24,.985));box-shadow:0 30px 90px rgba(0,0,0,.55),0 0 55px rgba(37,99,235,.13),inset 0 1px rgba(255,255,255,.09);color:var(--t1);transform:translateY(8px) scale(.985);opacity:0;transition:.22s ease;display:flex;flex-direction:column}
.protocol-picker-bg.open .protocol-picker{transform:none;opacity:1}
.protocol-picker-head{padding:17px 18px 15px;border-bottom:1px solid rgba(148,163,184,.12);display:flex;align-items:center;gap:12px;flex:0 0 auto;background:linear-gradient(180deg,rgba(255,255,255,.045),transparent)}
.protocol-picker-head-icon{width:45px;height:45px;border-radius:14px;display:grid;place-items:center;font-size:24px;background:linear-gradient(145deg,#0ea5e9,#2563eb 55%,#7c3aed);box-shadow:0 10px 26px rgba(37,99,235,.35),inset 0 1px rgba(255,255,255,.35);border:1px solid rgba(255,255,255,.2)}
.protocol-picker-head-text{flex:1;min-width:0}.protocol-picker-title{font-size:17px;font-weight:900}.protocol-picker-subtitle{font-size:10px;color:var(--t3);margin-top:3px}.protocol-picker-close{width:34px;height:34px;border:1px solid rgba(148,163,184,.16);border-radius:10px;background:rgba(255,255,255,.035);color:var(--t2);cursor:pointer;font-size:20px;line-height:1;display:grid;place-items:center;transition:.15s}.protocol-picker-close:hover{background:rgba(59,130,246,.14);color:#fff;border-color:rgba(96,165,250,.45)}
.protocol-picker-scroll{overflow:auto;padding:14px 16px 16px;scrollbar-width:thin}.protocol-picker-scroll::-webkit-scrollbar{width:4px}.protocol-picker-scroll::-webkit-scrollbar-thumb{background:rgba(96,165,250,.28);border-radius:99px}
.protocol-section{margin-bottom:17px}.protocol-section:last-child{margin-bottom:0}.protocol-section-title{display:flex;align-items:center;gap:9px;margin:0 2px 9px;color:#93c5fd;font-size:11px;font-weight:900}.protocol-section-title:before{content:"";height:1px;flex:1;background:linear-gradient(90deg,rgba(59,130,246,.05),rgba(59,130,246,.38));order:2}.protocol-section-title span{order:1}.protocol-section-title b{font-size:13px;order:3;font-weight:500}
.protocol-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.protocol-option{position:relative;min-height:91px;border-radius:16px;border:1px solid rgba(96,165,250,.16);background:linear-gradient(145deg,rgba(17,34,62,.74),rgba(7,16,32,.82));padding:11px 10px 10px;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;overflow:hidden;transition:.18s ease;box-shadow:inset 0 1px rgba(255,255,255,.045)}.protocol-option:before{content:"";position:absolute;inset:-30%;background:radial-gradient(circle,rgba(59,130,246,.15),transparent 55%);opacity:0;transition:.18s}.protocol-option:hover{transform:translateY(-2px);border-color:rgba(96,165,250,.48);box-shadow:0 10px 24px rgba(37,99,235,.14),inset 0 1px rgba(255,255,255,.07)}.protocol-option:hover:before{opacity:1}.protocol-option.selected{border-color:#38bdf8;box-shadow:0 0 0 1px rgba(56,189,248,.18),0 0 24px rgba(37,99,235,.24),inset 0 1px rgba(255,255,255,.12);background:linear-gradient(145deg,rgba(18,53,91,.88),rgba(22,18,63,.86))}.protocol-option.selected:after{content:"✓";position:absolute;top:7px;right:7px;width:21px;height:21px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#38bdf8,#6366f1);color:#fff;font-size:12px;font-weight:900;box-shadow:0 5px 13px rgba(59,130,246,.38)}
.protocol-option-radio{position:absolute;top:10px;left:10px;width:16px;height:16px;border-radius:50%;border:2px solid rgba(191,219,254,.65);background:transparent}
/* ============================================================
   REAL 3D PROTOCOL ICONS — static image assets, no animation
   ============================================================ */
.protocol-option-icon.proto-3d{width:76px;height:76px;display:grid;place-items:center;position:relative;flex:0 0 auto;z-index:2}
.proto-3d .static-icon{width:74px;height:74px;display:block;object-fit:contain;filter:drop-shadow(0 9px 12px rgba(0,0,0,.38))}
.protocol-option-name{color:#f8fafc;font-size:12px;font-weight:800;line-height:1.25;text-shadow:0 1px 2px rgba(0,0,0,.55)}
.protocol-option-desc{color:#94a3b8;font-size:9px;line-height:1.25;margin-top:2px}
.protocol-option:hover .static-icon,.protocol-option.selected .static-icon{filter:drop-shadow(0 10px 16px rgba(56,189,248,.30))}
.protocol-option{transition:border-color .15s ease,box-shadow .15s ease,background .15s ease}
.protocol-option:hover{transform:none}
.protocol-option:before{display:none!important}
.protocol-option.selected{transform:none}
.protocol-picker-foot{flex:0 0 auto;padding:10px 14px 14px;border-top:1px solid rgba(148,163,184,.13);background:linear-gradient(180deg,rgba(5,13,27,.72),rgba(5,11,24,.98));display:flex;align-items:center;gap:10px;direction:rtl}
.protocol-selected-info{flex:1;min-width:0;height:38px;display:flex;align-items:center;padding:0 12px;border:1px solid rgba(96,165,250,.16);border-radius:12px;background:rgba(15,35,64,.55);color:#93c5fd;font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.protocol-picker-confirm{flex:0 0 auto;height:42px;padding:0 18px;border:0;border-radius:12px;background:linear-gradient(135deg,#2196f3,#7c4dff);color:#fff;font:800 11px inherit;cursor:pointer;box-shadow:0 8px 20px rgba(37,99,235,.22)}
.protocol-picker-confirm:active{transform:translateY(1px)}
#page-create .protocol-trigger .protocol-option-icon.proto-3d{width:34px;height:34px}
#page-create .protocol-trigger .proto-3d .static-icon{width:34px;height:34px;filter:drop-shadow(0 4px 7px rgba(0,0,0,.28))}

html.light .protocol-picker-bg{background:rgba(15,23,42,.28);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}
html.light .protocol-picker{background:linear-gradient(145deg,#fff,#f7fbff);border-color:rgba(37,99,235,.18);box-shadow:0 28px 80px rgba(15,23,42,.18),0 0 35px rgba(37,99,235,.08);color:#0f172a}.light .protocol-picker-head{border-color:rgba(15,23,42,.08);background:linear-gradient(180deg,#fff,#f8fbff)}.light .protocol-picker-close{background:#f8fafc;color:#475569;border-color:#e2e8f0}.light .protocol-section-title{color:#2563eb}.light .protocol-section-title:before{background:linear-gradient(90deg,rgba(37,99,235,.03),rgba(37,99,235,.22))}.light .protocol-option{background:linear-gradient(145deg,#fff,#f7faff);border-color:rgba(37,99,235,.13);box-shadow:0 5px 18px rgba(15,23,42,.05),inset 0 1px #fff}.light .protocol-option:hover{border-color:rgba(37,99,235,.38);box-shadow:0 9px 22px rgba(37,99,235,.10)}.light .protocol-option.selected{background:linear-gradient(145deg,#eff8ff,#f4f0ff);border-color:#3b82f6;box-shadow:0 0 0 1px rgba(59,130,246,.10),0 10px 25px rgba(37,99,235,.12)}.light .protocol-option-radio{border-color:#94a3b8}.light .protocol-option-desc,.light .protocol-picker-subtitle{color:#64748b}.light .protocol-selected-info{background:#eff6ff;border-color:#bfdbfe;color:#2563eb}
@media(max-width:560px){.protocol-picker-bg{padding:8px}.protocol-picker{width:calc(100vw - 16px);max-height:90vh;border-radius:20px}.protocol-picker-head{padding:13px 14px 12px}.protocol-picker-head-icon{width:40px;height:40px;font-size:21px;border-radius:12px}.protocol-picker-title{font-size:15px}.protocol-picker-scroll{padding:11px 11px 12px}.protocol-grid{gap:7px}.protocol-option{min-height:104px;padding:8px 7px}.protocol-option-name{font-size:10px}.protocol-option-desc{font-size:7.5px}.protocol-picker-foot{padding:9px 11px 11px;gap:7px}.protocol-selected-info{height:34px;font-size:8px}.protocol-picker-confirm{height:40px;padding:0 12px;font-size:10px}}

@media(max-width:560px){.protocol-option-icon.proto-3d{width:64px;height:64px}.proto-3d .static-icon{width:62px;height:62px}}
@media(max-width:360px){.protocol-grid{grid-template-columns:1fr}.protocol-option{min-height:72px}.protocol-option-icon{font-size:21px;margin-bottom:3px}}
#page-create .field label[data-i18n="label_proto"]:before{content:"✦ ";}
/* Hard guarantee: the two protocol controls are custom buttons, never native selects. */
#page-create .protocol-field{position:relative}
#page-create .protocol-field > .protocol-trigger{display:flex!important;visibility:visible!important;opacity:1!important;position:relative!important;z-index:20!important;width:100%!important;min-height:46px!important}
#page-create .protocol-field > select.protocol-native{display:none!important;pointer-events:none!important}
@media(max-width:560px){#page-create .protocol-field > .protocol-trigger{min-height:48px!important;border-radius:14px!important}.protocol-picker{width:calc(100vw - 20px)!important;max-height:88vh!important}.protocol-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}}

/* Final lightweight protocol picker guards */
#page-create .field:has(> select.protocol-native){position:relative}
#page-create .field > select.protocol-native + .protocol-trigger{display:flex!important;visibility:visible!important;opacity:1!important;position:relative!important;z-index:5!important}
.protocol-picker-bg.open{display:flex!important}
.protocol-picker{pointer-events:auto}
@media(max-width:560px){.protocol-picker-bg{padding:7px!important}.protocol-picker{width:min(94vw,620px)!important;max-height:92vh!important;border-radius:22px!important}.protocol-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}}

/* FINAL OVERRIDE - protocol fields are NEVER native dropdowns */
#page-create .protocol-field > select#cProto,
#page-create .protocol-field > select#aProto {
  display:none !important;
  visibility:hidden !important;
  width:0 !important; height:0 !important;
  opacity:0 !important; pointer-events:none !important;
}
#page-create .protocol-field > button.protocol-trigger {
  display:flex !important;
  visibility:visible !important;
  opacity:1 !important;
  width:100% !important;
  min-height:46px !important;
  position:relative !important;
  z-index:30 !important;
  cursor:pointer !important;
}
.protocol-picker-bg { z-index:99999 !important; }
.protocol-picker-bg.open { display:flex !important; visibility:visible !important; opacity:1 !important; }

</style>
</head>
<body>

<div class="mob-bar" id="mobBar">
  <button class="mob-menu-btn" id="mobMenuBtn" aria-label="منو">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
  <div class="mob-brand"><div class="mob-brand-icon">N</div><div class="mob-brand-text"><span>پنل مدیریت</span></div></div>
  <div class="mob-status"><i></i><span>آنلاین</span></div>
</div>
<div class="overlay" id="overlay"></div>

<aside class="sidebar" id="sidebar">
  <button class="sb-toggle" id="sbToggle" title="Toggle">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
  </button>
  <div class="sb-logo">
    <div class="sb-logo-icon" aria-label="ONEX 3D logo">N</div>
  </div>
  <nav class="nav">
    <div class="nav-sec" data-i18n="sec_panel">پنــــل</div>
    <button class="nav-item on" data-page="dash" data-perm="dash">
      <svg class="nav-ico nav-ico-dash" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 13.5 12 4l8 9.5"/><path d="M6.5 12.5V20h11v-7.5"/><path d="M9.5 20v-4.5h5V20"/></svg>
      <span class="nav-label" data-i18n="nav_dash">داشبـورد</span>
    </button>
    <button class="nav-item" data-page="configs" data-perm="configs">
      <svg class="nav-ico nav-ico-configs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m7 4 10 0 3 3v10l-3 3H7l-3-3V7l3-3Z"/><path d="m8 8 8 8M16 8l-8 8"/></svg>
      <span class="nav-label" data-i18n="nav_configs">کانفیگ‌هـا</span>
    </button>
    <button class="nav-item" data-page="groups" data-perm="configs">
      <svg class="nav-ico nav-ico-groups" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="9" r="3"/><circle cx="17" cy="10" r="2.5"/><path d="M3.5 20c.5-3.1 2.4-4.7 5.5-4.7s5 1.6 5.5 4.7"/><path d="M14 15.8c2.8-.8 5 .5 6 3.2"/></svg>
      <span class="nav-label" data-i18n="nav_groups">گروه‌هـا</span>
    </button>
    <button class="nav-item" data-page="create" data-perm="create">
      <svg class="nav-ico nav-ico-create" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m14.5 3 6.5 6.5-8.5 8.5-5.5 1 1-5.5L16.5 5Z"/><path d="m13 5 6 6"/><path d="M4 20h4"/></svg>
      <span class="nav-label" data-i18n="nav_create">ساخت کانفیـگ</span>
    </button>
    <button class="nav-item" data-page="stats" data-perm="stats">
      <svg class="nav-ico nav-ico-stats" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19V5"/><path d="M4 19h16"/><path d="m7 15 3-4 3 2 5-7"/><path d="M16 6h2v2"/></svg>
      <span class="nav-label" data-i18n="nav_stats">امـار</span>
    </button>
    <button class="nav-item" data-page="logs" data-perm="logs">
      <svg class="nav-ico nav-ico-logs" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="3" width="14" height="18" rx="3"/><path d="M8.5 8h7M8.5 12h7M8.5 16h4"/><circle cx="17" cy="17" r="2.2" fill="currentColor" stroke="none"/></svg>
      <span class="nav-label" data-i18n="nav_logs">لاگ فعالیـت</span>
    </button>
    <div class="nav-sec" data-i18n="sec_sys">سیستـم</div>
    <button class="nav-item" data-page="telegram" data-perm="telegram">
      <svg class="nav-ico nav-ico-telegram" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m6.5 12 11-4-3.2 8-2.1-3-3.2-1Z"/><path d="m12.2 13 2.1-2.2"/></svg>
      <span class="nav-label" data-i18n="nav_telegram">پی ایکس بات</span>
    </button>
    <button class="nav-item" data-page="news" data-perm="news">
      <svg class="nav-ico nav-ico-news" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 8h8M8 12h5M8 16h8"/><path d="m15 12 1.5 1.5L19 11"/></svg>
      <span class="nav-label" data-i18n="nav_news">اخبـار</span>
    </button>
    <button class="nav-item" data-page="admins" data-perm="admins">
      <svg class="nav-ico nav-ico-admins" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 20 6v5c0 5-3.2 8.2-8 10-4.8-1.8-8-5-8-10V6l8-3Z"/><circle cx="12" cy="10" r="2.2"/><path d="M8.5 16c.8-2 2-2.8 3.5-2.8s2.7.8 3.5 2.8"/></svg>
      <span class="nav-label" data-i18n="nav_admins">ادمین‌هـا</span>
    </button>
    <button class="nav-item" data-page="settings" data-perm="settings">
      <svg class="nav-ico nav-ico-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 7h14M5 12h14M5 17h14"/><circle cx="9" cy="7" r="2.2" fill="var(--bg2)"/><circle cx="15" cy="12" r="2.2" fill="var(--bg2)"/><circle cx="11" cy="17" r="2.2" fill="var(--bg2)"/></svg>
      <span class="nav-label" data-i18n="nav_settings">تنظیمـات</span>
    </button>
  </nav>
  <div class="sb-foot">
    <a href="/logout" class="btn danger">
      <svg class="logout-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="m14 8 4 4-4 4"/><path d="M18 12H8"/><path d="M13 4v3M13 17v3" opacity=".45"/></svg>
      <span data-i18n="logout">خروج</span>
    </a>
  </div>
</aside>

<main class="main" id="main">

<div class="onex-topbar">
  <div class="top-server"><span class="top-dot"></span><b>سرور آنلاین</b><span class="top-sep"></span><small id="topHost">—</small><span class="top-sep"></span><small id="topUptime">Uptime: —</small></div>
  <div class="top-actions"><div class="top-chip">🇮🇷 فارسی</div><div class="top-chip">🔔 اعلان‌ها</div><div class="top-avatar">N</div></div>
</div>

<div class="onex-control-dock" aria-label="کنترل‌های سریع ONEX">
  <button type="button" class="onex-3d-control" onclick="toggleTheme()">
    <span class="control-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg></span>
    <span class="control-copy"><span class="control-title" id="themeLabel" data-i18n="theme">تم روشن</span><span class="control-sub">THEME CONTROL</span></span>
  </button>
  <button type="button" class="onex-3d-control" onclick="refreshAll()">
    <span class="control-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10M1 14l5.4 4.4A9 9 0 0 0 20.5 15"/></svg></span>
    <span class="control-copy"><span class="control-title" data-i18n="refresh_stats">بروزرسانی آمار</span><span class="control-sub">LIVE STATISTICS</span></span>
  </button>
  <button type="button" class="onex-3d-control" onclick="panelUpdate()">
    <span class="control-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg></span>
    <span class="control-copy"><span class="control-title" data-i18n="refresh_panel">بروزرسانی پنل</span><span class="control-sub">PANEL UPDATE</span></span>
  </button>
</div>
<section class="page on" id="page-dash">
  <div class="dashboard-hero">
    <div>
      <div class="hero-title">خوش آمدید به <span>ONEX</span></div>
      <div class="hero-sub" id="lastUpd" data-i18n="loading">در حال بارگذاری...</div>
    </div>
    <div class="hero-actions">
      <button class="btn btn-p btn-sm" onclick="goPage('create')">＋ ساخت کانفیگ</button>
      <button class="btn btn-sm" onclick="refreshAll()">↻ بروزرسانی</button>
    </div>
  </div>

  <div class="onex-metrics">
    <div class="onex-metric"><div class="metric-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg></div><div class="metric-label">اتصالات فعال</div><div class="metric-val" id="mConns">—</div><div class="metric-trend">LIVE</div></div>
    <div class="onex-metric"><div class="metric-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 20V10M18 20V4M6 20v-4"/><path d="M3 20h18"/></svg></div><div class="metric-label">ترافیک مصرف‌شده</div><div class="metric-val" id="mTraffic">—</div><div class="metric-trend">↑ REALTIME</div></div>
    <div class="onex-metric"><div class="metric-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/></svg></div><div class="metric-label">کانفیگ‌ها</div><div class="metric-val" id="mLinks">—</div><div class="metric-trend">ACTIVE</div></div>
    <div class="onex-metric"><div class="metric-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></div><div class="metric-label">آپتایم سرور</div><div class="metric-val" id="mUptime" style="font-size:17px">—</div><div class="metric-trend">STABLE</div></div>
  </div>

  <div class="dashboard-grid">
    <div>
      <div class="onex-card">
        <div class="onex-card-head"><div class="onex-card-title"><svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg>نمودار مصرف ترافیک</div><div class="range-mini"><button class="on">امروز</button><button>هفته</button><button>ماه</button><button>کل</button></div></div>
        <div class="chart-wrap">
          <div class="chart-badge">ترافیک زنده · <b id="chartTraffic">—</b></div>
          <svg class="traffic-svg" viewBox="0 0 900 270" preserveAspectRatio="none" aria-label="Traffic chart">
            <defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#20c8ff" stop-opacity=".34"/><stop offset="1" stop-color="#2563eb" stop-opacity="0"/></linearGradient></defs>
            <path class="chart-grid-line" d="M20 45H880M20 95H880M20 145H880M20 195H880M20 245H880"/>
            <path class="chart-fill" d="M20 220 C80 190 105 215 155 175 S240 115 290 155 S375 105 420 132 S505 65 555 100 S630 150 680 108 S750 82 800 115 S845 65 880 90 L880 245 L20 245Z"/>
            <path class="chart-line" d="M20 220 C80 190 105 215 155 175 S240 115 290 155 S375 105 420 132 S505 65 555 100 S630 150 680 108 S750 82 800 115 S845 65 880 90"/>
            <circle class="chart-dot" cx="555" cy="100" r="5"/><circle class="chart-dot" cx="800" cy="115" r="5"/><circle class="chart-dot" cx="880" cy="90" r="5"/>
          </svg>
          <div class="chart-labels"><span>00:00</span><span>04:00</span><span>08:00</span><span>12:00</span><span>16:00</span><span>20:00</span><span>24:00</span></div>
        </div>
      </div>
      <div class="onex-card" style="margin-top:14px"><div class="onex-card-head"><div class="onex-card-title">⚡ عملیات سریع</div></div><div class="onex-card-body"><div class="quick-grid">
        <div class="quick-item" onclick="goPage('create')"><div class="quick-icon">＋</div><div><div class="quick-name">ساخت کانفیگ</div><div class="quick-desc">ایجاد کانفیگ جدید</div></div></div>
        <div class="quick-item" onclick="doAutoCreate()"><div class="quick-icon">✦</div><div><div class="quick-name">ساخت خودکار</div><div class="quick-desc">تولید سریع کانفیگ</div></div></div>
        <div class="quick-item" onclick="goPage('configs')"><div class="quick-icon">☷</div><div><div class="quick-name">مدیریت کانفیگ‌ها</div><div class="quick-desc">مشاهده و ویرایش</div></div></div>
        <div class="quick-item" onclick="goPage('telegram')"><div class="quick-icon">➤</div><div><div class="quick-name">ربات تلگرام</div><div class="quick-desc">مدیریت ربات</div></div></div>
      </div></div></div>
      <div class="onex-card recent-card"><div class="onex-card-head"><div class="onex-card-title">▣ کانفیگ‌های اخیر</div><button class="btn btn-sm" onclick="goPage('configs')">مشاهده همه ←</button></div><div class="onex-card-body" style="padding:0"><div style="overflow-x:auto"><table class="recent-table"><thead><tr><th>نام کانفیگ</th><th>پروتکل</th><th>مصرف</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody id="onexRecentBody"><tr><td colspan="5" style="text-align:center;color:var(--t3);padding:24px">در حال بارگذاری...</td></tr></tbody></table></div></div></div>
    </div>
    <div class="dashboard-grid-right">
      <div class="onex-card"><div class="onex-card-head"><div class="onex-card-title">◉ وضعیت سرور</div><span style="color:#34d399;font-size:10px;font-weight:800"><span class="xray-dot"></span>فعال</span></div><div class="onex-card-body"><div class="health-list">
        <div class="health-row"><div class="health-icon">CPU</div><div><div class="health-name">CPU</div><div class="health-track"><div class="health-fill" style="--w:32%"></div></div></div><div class="health-pct">32%</div></div>
        <div class="health-row"><div class="health-icon">RAM</div><div><div class="health-name">RAM</div><div class="health-track"><div class="health-fill" style="--w:56%"></div></div></div><div class="health-pct">56%</div></div>
        <div class="health-row"><div class="health-icon">SSD</div><div><div class="health-name">Disk</div><div class="health-track"><div class="health-fill" style="--w:48%"></div></div></div><div class="health-pct">48%</div></div>
        <div class="health-row"><div class="health-icon">NET</div><div><div class="health-name">Network</div><div class="health-track"><div class="health-fill" style="--w:72%"></div></div></div><div class="health-pct">72%</div></div>
        <div class="xray-state"><span>Xray Core</span><span><span class="xray-dot"></span>Running</span></div>
      </div></div></div>
      <div class="telegram-card"><div><div class="tg-orbit"><div class="tg-logo"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.5 3.5 18.2 20c-.25 1.17-.9 1.45-1.83.9l-5.05-3.72-2.43 2.34c-.27.27-.5.5-1.02.5l.37-5.23 9.52-8.6c.41-.37-.09-.58-.64-.21L5.35 13.2.43 11.66c-1.07-.33-1.09-1.07.22-1.58L19.9 2.52c.91-.34 1.71.21 1.6.98Z"/></svg></div></div><div class="tg-title">کانال تلگرام ما</div><div class="tg-handle">@V2rayTun0</div><div class="tg-desc">آخرین اخبار، آپدیت‌ها و پشتیبانی</div></div><a class="tg-btn" href="https://t.me/V2rayTun0" target="_blank" rel="noopener">➤ عضویت در کانال</a></div>
      <div class="onex-card"><div class="onex-card-head"><div class="onex-card-title">▤ اطلاعات سرور</div></div><div class="onex-card-body"><div class="server-info"><div class="info-row"><span>IP سرور</span><span id="serverIp">—</span></div><div class="info-row"><span>کشور</span><span>—</span></div><div class="info-row"><span>نوع سرور</span><span>VPS</span></div><div class="info-row"><span>شروع سرویس</span><span>ONEX</span></div><div class="info-row"><span>نسخه Xray</span><span>—</span></div></div></div></div>
    </div>
  </div>
  <div class="onex-footer"><span><b>Fast · Secure · Stable</b></span><span>Designed by <b>@Mehtif</b> · Telegram <b>@V2rayTun0</b></span></div>
</section>

<section class="page" id="page-configs">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg><span data-i18n="nav_configs">کانفیگ‌ها</span></div>
      <div class="page-sub" data-i18n="configs_sub">مدیریـت لینک‌هــا · VLESS و سـاب</div>
    </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="cfgSearch" placeholder="جستجو..." oninput="filterConfigs()" style="padding:8px 12px;border-radius:10px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:12px;min-width:140px">

      <button class="btn btn-p btn-sm" onclick="goPage('create')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M12 5v14M5 12h14"/></svg></button>
      <button class="btn btn-sm" onclick="refreshAll()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
    </div>
  </div>
  <div class="card" style="padding:0">
    <div class="table-wrap">
      <div id="bulkBar" style="display:none"></div>
      <table>
        <thead><tr>
          <th style="width:40px;text-align:center;padding:10px 8px">
            <input type="checkbox" id="chkAll" onchange="toggleSelectAll(this.checked);updateBulkBar()" title="انتخاب همه" style="width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer">
          </th>
          <th style="width:28px;padding:10px 4px"></th>
          <th data-i18n="th_name">نـام</th><th data-i18n="th_proto">پروتکـل</th><th data-i18n="th_status">وضعیت</th>
          <th data-i18n="th_usage">مصـرف</th><th data-i18n="th_ops">عملیـات</th>
        </tr></thead>
        <tbody id="linksTable"><tr><td colspan="7" style="text-align:center;color:var(--t3);padding:32px">...</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<section class="page" id="page-create">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="nav_create">ساخت کانفیگ</span></div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="manual_create">ساخت دستی</div>
      <div class="field"><label data-i18n="label_name">نام</label>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="cName" placeholder="auto" style="flex:1">
          <button type="button" class="btn btn-sm" onclick="randomName()" title="Random" style="min-width:44px;height:42px">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></svg>
          </button>
        </div>
      </div>
            <div class="field protocol-field" data-protocol-picker="cProto"><label data-i18n="label_proto">پروتکـل</label><select id="cProto" class="protocol-native" tabindex="-1" aria-hidden="true"></select><button type="button" class="protocol-trigger" data-for="cProto" onclick="window.openProtocolPicker&&window.openProtocolPicker('cProto')"><span class="protocol-trigger-main"><span class="protocol-trigger-icon">🚀</span><span class="protocol-trigger-text"><span class="protocol-trigger-name">VLESS WebSocket</span><span class="protocol-trigger-sub">برای تغییر پروتکل، اینجا بزنید</span></span></span><span class="protocol-trigger-arrow">⌄</span></button></div>
      <div class="field"><label>گروه</label><select id="cGroup"></select></div>
<div class="form-row">
        <div class="field"><label data-i18n="label_count">تعداد کانفیگ در ساب (۱–۴۰)</label><input id="cCount" type="number" value="1" min="1" max="40"></div>
        <div class="field"><label data-i18n="label_days">انقضـا (روز)</label><input id="cDays" type="number" value="0" min="0"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">محدودیت حجم</label><input id="cLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحد</label><select id="cUnit"><option>GB</option><option>MB</option><option>KB</option></select></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_ip">محدودیت IP</label><input id="cIp" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_speed">سرعـت (Mbps)</label><input id="cSpeed" type="number" value="0" min="0"></div>
      </div>
      <button class="btn btn-p" style="width:100%" onclick="doManualCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M5 12h14"/></svg>
        <span data-i18n="btn_create">ساخت</span>
      </button>
    </div>
    <div class="card" style="border-color:rgba(139,92,246,.35)">
      <div class="card-title" data-i18n="auto_create">ساخت خودکـار (پیشنهــادی)</div>
      <p style="color:var(--t2);font-size:13px;line-height:1.75;margin-bottom:14px" data-i18n="auto_desc">با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.</p>
      <div class="field protocol-field" data-protocol-picker="aProto"><label data-i18n="label_proto">پروتکـل</label><select id="aProto" class="protocol-native" tabindex="-1" aria-hidden="true"></select><button type="button" class="protocol-trigger" data-for="aProto" onclick="window.openProtocolPicker&&window.openProtocolPicker('aProto')"><span class="protocol-trigger-main"><span class="protocol-trigger-icon">🚀</span><span class="protocol-trigger-text"><span class="protocol-trigger-name">VLESS WebSocket</span><span class="protocol-trigger-sub">برای تغییر پروتکل، اینجا بزنید</span></span></span><span class="protocol-trigger-arrow">⌄</span></button></div>
      <div class="field"><label data-i18n="label_count">تعداد کانفیگ در سـاب (1-40)</label><input id="aCount" type="number" value="1" min="1" max="40"></div>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="doAutoCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2"/></svg>
        <span data-i18n="btn_auto">ساخـت خودکــار</span>
      </button>
    </div>
  </div>
</section>


<section class="page" id="page-groups">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg><span data-i18n="nav_groups">گروه‌ها</span></div>
      <div class="page-sub">ساخـت گـروه و اختصـاص کانفیـگ هـای دستـی و خودکـار</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title">ساخت گروه جدیـد</div>
      <div class="field"><label>نام گروه</label><input id="grpName" placeholder="مثلا اختصاصـی"></div>
      <button class="btn btn-p" style="width:100%" onclick="createGroup()">ساخـت گروه</button>
    </div>
    <div class="card" style="padding:0">
      <div style="padding:16px 18px;border-bottom:1px solid var(--card-b);font-weight:700">لیست گروه‌ها</div>
      <div id="groupsList" style="padding:12px;max-height:480px;overflow:auto">...</div>
    </div>
  </div>
</section>
<section class="page" id="page-stats">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg><span data-i18n="nav_stats">آمار</span></div>
      <div class="page-sub" data-i18n="stats_sub">ترافیـک و اتصـالات · فیلتـر زمانـی</div>
    </div>
    <div class="range-tabs" id="rangeTabs">
      <button class="range-tab" data-r="day" onclick="setRange('day',this)" data-i18n="r_day">روز</button>
      <button class="range-tab" data-r="week" onclick="setRange('week',this)" data-i18n="r_week">هفتـه</button>
      <button class="range-tab on" data-r="month" onclick="setRange('month',this)" data-i18n="r_month">مـاه</button>
      <button class="range-tab" data-r="all" onclick="setRange('all',this)" data-i18n="r_all">کـل</button>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="metric-label" data-i18n="m_traffic">ترافیـک</div><div class="metric-val" id="sTraffic">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_conns">اتصـالات</div><div class="metric-val" id="sConns">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_links">کانفیـگ فعـال</div><div class="metric-val" id="sActive">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_uptime">آپتایـم</div><div class="metric-val" id="sUptime" style="font-size:16px">—</div></div>
  </div>
  <div class="card"><div class="card-title" data-i18n="panel_info">اطلاعات کل پنل</div><div id="panelInfo" style="font-size:13px;color:var(--t2);line-height:2"></div></div>
</section>

<section class="page" id="page-logs">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg><span data-i18n="nav_logs">لاگ فعالیت</span></div></div>
    <button class="btn btn-sm" onclick="loadLogs()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
  </div>
  <div class="card" id="logsBox"><div style="text-align:center;color:var(--t3);padding:28px">...</div></div>
</section>

<section class="page" id="page-settings">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/></svg><span data-i18n="nav_settings">تنظیمات</span></div></div></div>
  <div class="card">
    <div class="card-title" data-i18n="theme">تــــم هـا</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setTheme('dark')" data-i18n="theme_dark">تـم دارک</button>
      <button class="btn" onclick="setTheme('light')" data-i18n="theme_light">تـم روشـن</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="lang_label">زبـان / Language</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setLang('fa')">فارسـی</button>
      <button class="btn" onclick="setLang('en')">English</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="change_pw">تغییر نام کاربری و رمز عبور</div>
    <div class="field"><label>نام کاربری جدید</label><input type="text" id="newUser" value="admin" autocomplete="username"></div>
    <div class="field"><label data-i18n="pw_cur">رمز فعلـی</label><input type="password" id="pwCur"></div>
    <div class="field"><label data-i18n="pw_new">رمـز جدیـد</label><input type="password" id="pwNew"></div>
    <div class="field"><label data-i18n="pw_cf">تکـرار رمـز</label><input type="password" id="pwCf"></div>
    <button class="btn btn-p" onclick="doChangePw()"><span data-i18n="btn_save">ذخیـره</span></button>
  </div>
  
  <div class="card">
    <div class="card-title">امنیت بیشتـر</div>
    <p style="font-size:12px;color:var(--t3);line-height:1.8;margin-bottom:12px">پـس از 5 تـلاش ناموفـق، ایپـی به مدت 30 دقیقه مسدود می‌شود.</p>
    <div id="secStatus" style="font-size:12px;color:var(--t2);margin-bottom:10px">—</div>
    <button class="btn btn-sm" onclick="loadSecurity()">بروزرسانی وضعیـت</button>
    <button class="btn btn-sm btn-d" onclick="unlockAllIps()">رفع مسدودی همـه ایپــی هــا</button>
  </div>
<div class="card">
    <div class="card-title">بــک آپ و بازیابــی</div>
    <p style="font-size:12px;color:var(--t3);line-height:1.8;margin-bottom:14px">در صورت خرابی پنل، بک‌آپ را دانلود کنید و در پنل جدید وارد کنید.</p>
    <div class="g2" style="margin-bottom:12px">
      <button class="btn btn-p" style="width:100%" onclick="downloadBackup('users')">دانلود بک‌آپ کاربران</button>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="downloadBackup('bot')">دانلود بک‌آپ ربات</button>
    </div>
    <div class="field">
      <label>وارد کردن بـک‌آپ کاربران</label>
      <input type="file" id="restoreUsersFile" accept="application/json,.json" style="padding:10px">
      <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
        <button class="btn btn-sm" onclick="restoreUsers('merge')">ادغام بــــا فعلـی</button>
        <button class="btn btn-sm btn-d" onclick="restoreUsers('replace')">جایگزینی کامـل</button>
      </div>
    </div>
    <div class="field" style="margin-top:12px">
      <label>وارد کردن بــک آپ ربـات</label>
      <input type="file" id="restoreBotFile" accept="application/json,.json" style="padding:10px">
      <button class="btn btn-sm" style="margin-top:8px" onclick="restoreBot()">بازیابـی ربـات</button>
    </div>
  </div>
</section>


<section class="page" id="page-news">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a2 2 0 0 1-2 2Zm0 0a2 2 0 0 1-2-2v-9c0-1.1.9-2 2-2h2"/></svg><span data-i18n="nav_news">اخبار</span></div>
      
    </div>
    <button class="btn btn-sm" onclick="loadNews(true)"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg> <span data-i18n="refresh_news">بروزرسانی اطلاعیه</span></button>
  </div>
  <div class="card" id="newsCard">
    <div class="card-title" id="newsTitle">—</div>
    <div id="newsBody" style="white-space:pre-wrap;line-height:1.9;color:var(--t2);font-size:13px">...</div>
    <div id="newsMeta" style="margin-top:14px;font-size:11px;color:var(--t3)"></div>
  </div>
</section>

<section class="page" id="page-admins">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/></svg><span data-i18n="nav_admins">(نسخـه دمـو) ادمیـن هــا</span></div>
      <div class="page-sub" data-i18n="admins_sub">ساخت اکانت ادمین با دسترسی سفارشـی</div>
    </div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="admin_create">ساخـت اکانـت ادمیـن</div>
      <div class="field"><label data-i18n="admin_user">نام کاربـری</label><input id="adUser" placeholder="user1" style="direction:ltr;text-align:left"></div>
      <div class="form-row">
        <div class="field"><label data-i18n="admin_pw">رمز عبـور</label><input id="adPw" type="password"></div>
        <div class="field"><label data-i18n="admin_pw2">تکرار رمـز</label><input id="adPw2" type="password"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">حجـم</label><input id="adLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحـد</label><select id="adUnit"><option>GB</option><option>MB</option></select></div>
      </div>
      <div class="field"><label data-i18n="label_days">مدت اعتبـار (روز)</label><input id="adDays" type="number" value="0" min="0"></div>
      <div class="card-title" style="margin-top:8px" data-i18n="admin_perms">دسترسی‌ها</div>
      <div id="adPerms" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px"></div>
      <button class="btn btn-p" style="width:100%;margin-top:14px" onclick="createAdmin()" data-i18n="admin_btn">ساخت اکانت</button>
    </div>
    <div class="card" style="padding:0">
      <div style="padding:16px 18px;border-bottom:1px solid var(--card-b);font-weight:700" data-i18n="admin_list">لیست ادمین‌ها</div>
      <div id="adminsList" style="padding:12px;max-height:480px;overflow:auto"><div style="color:var(--t3);text-align:center;padding:20px">...</div></div>
    </div>
  </div>
</section>




<section class="page" id="page-telegram">
  <div class="page-head">
    <div>
      <div class="page-title">
        <svg viewBox="0 0 24 24" fill="currentColor" width="22" height="22"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg>
        <span data-i18n="nav_telegram">پی ایکس بات</span>
      </div>
      <div class="page-sub" data-i18n="tg_sub">توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک</div>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="tg_config">پیکربندی ربات</div>
    <div class="field"><label data-i18n="tg_token">توکن ربات (BotFather)</label><input id="tgToken" placeholder="123456:ABC-DEF..." autocomplete="off"></div>
    <div class="field"><label data-i18n="tg_admin">آیدی عددی ادمین</label><input id="tgAdmin" placeholder="123456789" inputmode="numeric"></div>
    <div class="field" style="display:flex;align-items:center;gap:10px">
      <label class="switch"><input type="checkbox" id="tgWebhook" checked><span class="slider"></span></label>
      <span data-i18n="tg_webhook" style="font-size:13px;color:var(--t2)">فعال‌سازی Webhook (پیشنهادی روی Railway)</span>
    </div>
    <div id="tgStatus" style="font-size:12px;color:var(--t3);margin:10px 0"></div>
    <button class="btn btn-p" style="width:100%" onclick="saveTelegram()">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>
      <span data-i18n="tg_activate">ذخیره و فعال‌سازی ربات</span>
    </button>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="tg_help">راهنما</div>
    <ol style="color:var(--t2);font-size:13px;line-height:2;padding-right:18px">
      <li data-i18n="tg_h1">از @BotFather یک ربات بساز و توکن را کپی کن</li>
      <li data-i18n="tg_h2">آیدی عددی خودت را از @userinfobot بگیر</li>
      <li data-i18n="tg_h3">ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود</li>
    </ol>
  </div>
</section>

</main>

<!-- Result modal after create -->
<div class="modal-bg" id="resultModal">
  <div class="modal">
    <div class="modal-title" data-i18n="created_title">کانفیگ ساخته شد</div>
    <div class="field"><label>VLESS</label><div class="link-box" id="resVless">—</div>
      <button class="btn btn-p btn-sm" style="width:100%" onclick="copyText(document.getElementById('resVless').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <span data-i18n="copy_vless">کپی VLESS</span>
      </button>
    </div>
    <div class="field" style="margin-top:14px"><label data-i18n="sub_label">سابسکریپشن</label><div class="link-box" id="resSub">—</div>
      <button class="btn btn-sm" style="width:100%" onclick="copyText(document.getElementById('resSub').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
        <span data-i18n="copy_sub">کپی ساب</span>
      </button>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeResult()">OK</button>
    </div>
  </div>
</div>

<div class="modal-bg" id="panelModal">
  <div class="modal">
    <div class="modal-title" id="panelModalTitle">...</div>
    <div id="panelModalBody" style="color:var(--t2);font-size:13px;line-height:1.8"></div>
    <div class="modal-actions">
      <button class="btn" onclick="document.getElementById('panelModal').classList.remove('open')">OK</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
const I18N={
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_groups:'گروه‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',nav_donate:'حمایت مالی',nav_news:'اخبار',nav_admins:'ادمین‌ها',refresh_news:'بروزرسانی اطلاعیه',admins_sub:'ساخت اکانت ادمین با دسترسی سفارشی',admin_create:'ساخت اکانت ادمین',admin_user:'نام کاربری',admin_pw:'رمز عبور',admin_pw2:'تکرار رمز',admin_perms:'دسترسی‌ها',admin_btn:'ساخت اکانت',admin_list:'لیست ادمین‌ها',refresh:'بروزرسانی',refresh_stats:'بروزرسانی آمار',refresh_panel:'بروزرسانی پنل',nav_telegram:'ربات تلگرام',tg_sub:'توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک',tg_config:'پیکربندی ربات',tg_token:'توکن ربات (BotFather)',tg_admin:'آیدی عددی ادمین',tg_webhook:'فعال‌سازی Webhook (پیشنهادی روی Railway)',tg_activate:'ذخیره و فعال‌سازی ربات',tg_help:'راهنما',tg_h1:'از @BotFather یک ربات بساز و توکن را کپی کن',tg_h2:'آیدی عددی خودت را از @userinfobot بگیر',tg_h3:'ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا',auto_create:'ساخت خودکار (پیشنهادی)',auto_create_desc:'ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_proto:'پروتکل',label_count:'تعداد کانفیگ در ساب (۱–۴۰)',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',btn_auto:'ساخت خودکار',auto_desc:'با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_groups:'Groups',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',nav_donate:'Donate',nav_news:'News',nav_admins:'Admins',refresh_news:'Refresh news',admins_sub:'Create admin accounts with custom access',admin_create:'Create admin account',admin_user:'Username',admin_pw:'Password',admin_pw2:'Confirm password',admin_perms:'Permissions',admin_btn:'Create account',admin_list:'Admin list',refresh:'Refresh',refresh_stats:'Refresh stats',refresh_panel:'Update panel',nav_telegram:'Telegram bot',tg_sub:'Bot token and numeric admin ID · auto activate and webhook',tg_config:'Bot configuration',tg_token:'Bot token (BotFather)',tg_admin:'Admin numeric ID',tg_webhook:'Enable Webhook (recommended on Railway)',tg_activate:'Save and activate bot',tg_help:'Guide',tg_h1:'Create a bot with @BotFather and copy the token',tg_h2:'Get your numeric ID from @userinfobot',tg_h3:'Save — webhook is set automatically on Railway domain',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed, count and expiry',auto_create:'Auto Create (Suggested)',auto_create_desc:'Quick optimal create · VLESS and Sub links',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_proto:'Protocol',label_count:'Configs in sub (1–40)',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',btn_auto:'Auto create',auto_desc:'One click creates an optimal config. VLESS and Sub links will be shown.',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
};
let lang=localStorage.getItem('px_lang')||'fa';
let statRange='month';
function t(k){return (I18N[lang]||I18N.fa)[k]||k}
function applyLang(){
  document.getElementById('htmlRoot').lang=lang;
  document.getElementById('htmlRoot').dir=lang==='fa'?'rtl':'ltr';
  document.body.classList.toggle('en',lang==='en');
  document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(I18N[lang][k])el.textContent=I18N[lang][k]});
  const tl=document.getElementById('themeLabel');
  if(tl) tl.textContent=document.documentElement.classList.contains('light')?t('theme_dark'):t('theme_light');
}
function setLang(l){lang=l;localStorage.setItem('px_lang',l);applyLang();toast(l==='fa'?'زبان فارسی':'English')}

function setTheme(mode){
  if(mode==='light') document.documentElement.classList.add('light');
  else document.documentElement.classList.remove('light');
  localStorage.setItem('px_theme',mode);
  applyLang();
}
function toggleTheme(){
  const isLight=document.documentElement.classList.contains('light');
  setTheme(isLight?'dark':'light');
}
(function(){const th=localStorage.getItem('px_theme')||'dark';setTheme(th)})();

const sb=document.getElementById('sidebar'),main=document.getElementById('main');
const mobMenuBtn=document.getElementById('mobMenuBtn'),overlay=document.getElementById('overlay');
function closeMobileNav(){ if(sb) sb.classList.remove('mobile-open'); if(overlay) overlay.classList.remove('show'); }
function openMobileNav(){ if(sb) sb.classList.add('mobile-open'); if(overlay) overlay.classList.add('show'); }
if(mobMenuBtn) mobMenuBtn.onclick=()=>{ if(sb.classList.contains('mobile-open')) closeMobileNav(); else openMobileNav(); };
if(overlay) overlay.onclick=closeMobileNav;

document.getElementById('sbToggle').onclick=()=>{
  sb.classList.toggle('collapsed');
  main.classList.toggle('expanded',sb.classList.contains('collapsed'));
  localStorage.setItem('sb_c',sb.classList.contains('collapsed')?'1':'0');
};
if(localStorage.getItem('sb_c')==='1'){sb.classList.add('collapsed');main.classList.add('expanded')}
function goPage(name){
  closeMobileNav();
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('on',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('on',p.id==='page-'+name));
  window.scrollTo({top:0,behavior:'smooth'});
  if(name==='logs')loadLogs();
  if(name==='configs'||name==='dash'||name==='stats')refreshAll();
}
document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>goPage(el.dataset.page)));

function toast(msg){
  const el=document.getElementById('toast');
  el.textContent=msg;el.classList.add('show');
  clearTimeout(window.__tt);window.__tt=setTimeout(()=>el.classList.remove('show'),2200);
}
async function api(url,opts={}){
  try{
    const r=await fetch(url,{cache:'no-store',credentials:'same-origin',...opts});
    if(r.status===401){location.href='/login';return null}
    let data=null;try{data=await r.json()}catch{data={ok:false}}
    if(!r.ok){toast(data.detail||data.error||'Error');return null}
    return data;
  }catch(e){toast(lang==='fa'?'ارتباط برقرار نشد':'Connection failed');return null}
}
function fmtB(b){b=Number(b)||0;if(b<1024)return b+' B';if(b<1024**2)return (b/1024).toFixed(1)+' KB';if(b<1024**3)return (b/1024**2).toFixed(2)+' MB';return (b/1024**3).toFixed(2)+' GB'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

async function refreshAll(){
  if(typeof loadGroups==='function') try{await loadGroups()}catch(e){}
  const links=await api('/api/links');
  if(!links)return;
  const arr=Array.isArray(links.links)?links.links:(Array.isArray(links)?links:[]);
  document.getElementById('mLinks').textContent=arr.length;
  let active=0,used=0;
  arr.forEach(l=>{if(l.active!==false)active++;used+=Number(l.used_bytes||0)});
  document.getElementById('mTraffic').textContent=fmtB(used);
  document.getElementById('sTraffic').textContent=fmtB(used);
  document.getElementById('sActive').textContent=active;
  document.getElementById('lastUpd').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
  try{
    const c=await api('/api/connections');
    const cnt=(c&&c.connections)?c.connections.length:((c&&typeof c.count==='number')?c.count:0);
    document.getElementById('mConns').textContent=cnt;
    document.getElementById('sConns').textContent=cnt;
  }catch(e){}
  try{
    const h=await fetch('/health',{cache:'no-store'}).then(r=>r.json());
    if(h&&h.uptime){
      document.getElementById('mUptime').textContent=h.uptime;
      const su=document.getElementById('sUptime');if(su)su.textContent=h.uptime;
    }
  }catch(e){}
    __allLinks=arr;
  softUpdateLinks(arr);
  document.getElementById('panelInfo').innerHTML=lang==='fa'
    ?`کل کانفیگ: <b>${arr.length}</b> · فعال: <b>${active}</b> · مصرف: <b>${fmtB(used)}</b> · بازه: <b>${statRange}</b>`
    :`Total: <b>${arr.length}</b> · Active: <b>${active}</b> · Usage: <b>${fmtB(used)}</b> · Range: <b>${statRange}</b>`;
  renderOnexRecent(arr);
  const hostEl=document.getElementById('topHost'); if(hostEl) hostEl.textContent=location.host||'ONEX SERVER';
  const ipEl=document.getElementById('serverIp'); if(ipEl) ipEl.textContent=location.hostname||'—';
  const chartEl=document.getElementById('chartTraffic'); if(chartEl) chartEl.textContent=fmtB(used);
  const upEl=document.getElementById('topUptime'); const mu=document.getElementById('mUptime'); if(upEl && mu) upEl.textContent='Uptime: '+mu.textContent;
}

function renderOnexRecent(arr){
  const el=document.getElementById('onexRecentBody'); if(!el) return;
  if(!arr.length){el.innerHTML='<tr><td colspan=5 style="text-align:center;color:var(--t3);padding:24px">کانفیگی وجود ندارد</td></tr>';return}
  el.innerHTML=arr.slice(0,5).map(l=>{
    const name=esc(l.label||l.name||String(l.uuid||l.id||'').slice(0,8));
    const proto=esc(l.protocol||'vless-ws');
    const usage=fmtB(l.used_bytes);
    const active=l.active!==false&&!l.expired;
    const uid=esc(l.uuid||l.id||'');
    return `<tr><td><b>${name}</b></td><td>${proto}</td><td>${usage}</td><td><span class="recent-status"><i></i>${active?'فعال':'متوقف'}</span></td><td><div class="recent-actions"><button class="mini-action" onclick="copyLinkById('${uid}')">⧉</button><button class="mini-action" onclick="copySubById('${uid}')">↗</button></div></td></tr>`;
  }).join('');
}


function linkBadgeClass(l){
  const conn=Number(l.connected_ips||0);
  const used=Number(l.used_bytes||0), lim=Number(l.limit_bytes||0);
  let usagePct=lim>0?(used/lim)*100:0;
  let expWarn=false, expDead=false;
  if(l.expires_at){try{const ms=new Date(l.expires_at)-Date.now();if(ms<=0)expDead=true;else if(ms<3*864e5)expWarn=true}catch(e){}}
  if(expDead||usagePct>=90) return 'conn-badge red';
  if(expWarn||usagePct>=70) return 'conn-badge orange';
  if(conn>0) return 'conn-badge green';
  return 'conn-badge gray';
}
function softUpdateLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!tb) return;
  const rows=[...tb.querySelectorAll('tr[data-uid]')];
  const existing=rows.map(r=>r.getAttribute('data-uid'));
  const incoming=arr.map(l=>String(l.uuid||l.id||''));
  const same = existing.length===incoming.length && existing.every((id,i)=>id===incoming[i]);
  // اگر در حال درگ یا انتخاب هستیم، فقط سلول‌ها را آپدیت کن
  const selecting = document.querySelectorAll('.cfg-chk:checked').length>0;
  const dragging = !!__dragUid;
  if(!same || existing.length===0){
    if(dragging || selecting){
      // فقط آمار ردیف‌های موجود را آپدیت کن، ساختار را نشکن
      window.__linksMap = window.__linksMap || {};
      arr.forEach(l=>{
        const uid=String(l.uuid||l.id||'');
        window.__linksMap[uid]=l;
        const tr=tb.querySelector(`tr[data-uid="${uid}"]`);
        if(!tr) return;
        patchLinkRow(tr, l);
      });
      return;
    }
    renderLinks(arr);
    return;
  }
  window.__linksMap = window.__linksMap || {};
  arr.forEach(l=>{
    const uid=String(l.uuid||l.id||'');
    window.__linksMap[uid]=l;
    const tr=tb.querySelector(`tr[data-uid="${uid}"]`);
    if(tr) patchLinkRow(tr, l);
  });
}
function patchLinkRow(tr, l){
  const conn=Number(l.connected_ips||0);
  const badge=tr.querySelector('.conn-badge');
  if(badge){ badge.textContent=String(conn); badge.className=linkBadgeClass(l); }
  const usageCell=tr.querySelector('[data-usage]');
  if(usageCell){
    usageCell.textContent = fmtB(l.used_bytes) + (l.limit_bytes?(' / '+fmtB(l.limit_bytes)):'');
  }
  // وضعیت سوئیچ را اگر کاربر همین الان عوض نکرده دست نزن — فقط اگر API فرق دارد و فوکوس نیست
  const sw=tr.querySelector('.switch input[type=checkbox]');
  if(sw && document.activeElement!==sw){
    const on=l.active!==false&&!l.expired;
    if(sw.checked!==on) sw.checked=on;
  }
}
function renderLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!arr.length){tb.innerHTML=`<tr><td colspan="7" style="text-align:center;color:var(--t3);padding:28px">${lang==='fa'?'کانفیگی نیست':'No configs'}</td></tr>`;updateBulkBar();return}
  window.__linksMap={};
  const catMap=window.__catMap||{};
  // preserve checked state
  const prevChecked=new Set([...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value));
  tb.innerHTML=arr.map(l=>{
    const uid=l.uuid||l.id||'';
    window.__linksMap[uid]=l;
    const name=l.label||l.name||String(uid).slice(0,8);
    const proto=l.protocol||'vless-ws';
    const on=l.active!==false&&!l.expired;
    const conn=Number(l.connected_ips||0);
    const gname=catMap[String(l.category_id||'')]||'';
    const chk=prevChecked.has(uid)?'checked':'';
    return `<tr draggable="true" data-uid="${esc(uid)}" ondragstart="cfgDragStart(event)" ondragover="cfgDragOver(event)" ondrop="cfgDrop(event)" ondragend="cfgDragEnd(event)">
      <td style="text-align:center;padding:10px 8px;vertical-align:middle"><input type="checkbox" class="cfg-chk" value="${esc(uid)}" ${chk} onchange="updateBulkBar()" style="width:16px;height:16px;margin:0;vertical-align:middle;cursor:pointer"></td>
      <td style="cursor:grab;color:var(--t3);user-select:none" title="کشیدن">⋮⋮</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <b>${esc(name)}</b>
          <span class="${linkBadgeClass(l)}" title="${lang==='fa'?'متصل الان':'Online now'}">${conn}</span>
          ${gname?`<span style="font-size:10px;padding:2px 7px;border-radius:8px;background:var(--hover);color:var(--t3)">${esc(gname)}</span>`:''}
        </div>
      </td>
      <td style="color:var(--t3);font-size:11px">${esc(proto)}</td>
      <td><label class="switch"><input type="checkbox" ${on?'checked':''} onchange="toggleLink('${esc(uid)}',this.checked)"><span class="slider"></span></label></td>
      <td data-usage>${fmtB(l.used_bytes)}${l.limit_bytes?(' / '+fmtB(l.limit_bytes)):''}</td>
      <td class="ops">
        <button class="btn btn-sm" onclick="copyLinkById('${esc(uid)}')" title="VLESS"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        <button class="btn btn-sm" onclick="copySubById('${esc(uid)}')" title="Sub"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg></button>
        <a class="btn btn-sm" href="/info/${esc(uid)}" target="_blank" title="INFO" style="text-decoration:none"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg></a>
        <button class="btn btn-sm" onclick="resetUsage('${esc(uid)}')" title="Reset"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg></button>
        <button class="btn btn-sm btn-d" onclick="deleteLink('${esc(uid)}')"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </td>
    </tr>`;
  }).join('');
  updateBulkBar();
}
function getLinkUrl(l){if(!l)return '';return l.vless_full||l.vless||l.vless_link||l.link||''}
function getSubUrl(l){if(!l)return '';return l.sub||l.sub_url||l.info||''}
async function copyText(text){
  text=String(text||'').trim();
  if(!text||text==='—'){toast(lang==='fa'?'لینکی نیست':'Nothing to copy');return}
  try{
    if(navigator.clipboard&&window.isSecureContext) await navigator.clipboard.writeText(text);
    else{const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;left:-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta)}
    toast(lang==='fa'?'کپی شد':'Copied');
  }catch(e){toast(lang==='fa'?'کپی نشد':'Copy failed')}
}
async function copyLinkById(uid){await copyText(getLinkUrl((window.__linksMap||{})[uid]))}
async function copySubById(uid){await copyText(getSubUrl((window.__linksMap||{})[uid]))}
async function toggleLink(uid,state){
  // optimistic UI — رنگ بلافاصله عوض می‌شود
  if(window.__linksMap && window.__linksMap[uid]){
    window.__linksMap[uid].active = !!state;
    if(window.__linksMap[uid].expired && state) window.__linksMap[uid].expired = false;
  }
  if(typeof __allLinks !== 'undefined' && Array.isArray(__allLinks)){
    const item = __allLinks.find(x => (x.uuid||x.id)===uid);
    if(item) item.active = !!state;
  }
  const r=await api('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!!state})});
  if(r===null){
    // rollback
    if(window.__linksMap && window.__linksMap[uid]) window.__linksMap[uid].active = !state;
    refreshAll();
    return;
  }
  toast(state?(lang==='fa'?'فعال شد':'Enabled'):(lang==='fa'?'غیرفعال شد':'Disabled'));
}
async function deleteLink(uid){
  if(!confirm(lang==='fa'?'حذف شود؟':'Delete?'))return;
  const r=await api('/api/links/'+uid,{method:'DELETE'});
  if(r!==null){toast(lang==='fa'?'حذف شد':'Deleted');refreshAll()}
}
function showResult(data){
  if(!data)return;
  document.getElementById('resVless').textContent=getLinkUrl(data)||'—';
  document.getElementById('resSub').textContent=getSubUrl(data)||'—';
  document.getElementById('resultModal').classList.add('open');
}
function closeResult(){document.getElementById('resultModal').classList.remove('open')}
document.getElementById('resultModal').addEventListener('click',e=>{if(e.target.id==='resultModal')closeResult()});

async function doAutoCreate(){
  toast(lang==='fa'?'در حال ساخت...':'Creating...');
  const count=Math.max(1,Math.min(40,Number(document.getElementById('aCount')?.value)||1));
  const protocol=document.getElementById('aProto')?.value||undefined;
  let r=await api('/api/links/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config_count:count,protocol})});
  if(!r){
    r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:'auto-'+Date.now().toString(36).slice(-5),limit_value:0,limit_unit:'GB',config_count:count})});
  }
  if(r){showResult(r);refreshAll()}
}
async function doManualCreate(){
  const body={
    label:document.getElementById('cName').value||undefined,
    protocol:document.getElementById('cProto')?.value||undefined,
    category_id:document.getElementById('cGroup')?.value||'0',
    config_count:Math.max(1,Math.min(40,Number(document.getElementById('cCount').value)||1)),
    limit_value:Number(document.getElementById('cLimit').value)||0,
    limit_unit:document.getElementById('cUnit').value||'GB',
    expires_days:Number(document.getElementById('cDays').value)||0,
    ip_limit:Number(document.getElementById('cIp').value)||0,
    speed_limit_value:Number(document.getElementById('cSpeed').value)||0,
    speed_limit_unit:'MBIT'
  };
  const r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){showResult(r);refreshAll()}
}
async function doChangePw(){
  const user=document.getElementById('newUser').value.trim(),cur=document.getElementById('pwCur').value,nw=document.getElementById('pwNew').value,cf=document.getElementById('pwCf').value;
  if(nw!==cf){toast(lang==='fa'?'رمزها یکی نیستند':'Passwords mismatch');return}
  const r=await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_username:user,current_password:cur,new_password:nw,repeat_password:cf})});
  if(r){toast(lang==='fa'?'اطلاعات ورود تغییر کرد':'Credentials changed');document.getElementById('pwCur').value='';document.getElementById('pwNew').value='';document.getElementById('pwCf').value='';}
}
async function loadLogs(){
  const box=document.getElementById('logsBox');
  const data=await api('/api/activity');
  const logs=Array.isArray(data)?data:(data&&data.logs)||[];
  if(!logs.length){box.innerHTML=`<div style="text-align:center;color:var(--t3);padding:24px">${lang==='fa'?'لاگی نیست':'No logs'}</div>`;return}
  box.innerHTML=logs.slice().reverse().map(l=>{
    const tm=(l.time||l.ts||'').toString().slice(11,19)||'—';
    return `<div class="log-item"><div class="log-time">${esc(tm)}</div><div class="log-msg">${esc(l.message||l.msg||JSON.stringify(l))}</div></div>`;
  }).join('');
}
function setRange(r,el){
  statRange=r;
  document.querySelectorAll('#rangeTabs .range-tab').forEach(t=>t.classList.toggle('on',t.dataset.r===r));
  refreshAll();toast(t('r_'+r));
}
function randomName(){
  const chars='abcdefghijklmnopqrstuvwxyz0123456789';
  let s='';
  for(let i=0;i<10;i++) s+=chars[Math.floor(Math.random()*chars.length)];
  if(/^[0-9]/.test(s)) s='a'+s.slice(1);
  document.getElementById('cName').value=s;
}
async function panelUpdate(){
  const m=document.getElementById('panelModal');
  const t=document.getElementById('panelModalTitle');
  const b=document.getElementById('panelModalBody');
  t.textContent=lang==='fa'?'در حال بررسی آپدیت...':'Checking update...';
  b.innerHTML='<div style="text-align:center;padding:20px"><div class="spin"></div></div>';
  m.classList.add('open');
  await new Promise(r=>setTimeout(r,1400));
  t.textContent=lang==='fa'?'آپدیت پنل':'Panel update';
  b.innerHTML=(lang==='fa'
    ?'<p style="margin-bottom:12px">اپدیت با خطا مواجه شد. اپدیت را دستی انجام دهید.</p><a href="https://github.com/iran-px-panel/pxpanel" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:700">github.com/iran-px-panel/pxpanel</a>'
    :'<p style="margin-bottom:12px">Update failed. Please update manually.</p><a href="https://github.com/iran-px-panel/pxpanel" target="_blank" rel="noopener" style="color:var(--accent2);font-weight:700">github.com/iran-px-panel/pxpanel</a>');
}
async function saveTelegram(){
  const token=document.getElementById('tgToken').value.trim();
  const admin=document.getElementById('tgAdmin').value.trim();
  const webhook=document.getElementById('tgWebhook').checked;
  if(!token||!admin){toast(lang==='fa'?'توکن و آیدی لازم است':'Token and admin ID required');return}
  toast(lang==='fa'?'در حال فعال‌سازی...':'Activating...');
  const r=await api('/api/telegram/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,admin_ids:admin,webhook})});
  if(r){
    document.getElementById('tgStatus').textContent=r.message||(lang==='fa'?'فعال شد':'Enabled');
    toast(r.message||'OK');
  }
}
async function loadTelegram(){
  const r=await api('/api/telegram/settings');
  if(!r)return;
  if(r.admin_ids) document.getElementById('tgAdmin').value=r.admin_ids;
  document.getElementById('tgWebhook').checked=r.webhook!==false;
  document.getElementById('tgStatus').textContent=r.has_token?(lang==='fa'?'توکن ذخیره شده: ':'Token saved: ')+(r.token_masked||''):'';
}
const _goPage=goPage;
goPage=function(name){
  _goPage(name);
  if(name==='telegram') loadTelegram();
  if(name==='news') loadNews();
  if(name==='admins') loadAdmins();
  if(name==='groups') loadGroups();
  if(name==='settings') loadSecurity();
};

const PERM_LABELS={
  fa:{dash:'داشبورد',configs:'کانفیگ‌ها',create:'ساخت',stats:'آمار',logs:'لاگ',settings:'تنظیمات',support:'پشتیبانی',telegram:'ربات',news:'اخبار',admins:'ادمین‌ها'},
  en:{dash:'Dashboard',configs:'Configs',create:'Create',stats:'Stats',logs:'Logs',settings:'Settings',support:'Support',telegram:'Bot',news:'News',admins:'Admins'}
};
let USER_PERMS=null;
let USER_ROLE='owner';
function buildPermChecks(containerId, selected){
  const box=document.getElementById(containerId);
  if(!box)return;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=Object.keys(labels).map(k=>{
    const on=selected?!!selected[k]:(['dash','configs','create','stats','news'].includes(k));
    return `<div style="display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 12px;border-radius:12px;background:var(--bg3);border:1px solid var(--card-b)">
      <span style="font-size:12px;font-weight:600">${labels[k]}</span>
      <label class="switch"><input type="checkbox" data-perm="${k}" ${on?'checked':''}><span class="slider"></span></label>
    </div>`;
  }).join('');
}
function readPermChecks(containerId){
  const out={};
  document.querySelectorAll('#'+containerId+' input[data-perm]').forEach(inp=>{out[inp.getAttribute('data-perm')]=inp.checked});
  return out;
}
async function loadMe(){
  const r=await api('/api/me');
  if(!r)return;
  USER_ROLE=r.role||'owner';
  USER_PERMS=r.permissions||{};
  const ownerUser=document.getElementById('newUser');
  if(ownerUser && USER_ROLE==='owner' && r.username) ownerUser.value=r.username;
  document.querySelectorAll('.nav-item[data-perm]').forEach(el=>{
    const p=el.getAttribute('data-perm');
    if(USER_ROLE==='owner'){el.style.display='';return}
    el.style.display=USER_PERMS[p]?'':'none';
  });
  // hide admins for non-owner always if no perm
  document.querySelectorAll('.nav-item[data-page="admins"]').forEach(el=>{
    if(USER_ROLE!=='owner') el.style.display='none';
  });
}
async function loadNews(toastOk){
  const r=await api('/api/news');
  if(!r)return;
  document.getElementById('newsTitle').textContent=r.title||(lang==='fa'?'بدون عنوان':'No title');
  document.getElementById('newsBody').textContent=r.message||'';
  document.getElementById('newsMeta').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+(r.updated_at||'—');
  if(toastOk) toast(lang==='fa'?'اطلاعیه بروزرسانی شد':'News refreshed');
}
async function loadAdmins(){
  buildPermChecks('adPerms');
  const r=await api('/api/admins');
  const box=document.getElementById('adminsList');
  if(!r||!r.admins){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:20px">—</div>';return}
  if(!r.admins.length){box.innerHTML=`<div style="color:var(--t3);text-align:center;padding:20px">${lang==='fa'?'ادمینی نیست':'No admins'}</div>`;return}
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  box.innerHTML=r.admins.map(a=>{
    const st=a.blocked?'🔴 مسدود':(a.valid?'🟢 فعال':'🟠 نامعتبر');
    const perms=Object.entries(a.permissions||{}).filter(([,v])=>v).map(([k])=>labels[k]||k).join(' · ')||'—';
    return `<div style="border:1px solid var(--card-b);border-radius:12px;padding:12px;margin-bottom:10px;background:var(--bg3)">
      <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center">
        <div><b>${esc(a.username)}</b> <span style="font-size:11px;color:var(--t3)">${st}</span></div>
        <div class="ops" style="align-items:center">
          <label class="switch" title="مسدود">
            <input type="checkbox" ${a.blocked?'checked':''} onchange="toggleBlockAdmin('${esc(a.id)}',this.checked)">
            <span class="slider"></span>
          </label>
          <button class="btn btn-sm btn-d" onclick="deleteAdmin('${esc(a.id)}')">حذف</button>
        </div>
      </div>
      <div style="font-size:11px;color:var(--t3);margin-top:8px">حجم: ${fmtB(a.used_bytes)}${a.limit_bytes?(' / '+fmtB(a.limit_bytes)):' / ∞'} · انقضا: ${a.expires_at||'∞'}</div>
      <div style="font-size:11px;color:var(--t2);margin-top:6px">${perms}</div>
    </div>`;
  }).join('');
}
async function createAdmin(){
  const body={
    username:document.getElementById('adUser').value.trim(),
    password:document.getElementById('adPw').value,
    repeat_password:document.getElementById('adPw2').value,
    limit_value:Number(document.getElementById('adLimit').value)||0,
    limit_unit:document.getElementById('adUnit').value,
    expires_days:Number(document.getElementById('adDays').value)||0,
    permissions:readPermChecks('adPerms')
  };
  const r=await api('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){toast(lang==='fa'?'اکانت ساخته شد':'Created');document.getElementById('adUser').value='';document.getElementById('adPw').value='';document.getElementById('adPw2').value='';loadAdmins()}
}
async function toggleBlockAdmin(id,blocked){
  const r=await api('/api/admins/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({blocked})});
  if(r){toast(blocked?'مسدود شد':'رفع شد');loadAdmins()}
}
async function deleteAdmin(id){
  if(!confirm(lang==='fa'?'حذف اکانت؟':'Delete?'))return;
  const r=await api('/api/admins/'+id,{method:'DELETE'});
  if(r){toast('OK');loadAdmins()}
}


async function loadProtocols(){
  const r=await api('/api/protocols');
  const list=(r&&r.protocols)||[];
  const def=(r&&r.default)||'vless-ws';
  __protocolPickerOptions=list;
  ['cProto','aProto'].forEach(id=>{
    const el=document.getElementById(id);
    if(!el)return;
    el.innerHTML=list.map(p=>`<option value="${esc(p.id)}" ${p.id===def?'selected':''}>${esc(p.label||p.id)}</option>`).join('')
      ||'<option value="vless-ws">VLESS WebSocket</option>';
  });
  setupProtocolPickers();
}
let __allLinks=[];
function filterConfigs(){
  const q=(document.getElementById('cfgSearch')?.value||'').trim().toLowerCase();
  if(!q){renderLinks(__allLinks);return}
  renderLinks(__allLinks.filter(l=>{
    const name=(l.label||l.name||'').toLowerCase();
    const proto=(l.protocol||'').toLowerCase();
    const uid=String(l.uuid||l.id||'').toLowerCase();
    return name.includes(q)||proto.includes(q)||uid.includes(q);
  }));
}
async function resetUsage(uid){
  if(!confirm(lang==='fa'?'مصرف ریست شود؟':'Reset usage?'))return;
  const r=await api('/api/links/'+uid+'/reset-usage',{method:'POST'});
  if(r!==null){toast(lang==='fa'?'مصرف ریست شد':'Usage reset');refreshAll()}
}


let __dragUid=null;
function cfgDragStart(e){__dragUid=e.currentTarget.getAttribute('data-uid');e.currentTarget.style.opacity='.5';e.dataTransfer.effectAllowed='move';}
function cfgDragOver(e){e.preventDefault();e.dataTransfer.dropEffect='move';const tr=e.currentTarget;if(tr&&tr.tagName==='TR')tr.style.background='var(--hover)';}
function cfgDragEnd(e){e.currentTarget.style.opacity='1';document.querySelectorAll('#linksTable tr').forEach(tr=>tr.style.background='');}
async function cfgDrop(e){
  e.preventDefault();
  const target=e.currentTarget.getAttribute('data-uid');
  document.querySelectorAll('#linksTable tr').forEach(tr=>tr.style.background='');
  if(!__dragUid||!target||__dragUid===target)return;
  const rows=[...document.querySelectorAll('#linksTable tr[data-uid]')];
  const ids=rows.map(r=>r.getAttribute('data-uid'));
  const from=ids.indexOf(__dragUid), to=ids.indexOf(target);
  if(from<0||to<0)return;
  ids.splice(from,1);ids.splice(to,0,__dragUid);
  // reorder DOM optimistically
  const tb=document.getElementById('linksTable');
  ids.forEach(id=>{const el=tb.querySelector(`tr[data-uid="${id}"]`);if(el)tb.appendChild(el);});
  await api('/api/links/reorder',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({order:ids})});
  toast(lang==='fa'?'ترتیب ذخیره شد':'Order saved');
}

function updateBulkBar(){
  const n=document.querySelectorAll('.cfg-chk:checked').length;
  const bar=document.getElementById('bottomBulkBar');
  const cnt=document.getElementById('bulkCount');
  if(cnt) cnt.textContent = n + (lang==='fa'?' انتخاب‌شده':' selected');
  if(bar) bar.classList.toggle('show', n>0);
  const all=document.getElementById('chkAll');
  if(all && n===0) all.checked=false;
}
function clearSelection(){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=false);
  const all=document.getElementById('chkAll');
  if(all) all.checked=false;
  updateBulkBar();
}
function toggleSelectAll(on){
  document.querySelectorAll('.cfg-chk').forEach(c=>c.checked=!!on);
  updateBulkBar();
}

function selectedCfgIds(){return [...document.querySelectorAll('.cfg-chk:checked')].map(c=>c.value)}
async function bulkDelete(){
  const ids=selectedCfgIds();
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  if(!confirm(lang==='fa'?`حذف ${ids.length} کانفیگ؟`:`Delete ${ids.length}?`))return;
  const r=await api('/api/links/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
  if(r){toast(lang==='fa'?`حذف شد: ${r.deleted}`:`Deleted: ${r.deleted}`);refreshAll()}
}
async function bulkMoveGroup(){
  const ids=selectedCfgIds();
  const cid=document.getElementById('bulkGroup')?.value||'0';
  if(!ids.length){toast(lang==='fa'?'چیزی انتخاب نشده':'Nothing selected');return}
  const r=await api('/api/links/bulk-category',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,category_id:cid})});
  if(r){toast(lang==='fa'?'به گروه منتقل شد':'Moved');refreshAll()}
}
async function loadGroups(){
  const r=await api('/api/categories');
  const list=(r&&r.categories)||[];
  window.__catMap={};
  list.forEach(g=>{window.__catMap[String(g.id)]=g.name||g.id});
  const bulk=document.getElementById('bulkGroup');
  const cGroup=document.getElementById('cGroup');
  const opts=list.map(g=>`<option value="${esc(g.id)}">${esc(g.name||g.id)}</option>`).join('');
  if(bulk) bulk.innerHTML=opts||'<option value="0">عمومی</option>';
  if(cGroup) cGroup.innerHTML=opts||'<option value="0">عمومی</option>';
  const box=document.getElementById('groupsList');
  if(box){
    if(!list.length){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:16px">—</div>';}
    else{
      box.innerHTML=list.map(g=>{
        const cnt=(__allLinks||[]).filter(l=>String(l.category_id||'0')===String(g.id)).length;
        return `<div style="border:1px solid var(--card-b);border-radius:12px;padding:12px;margin-bottom:8px;background:var(--bg3);display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap">
          <div><b>${esc(g.name)}</b> <span style="font-size:11px;color:var(--t3)">${cnt} کانفیگ</span></div>
          <button class="btn btn-sm btn-d" onclick="deleteGroup('${esc(g.id)}')">حذف</button>
        </div>`;
      }).join('');
    }
  }
}
async function createGroup(){
  const name=document.getElementById('grpName').value.trim();
  if(!name){toast('نام لازم است');return}
  const r=await api('/api/categories',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  if(r){toast('گروه ساخته شد');document.getElementById('grpName').value='';loadGroups()}
}
async function deleteGroup(id){
  if(!confirm('حذف گروه؟'))return;
  const r=await api('/api/categories/'+id,{method:'DELETE'});
  if(r){toast('حذف شد');loadGroups();refreshAll()}
}


async function loadSecurity(){
  const r=await api('/api/security/status');
  const el=document.getElementById('secStatus');
  if(!r||!el)return;
  const locked=(r.locked_ips||[]).map(x=>`${x.ip} (${Math.ceil(x.remaining_sec/60)}د)`).join(' · ')||'—';
  el.innerHTML=`حداکثر تلاش: <b>${r.max_attempts}</b> · قفل: <b>${Math.round(r.lockout_seconds/60)} دقیقه</b><br>IPهای مسدود: ${locked}`;
}
async function unlockAllIps(){
  if(!confirm('رفع مسدودی همه؟'))return;
  const r=await api('/api/security/unlock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
  if(r){toast('انجام شد');loadSecurity()}
}


async function downloadBackup(kind){
  try{
    const url = kind==='bot' ? '/api/backup/bot' : '/api/backup/users';
    const r = await fetch(url, {credentials:'same-origin', cache:'no-store'});
    if(r.status===401){ location.href='/login'; return; }
    if(!r.ok){
      let msg='خطا';
      try{ const j=await r.json(); msg=j.detail||msg; }catch(e){}
      toast(String(msg)); return;
    }
    const text = await r.text();
    // validate json
    try{ JSON.parse(text); }catch(e){ toast('پاسخ نامعتبر'); return; }
    const blob = new Blob([text], {type:'application/json;charset=utf-8'});
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
    a.href = URL.createObjectURL(blob);
    a.download = kind==='bot' ? ('pxpanel-bot-'+stamp+'.json') : ('pxpanel-users-'+stamp+'.json');
    document.body.appendChild(a);
    a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 500);
    toast(lang==='fa'?'دانلود شد':'Downloaded');
  }catch(e){ toast(String(e.message||e)); }
}
function readJsonFile(inputId){
  return new Promise((resolve,reject)=>{
    const inp=document.getElementById(inputId);
    if(!inp||!inp.files||!inp.files[0]){ reject(new Error(lang==='fa'?'فایل انتخاب نشده':'No file')); return; }
    const fr=new FileReader();
    fr.onload=()=>{ try{ resolve(JSON.parse(fr.result)); }catch(e){ reject(new Error('JSON نامعتبر')); } };
    fr.onerror=()=>reject(new Error('خواندن فایل ناموفق'));
    fr.readAsText(inp.files[0],'utf-8');
  });
}
async function restoreUsers(mode){
  try{
    const data = await readJsonFile('restoreUsersFile');
    data.mode = mode||'merge';
    if(mode==='replace' && !confirm(lang==='fa'?'همه داده‌های فعلی پاک و جایگزین می‌شود. مطمئنی؟':'Replace all current data?')) return;
    const r = await api('/api/restore/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r){ toast(lang==='fa'?('بازیابی شد: '+r.links+' کانفیگ'):('Restored: '+r.links)); refreshAll(); }
  }catch(e){ toast(e.message||String(e)); }
}
async function restoreBot(){
  try{
    const data = await readJsonFile('restoreBotFile');
    const r = await api('/api/restore/bot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    if(r) toast(r.message||(lang==='fa'?'ربات بازیابی شد':'Bot restored'));
  }catch(e){ toast(e.message||String(e)); }
}


/* ============================================================
   PROTOCOL PICKER — STYLE 1 / NEON MODERN
   Single implementation. Internal protocol IDs remain unchanged.
   ============================================================ */
const PROTOCOL_PICKER_ICONS={
  'vless-ws':'V','xhttp-packet-up':'P','xhttp-stream-up':'S','xhttp-stream-one':'C',
  'vmess-ws':'M','trojan-ws':'T','shadowsocks':'S','socks5':'5','http':'H',
  'hysteria2':'H2','tuic':'T','wireguard':'W','highspeed-demo':'T','gaming-lite-demo':'G'
};
const PROTOCOL_PICKER_GROUPS=[
  {title:'VLESS',ids:['vless-ws','xhttp-packet-up','xhttp-stream-up','xhttp-stream-one']},
  {title:'VMess',ids:['vmess-ws']},
  {title:'Proxy',ids:['trojan-ws','shadowsocks','socks5','http','hysteria2']},
  {title:'VPN / Tunnel',ids:['tuic','wireguard']},
  {title:'NEON LAB',ids:['highspeed-demo','gaming-lite-demo']}
];
const PROTOCOL_PICKER_NAMES={
  'vless-ws':'Vortex Link','xhttp-packet-up':'XPacket Flow','xhttp-stream-up':'XStream Pulse','xhttp-stream-one':'XStream Core',
  'vmess-ws':'VMesh Nova','trojan-ws':'Trojan Glide','shadowsocks':'Shadow Mesh','socks5':'Socket Guard','http':'Web Shield',
  'hysteria2':'Hysteria Nova','tuic':'TUIC Blaze','wireguard':'WireGuard Orbit','highspeed-demo':'Turbo Surge','gaming-lite-demo':'Game Pulse'
};
const PROTOCOL_PICKER_KINDS={
  'vless-ws':'rocket','xhttp-packet-up':'packet','xhttp-stream-up':'pulse','xhttp-stream-one':'core',
  'vmess-ws':'mesh','trojan-ws':'trojan','shadowsocks':'shadow','socks5':'socket','http':'shield',
  'hysteria2':'vortex','tuic':'blaze','wireguard':'orbit','highspeed-demo':'turbo','gaming-lite-demo':'game'
};
let __protocolPickerTarget='';
let __protocolPickerOptions=[];
function protocolPickerLabel(id){const p=__protocolPickerOptions.find(x=>x.id===id);return p?.label||id||'VLESS WebSocket'}
function protocolPickerShort(id,label){return PROTOCOL_PICKER_NAMES[id]||label||id}
function protocolIconMarkup(id){
  const icons={
  'vless-ws':'data:image/webp;base64,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',
  'xhttp-packet-up':'data:image/webp;base64,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',
  'xhttp-stream-up':'data:image/webp;base64,UklGRqxSAABXRUJQVlA4WAoAAAAQAAAA7wAA7wAAQUxQSN0kAAAB/yckSPD/eGtEpO4TkNxGciRlRqSpqMr6/4N71ptzRP8nwP7N7vwCwD36c/hsdwCfEaQ72QDyk56P6A+5k2R0NrCAN/ACOIdkbyLR3e7BF3hFEiA7cmamamG9oNkBRHd3rsjxqbqr+KJ2HKbo6cEVd9yrOqteuJMjf+6996qqGmQeM7PHjLTd3bG3V/UZgWlmB0fklaqqG71R0pASaHZE8UraBLpbkIaUtPCQdOXdjZcpvgQe54zWvbdSYhVyOPe+lbPuveVXElXJmdnbaa9uVM34SPJu8bJ3rLC9X9RjjrRWksyMCNDsoZs17iNpk4fMQhDL3kZoQRLJvR1Ewd52AhIkknQAIPgOMwOAJs8KmplR9hsyILSRJEmKiOSPurt37yEQERPAH/eX+enHn62f6vLDxbj0VefG7essRpDWdzHqyK+rLTWy+qxilBXlq9Rq6zmg85IapBd2Ut7OVXo5N25aMXsz4GHFRl60gj0qtlW+YEeHbRwfsg3ziA0+2jbSVNu4li/Sjj6gEzbSvLENWA/KKi+xbQ/o6aM4KyD9SLPqgNRO7XFdQB/6TD2AKtV88581adu+Tm4lPc/3+0emJB9mLGZuZmYaMU57D72CXgEOccTMzNyHXW5LOinLUorJSor4/753EKGiBXRFxARAkiQ5blPp//8ZB24AKMnXiJgA35IkWZIk2RZSzGVd/v8P1wes97kEP6iauWdOfUBETIBn27YVudm2bc619o7IiASxLLZlmRrezMxMVXgYqk97aniMjDejLbPFCRF7zYJ9EBExAfwipf27/n8W/bv+2/5dX1r+W/pf64Pzi8Dn+knpX62j30V5WehVknw+b3l7zryUSv/W26e8xGa+1eeq6EW2+R2JvEU/OPRWv9nb/VTep8oPdS7v+eH5mcIS2cgDqvxGvNzrLvqlZT0UXvBT6z+cTvFmQgT0Br0CPps7jju1GAGEFACBAIhCtqrLkU/2+lwFBASJkBYSGlu9pE/ujnJlg8g9IqIwL8g1NiUHvcFno2uVysn6yD1AhfJSVj5058b0rZm96B19sjfnZZCynNz4+Fc/vsly/KoQ0jv0TW3AIS8zaI3whc98/+PDpIIP3TkrALGFSxe90Ys2VGK3KqI1Nl/4lX/gY+udMqy/9sHXZiDtqKSjI17wUftIa3Ub8X4mG3/xB5/c6F4GhPnFP/v5VvdSJX33UUi35WMC5mXyZ3926MUlUMm4/HV/ejP4halSSr/hJC1RE70gSHqJjb/7y4loRohx5JNHgZQNFJV8KUiiCMmZ5ygSzr6sfO4vv5xE4nDAPrkgnGIRUemLN1rMy+ZtY8C99Hs/+ofPrCyMAHIo4dXJTt44mutE30+IJK88l3Imw+6P//mvHnaRCFB7Id3c+3+2b5BMKBRV6DN6Deb7c62w+q1/+aub7N1AAGIv6Xjr8UiUVh4I0dH7Xkg65NO9CNn+hUd//7cPWZgAmACQQ3357kWFdHNMUI6V5PC1j+m+gYY5r//IJ3ezKlBeOj2/vXK4A54RN+kzekGXP3pA0Dpde7gzJoT9H1f3wnh54hvuQ1NKTijv25xk+loXROOKrS99eh1VBEKJkANdJ6dLPLCDPMs1VMq3CSNshWiVBh/63uM63JhIQsd+IO+8qgRmHWn+IVXfRrXQPEwWGkqNZPuzH54EjWBAzhAJMi5uXgU0ufOoh7Mq+jbKMd2og3ZEHKwf/7X31yOcMCAhezmDIfXodhMC20Wr6RurZnI9uUb9ZtX2+q//w7+BYQRBhLCfHQTSvnOHAJlnq/papBecFT9rtay7H/4zv/8zoQEEgOKBZ5ueu6/e7xl+pigLSt8YNm8HBNRAc3Orz/+qX/EZLLXUcVY3MemH/+u8SRK7XYNnlL61VJdKEDFgbp4rjn7F7/pOu4aTINfRJcTJzW+kQ0CfjJ7qu5P7aO5qg56Zr3/ml314jgLJucvyusPbpwKEL5rgm93dhtoDgYnrn/rClo4SxY4z0ysz394aAe0TfVQfwFOaq1oorX3sCzcTBiAwMVMTowczPrhFGTD6pDziu62HZfyoUNV286sfanq4KKjHLSwPghw/vzciv1BfQx8QLuWMsmpUfejO/ZUiNwrK4bmX4xqAzd3nS3Jon41y773yNicf1xg1jr/0fSuQMYQ39zDDXhz05HXhoS9KHxG9ueW5nghaVdnK/QP+Vz/dSwqqVLoh4vbWVVtFbs0G+0dIXpS3kyIBie4aPfzEoetnNKeDzvUkkOXZ1618vujon+HF+XBMIIwyjh98/VPbw0TkovsHpdswXffujWHHcAOh+dDXoadWfiIazVDf/faXbw7r2qxWQnFnYnfy00/GtqHKVe4hBPRtY91C68dP7qn29oNfODAlJyFalGDCYmJy9faZU0buvD+o4su0XHONn5W5o926xt6cxLvJVSrPMqHTZyfNmKw0NYic+ExmuQe1w2CO4UbqmUDCKO8PQ7mHBuLz+yZCVfJkdtBFH3pS60YS9NNvWf/0IQtBggDxXkeJuBFL8NmTYoZGmpgeQpvbQilT5CogBflOVD/067+rGyRK5005jAVVhxB4eSaTYBAP1pD/8eaVMz11ZEdzUCBp5hsf+sHjCUbXLR/aMm/LGZDHF8WgBcnTxR7UeM18IYepy5J7TkEVTfXth6uxaLEi9y5KZ6rp2FGS5PSygjChKbcel+P4PBUirkHrRozGAuqWP7AnbkZoDvekh0yuuUYE2d0PCHLvWxiHNndijSpKplREYj/L0oFLp737mwVOYZPQvNYRH5caST2/a0krEpTKjDS2O2fJ5HlMKbp4Nb5/r0mJkHBwed1F+2DuLT1O7hYupSFQNHf0QodiiaKUHRMdOUbGsh799s/sVCmBxIpg7nWRRK9nHQ1kvvN0VFWSjjzCPjolsosUWnMOOqL8XH78jFocP/knfvuIiU6YiLy5eSDiVZpIaV+8vS61VP0kZ36C9LxXUnWAWPXc/gLm5QACIpBSuvapz21G//qj+PF+duSPjgE+mR7KBTGREIyRgFHI6s3r2dhfEKa/ohdVAFAREfWdj230Yeu6FT2hnNHTuoxREfRPV9YChOo2HAyAYT+F0NMIo6L+AsH+ij0lRQpAmY8e3BkoJRApnyef5h6xpIiTDTMQA9DEjjG8sZDzRQVplmhFF6RemJUeQtBIKrY+sl5gIJGcfeKpp/cJLS3mSwkeBhPstImREBI/SStfHJVaFJP2ZPbn3g5KoIVtHwzlRgrMlzf3RXT0As2gm25lFuwP0ukkxqRDF+XAjj3N5pqTpvciL5XEgg4B4ORgRXC+i+eiV0XkWumTpM2uRtdRpGlaJp3u7iKTbjpVLsrb0AVRpr3dC6miTNsFUO0eNeHEe9lt5MNZMM29V2HrF/jIZhdFteu5Tq5227nSCVm7O/RTaZRrFzQ7SmjDXnTQ2nRi3q2XOeMdUnicsXfnYLbb57H+2h0N66xJd5sjtrvtxcX5Nsl2bfLzr/Uj51D+AbtoqheAYj3fffGYcM1ppIkNct2r7SIGQBYdVe6lCKFrV1oa5lerw7Qoljy5Oe0dFUmvqhqypN5Ut4Xi0XV7YHF3vbbUG05tODbrGAUFcPUyD5kQAN2BgE+admm4d7A1agfJvUo0pwpQkF6Us7XzPNRRpaUTAer1+9dGFNsOVWosMeRxc4qEeXzcT4sCyG3bToZNAxVPVg9Ga7uHNw+3x3Wy5JSlUP780AuiCNPe5q2WiyL3ntxIAXIfWj2vt7nvIf95UnsUKVJdtaOl5fHmJGWAIDw1qzu7642AUkCKBPZ0H9Vo5Z5eL4siEIubV0eN6LoXxibXMgVcrp5fCyaXJCarctP1Nqqb1gutdoTYjuvu4nI2jQKVPtBocV9IOHPHjaDoyK1jQ+RxOleNOb0ZHVfRHD9vhgACVkDLnry/nM+KW305tdaTG2n1MF4cryla+MkXWfR6xzQ0YWLV5vmHIm9er4Zb6+ntsEuAyIdOl1IPgUIYUzLvJPRz9efnnVJyNzNZ4y9uXwBNfFG7znQY01GUJ0lC1fAzdS3ioeav3FPSbRNKP3ya6S4FARjdESoFHuhKF8MW8OQwwD5x8qzXho7qzVi3Y8guFbp5bL04SVjqJv+3RV36wKS8rLDDwbz8xkeOI5gWGBZl1eb6tXWb+sgnNoYPnI6yf4TTaYBDUHnPoo60rWPu6bLL3DcGCcqvrv/vX2to5n/kCCEh99/59LoEAwEKB1i1LLuZ+sgn3wI+aCozYHKTz6bEIhJYuo3Kmh0MG3rARTkXyp2ghR7/62LM/IWzz3L9NZV4+87HVxQIMRmCBaMm1LUP3Vjk9WBSU8bB7vmzwqVERR5HtGkoZyR1IORthMG7zQ+GXPcXyMelNKlU5jtPr01jFwkQAQVHQlwWAKvq5Uw6m/Vfve2HQdR7Y5PlLDnIh63qZoDH48NVovJNT+bjXEPMcvbfGdXGOAnSSPYkJOm162U22BiYDJv9z3rFiHsl62bYzZTzo4ViEe5Y+UwrGuZvXLOHjudBMDXvnmtoOgQ7BoxCOj27dDS37QOCjo1fvdwAgrCHRkt3NG9TpD6IRCUzT3h8V5XyXU/mdfkw0b7263/g2bs3n132MmcCoTlQEJoQWdXUafWjExr6YfnZkkRg+bvnbUHiTR5zZkbGh1cijOwLs4fY0Qsilc0Xf/y7cvLOyYuRdEOTAEIgAvTBZFgvf3zbQTD9rA0qYj0Nyz48LOzN2QwQg5mfPhsQpCrTn6oRIR+xlK63PvFRz19eFQKUBJU3S88dzrOLkCxWj7ZAOJgXG/bMsnwSRpKC5k/no2KpdLrWHygFRclX+7HazYc+fr27nC8EQsAAAQF6jZXzs0JA40fbpgClbiPWCXHQ7GFgNOUev3MXlHbtUo7cexEEmD765ObuKFnXRRHkoAhNZld2ZyUgi1teiIhw046rUlrYQoRCvL48HopMe64KcfF07VgClNBYWr//oYMVXlx2BXQPY9LdY110EVAZf+j5SEDlPYtofjsG2ygsTWpeTAchaMdlmj7ooyJEEgDYrOzdu/3xfnURFAhAoEM7p0FQ9YlH3WE/vWvlzPwWxLDsURRV52NzkD1eb9YNo5yJJtRDORPIPo1UUfOxz3506csrBknYD8mkJ4wAPnS6cgi9suIck1oQ8iNzZOgylodWA1CevF1ejgi5dHluuj0rg5m55rz+2e/8TL86b8IhQ3YFBMBuPgEEJc/Dovl6Hjt+6sdRbJbrH/voJ/YJgj1eTy/XvM+1V8W8DIDge+m68alPf+oTT16QCCbVBpmArHv1ynQ4+DDSUk3PqVgWQNBg7iml5c2V3/SlweEdKwder5s/rssJSX4OYNC59uXLP/+XlSgZZOIrA8H0wQ860eTQRbFiYTSQaPFdJLa1Nctje3G8ExWFqtLkL+yjnC0UIYIgpl+f9ghAkaLyuYnU4P4zOiqRk9J7gIIFe++gbpdrnf/u5eUOZH/MKZPsaR3rs2JehuqCKLv63/95M0FgYRZWzw20WD58YdMdmEf1riCU4z1p0A4W508WdjFD9vLShIa5rwntG1PnFJKuO/9iK4JC9oBWCYKxtX6WhIDclcSqvlCLGCLSZEi5XRu8PnuF/uJVEGBVF1rQ/Gl76kkYmOTV3/76REQykUrrA5jBtgdrmoTQLSkt30chUWgcgLNKa7uz5y8v7eQsXpIQaPNswn1Ze9M3Hu8gMMz+l3/tGWopHUwaLyfB2a57QkN8oiRZ9HlEJUBnw+R1uzF6/vwNy8upNi6Ln2mQppnHdVxtYSDTr/+Fd7uhsGgkqt0zQdBaRiANeYoD2q4LkJ69qdgsL5VXz07aiz/Oh/k6HfImSB60p8UuCNWVRSLk0V/+t2ms1nIj0+r6mRCl2uqs15kEqUtKyVZRQAEU0fdW+WBSoRee/tdrLdJtv2YvcvhiIku3ltM4O1qi+cjTdxMSZBjn80XX//q8iLbY/fSoWUaV7L2sTSVzGuoDgm+OvuvmC2uyutnxr34+Z8fVo9//XnpVvpp77smndLrZw/JSjpZv7xKQoMkW80XMTrsCUg92rKZKCNTDPI4Wzus8qiBU+jRomxE1f/2LFwnzvtzb/+/fzevFMhfdPm4+1oU8rwkJqPbbzwcQhGi59MXmlGj96p53mqD8LBOGpse8DiGqw9zc086tlQx0p6+mnM072r2NzXNHubtYn3S8d9JV9KBBCZ0+vnfLKACS9aBOLCBkGG+lvitr5FBPSMUs9CYIILLkQVVV4/XWU8bFrJvNFx2x9DgNRrpj6erjoujNyhlCCPOYE5IOQXg7niwPKFJAPqhQSszIz/lo81A6vK6zcmUZi6tF1y9mhYbDuwtDaF5XmaJRD9sfI4e4fnpeGEB4vbw6HKaAKGitCQfQoML6RLu2CAUdS180LxHBbhqz+VVHkOnD6/MLqodliSmpIo9bMjYgoT908ahIEhryaFIVBwRxsbnZuZFMENCnyy4SEnHU6BYxjwiVVOfS98UJrn7cisU8516aunzairkXzE2+3ahC5NQMsQAJsGv3PdzNDMC9Xo2NbIIkzXPiWlqU0vcnl2vvWkK4eNkaZtULpsu+89iLz3vTRSEcv7e3DVFwKk7/8KoEIIBx/dZugtSfSvdHpa23jQTdfZRz6fpCXF3uZtNIfH7RCJ+HnLvtg0XtG7u9LFRo5fjZ08MeEFxQ9/K3bxEEhP7gKCYRoqdDMUayAZENID2PjxYyWpPrs6u5plHqfxUm9tlJL5q9KEn1WQ89zCGx6/ndjTxADzfrnv+hC0GKvrq3t6STgJ4rpdKOYzIQtLx/jYl5OK6r7W7OJhRdPHEAQhmCEeQx75Mv7/ZcLOfSt7cjhYtIFbx/cQEBEm19f3Vhzr14FNK280xXWhuCyMmd23V2gCgnnZM0jLAh1w1j835y7bPQm6kM9lsPnlrmSrIqeYWpIgBHXy2tjiB9IDw5LlmvjB0UMNof126JBaG1J4TE1ZuUAKqoWeUs17VV9CbImj5o83JECXM8vAXDmJCz53a9DjHAcnHe5VxBSILR5JFpeanjMYLN7YOW5owy70t3GrA7mw+cxA9jVUYJGXLfXlBN8mlF2hEiSj352moNS157XU/21gBz1+LN8YuLAs7uTkiTSWt3UDSGsTrarZJXTSgWfaEhkfPTcSNSfoK5D0XO3XTZzLX5dDD3nKH48CtX1lhS3Q6G9fJwUGfzUmZnb1+/uSqBTsJBN2YPG4Z2kRqO1C3fqMDUvV10i64vnQZSD68+Vmpx+XLZ0QzyOB93vJwAIACM216C53qyc/PO0QrkJF3n57vddpcE26bRTd216hoEdRDznQaJ7bSkbKWUhlmB21yPitCO1Isl0yEha5evbreoBwK2Mo9eMsvN+s5aDUIKn745m5goIp+7sWM59qnlrFmja1CX1A6IUoyGsTu5IaKW76aVNi+Xvle3a65UE7kPgTlZGrXJHUbT7LTrGonoup5svoNAcHex4XSO4XXTuiBMofXgQxESebteLEjNHs59jXWZXAlyMuudqR617K1yM5KZXUeVWEWZjObNJYSifc5xkIOhmmbYmoQAjv70+VEK0H1aQgpVx+Z5WO/2osnMPRDIIa4GVT1eWVlqK4cDCEzPq4woQbVU5Kv7W3IuhKq8mBDU0G0wqLMhVKCV73JENN1ErkGZ43Um73shpFGukg+v8nBlbXP34HDVDYKkk5PhUkb0M4pWjr7SG0t2TNJhnFfdg5zIq+QEqRjVnxpEUDuaM6UdJvc9yJ+cDwOoYWtrW9c29462G6PIHuouNJpkqqyJIoZ95yVjCXOdYX12JJDNONwNpARB69ovWyKQeF5rPqwjz8v2buyhhxYLIS5v3318Y/PacnYKKIjp6dWUk5GTsTYBiJmv7kGjpQmRxlx96OCFqeDlkgiUAOrmI3/w+gQRYiQcFoFIjkF6oPgwdHkuhKD51YNb0/3l2gGqROqf/qLe2V6eX67dzK8tojKjhwZLlpNmbusfHc4i/E0Zio4HhOHn/hBLkUAkQIAQDmiMsqJuxfgEeR9yKq5Wb/QY1dkQ6q178j9vDlbq168vSDjc1ulovkY7FpmbdP3IJOjU6g6CJECp9fG3jo5MczCRtI1hL+y3cm63Ue1Nxz6Ycx2LvJoYyQX0/fT3/3a8dbuu8sW2UyYjo3F4ussuo6wrmTNV+8vyQBeybpQCQhkvvnry4urGtc0QI2BDSCTYBtJ0PPPg/kFDIaRxVdQZEVg8/9lv1+8twS2tExLccjAjQ5cy1m2AzrRRieB8XhduqmoIForbW7fv3Lz/7PXaHN04qm46MUCEoKQgHQz64+UM+jajFwtNl7/5/9cPt/uguUFAgsWaOnk7jGWd5szLqRfAGYPHyyiHHI70xdNH79+5def0dTY3PrTRZAWiCTIzl2ftOAlFnaKzWPTSxfO33qCTO+nBkAON5nyqxS2MJKs1yFHqKIrjzSgRVKlkIMN5/vLetx+8fPqBy9GmSkhoyFDrVWivwnoxFholi7BFn7o3x687c4NlJ4kY4wHM3OyNsUpYgMRVI4IpFZUbR6NKtSyV6goTm+xePTh98t57py8uznfXl8G6WazUpNSFJsabDE1nAAssXvzrfx7PZleLqFI2ADT8DJev98JoddAgWpCgyS5eXEx3vaYRBBEKzJxzJj1369J4tBx96vTFq1cXa3w2E/GgrlRv5joxhsMagGD0Wvzsj+OtNReyL8eFQFi35jjmKTvMLwnU5VgEfPFyNr1Kr6kAiiiQgo6Q7qohLvXg/sMn750+fvHX//tZ9g2DvJ5clw9FS0SJOPlPHC2xyHNKA4u9OWc0WYobY5SxYCQRQ/jDXiYN6bKf7XYdIooUpWBoQBQrZVWVu+3u4vWLv/F3zowodLxvdCnqDRhIYnH+5I+bh/UClpMziUCxFUkmrCn3qjFamJAB7PRqMjEja067q54dBA9DNURQ9hUte6Yx3r6ZEMx3w2Y+jgLJvHz+5HxwsGadMXmCq0xpU748tETpXlmAsEGy7qRaAY0cRsecIU1FC9FUAsHsFXtUr9oOvn1K8+a9GGYL8jxCkITO+uLWV6Zrm8tV0FI2o8FAwMD61lUzxjoTUOIYN0RA9Up7lSaB9jAhkkQb6FJNgUlR9c6zQsnFdkxI3q55GYCr06/916+c7I0p1F4lGWkAsu/x5V2qotibDUcR0uvffAhGmca756wzQYESEYgRIsR90KAufOusIrpLoQhHESJ60dvHP/2/v3n/5UuTUKVsdBCCBeRgfSdZSlLzTNaBgHr+W9XAQMT40+vcraWVqqQ6wbAvGNACBaQGN6choQtjGCaPm/fJxYv3H1+u26szwbInghRIqbAFJt/dZJSOvajGqg5DeX77ASiUiOhfH5/PIgDSwHA6BSGQiqIgARHK/+9n5D4ZRMuSZazLAshSw429Xl2ta5PA2GCYNHXzRbnAtPVChrDcfbhSIEFk9/L5ZSeXmRFaaxXsGAQREQQTGcP/3+SeeWxNkJFcE0OOt8ebYu117SQkbHSw+pqONr04umh6ziQqxrB8vy0ESLG/OpsVeko0RCZJgBgMsm8JYYJt/odtx5Ae5D7K4xoiw4frkt1u7U7TEWIPTSbukklNL8ihBS8XYBHS9cOgCFBhnj0s5+yItem2TUtjNIoCAN132xjseNl05HleevpwR9Y5u0OHw2PLd+dlmQ+v9LcooiJpjtYRhIwQmEfjph7kzH7Xq7TpMUMAxUoxCLdmtV/v94RMe5hziTl+cXIxSbq7ARJyy+wr6ChnlnoopdLaFiG2hO79qSi3AATUw/Fk3Pr0KszUpFZMN6ZSDmCRqWHaau2IukXL65gUstncPbusYUgSk4CEIX1hWiobRvKWVNYQxNQkosfJk3ldQpAABevReJzOzi6STkiH2cFojYWWOpTx+f57MBjbzD2L2LQxW/T6k0eXl2rS3aSIMTPsS3JuyGbyXvXnb4MBRCKgv/zD//x6rVFXAiEgLLXDz42r7fZq7tbuueum1bFZjisLqPClM2dR5WXDYLGZvuLZzfPXlzEkBILInMu3d6nmzOfaMpnMtKp35w9faDRkKQqIZubD1c06J5lb6co8kBlx44BCrrbyr67OmqknFRIC6V7ZfGK52O3mrzHmdfmD0Twmj5ANyL2ku9e3T56es04qEUHSYFZXuU7J62owrBS6s5s7wAHQU0aHUrOHTIkRkrnbvnvr6Hy3zv7dHRbLGvalIYguTxltsSARQLAcZ69OukgGSEICEQLCzJlpmyrIdgqkZGZWTxR5mWv2us9u/quvXW7X2WqMueZPj8Yw5rva8XItSyyj56yLV68uZvMCeAAEQQJEAcL+QEBAwO/mTCGknkg5hTx6b8u6JkHbzDl/55I/qj2zEkUtCZCeeHX2+sWzV2fT8bgRQEBGB5RgnIMslBuqW7ojdUuuScbuZYZNwEiu098x1+hb89c7xYGoIWCw7JWV/vL05ARA09Z19mQpu0DP2YrLWEOGqDlzbR6oaUv79Nbu+pCElK7z5X2FTVj6hkzL5xEgiAmiJUPfRT/rymxaFr1KUDAZ0rAZOCrPvLckzaYVec7H/S67OzefbkqhSWRk3xjLvlDNma/SvnkqAUAYUEqJ0nUlPCJmHYpKV8LVtaEwdRMbkNEiZ3WLetH49ejth2vX0BDYYwv6RM4+mBAh9UjZh9y3hWzphma3Gcsywqihg6rAmOW8/f7tOwQRHUgQBMgBZu1u/ZX/Po+uenbb70yl0eMdLF+cOYdsRjJr2ZfYj/RLdzLpVI2iZGipVAkd33t057EJ8jJCKUgkYBxnX3vn9Jir3mNSDW05xmgZxPztq7GndjRtzaxf6ZUmlhhlgFIBoev+o5OLDbBVT5ERAUKEpW5/5WFvLki6W2yTkUkjjNmIPG9BH8iSJSKG5XEeZyEHpdgXQTFJCY/v3dsoaPOydAoCdHP0wde/9XpenBOazq8tpOmxIch9RIt8TjHPDLIMWZdrrgnEYDSC5kDA9Mjzm6+OGg0aM5aXgTT97r9/f53rhAQSMxiNObMhg9nYBpvrF1TJvHvyGFm3M6cJAgLIQYlJdT1/uweKIit5mdhk1x/89//92uwTQrjPymjYNubcTNZ8FVo/urUi1oMmEIM5hEQMRmIe3t0YwjVNCamEaerh/31UR0CIQNgfZdaEZZTXmRZ9QKod5LtdCMZUy74BOWwA7744buObaHmcpow8uLc9FvdoAjCNWTnssD3NuZmPVU6s0uqc82U9udpEcggpupCKjg/eflLLUFY1tHzm65p82JQp2qvBsKOLgtZyZ0lQGQoqiQphefV/Hh+VtI0BlTXRmCZdQqZy4lYqJdYV9xTZgzlr6lDKQKDeO2qIURDZZAiS8eDk4ghGKtIoy4RklRbkUefukKLKqtnyPmSYM9FA33hcM4IG8zghRpazbWGKYMXh+T54zjLnaJfZenv2YjA2IhYilc9cGYLR2IuC9GY9v34NFE2gTadjZOVs/pk5bHohIsk1I+p3FSIa1EPIyvL6/fWoO4D1p7ptN4xyT6x/JKkie/M+AZvk+Mc2QY1K25i29Tzi3f/2JN1zdvZ/sbXhpiPmXpZ/Uifdjrrvzd4oINWf+PGFAsVgVr+z3xp3/uG/vnc51/R+mD8/I+ecPfzjSrmnjqZpL5rNGAoArb9x+19++qlCgiYzdOL86j+7vVvbbb822Ju92osUHZmPU/8MIiyWc5Hli42xEQRxtDUNSVXYb7KrJ//rXi1pYn4Zy9f3dM6YBXvH/iG6wDI559pHz4NAVHeGg40cFJjm7M6rG4aDuc59LTt2Wb2LaRl5O/+cqgsLNiI29oUEBPu12yZVA4SQxPX+vXXpaKHZNrlPpqNLY3va5MxcdyP6R1BuMGrBRj6OIZHsd2+EQikq4Hj+lXuCECEV8xzWPC/qSRbNudFt/FNUlCb3GMo3N1ZRoN3e0E0QEOT1ndfXsEQibF4WlusuzbyMxmTK6y6KT2C5Nugw2UdyJRnNoyG2y7CA2fX0/c0106Qh7Pfm5bwOYzBnue6yy+bUZ2RiwRbMjNgxO2aHgH77vitMEejejAePWChnGwQyn69jXQZjGmOYzHWuKw8+Asc8TGKu6WjNkIa7+wKIAUmOlve/9ehs7YD+O5v5ciISiigqRSKTHCSKrr2kWwcR3dDbua4FEO1HN4KACGk2j//1v36wvVrnTNp+5+NdGigUXbkTMy3jhlR3XhuFHCNRJVgay47WBNTRJweUYCAsV//zb33tfG53nQ7NfHcLSYkSqaIklEeDlFLppjfoLFUSOS8VQjQdyKLZh28DCEDoevCf/tcHS8+sB36OJ3mpUumoUh0Cy5I0U3qhyJnOIXVC19nYLj8Mi6VPTcQAmqzc+ebrpWeahEC+sDnHTOfhhhKqtJxqZIIXKaGEknQKTMvkubDs3IMVCXTPf3Z6dDQnIQDRHWtPo1tzKs1VKjSSpuqFqjrdhZNLHc5hXYYQW0sKhmlr+zf/3GajMRRiODj0IG2ysjn1TEeKyUpz9Q4SupBK1w6bzXWXMLL9Fix0jPXOX/4LD60i0MDPIPcNBvNSiiA3lDTD0ny2+0V6AwBWUDggqC0AAJCHAJ0BKvAA8AA+YSaPRSQiIRd8ziBABgS2N3BgAfwD8AI0A/AC6AfwD8APyA1gD+AfgB+UG3/7P/mgPwD+AfgBcqQLfVfyA7ojSvaf7Z+v35J/KzVv7l/dv0z/bP2/+XnVd1t5T/On+4/xP7z/5X5zf631O/1T/O/+D3Af1F/0n90/Gj41P2k9037aeoj+q/2D/vf6H9//mO/33/J/xXuz/un+l/6/6x/IB/R/7R/3PbD/0fsNf5P/oewN/Ov736Y//g/0f78fRl/V/9Z/9P9d/vvkH/nX9n/7/5+fIB/2PUA/4XsXfwD93/c/6sf0z8Xvc54Ffl/yp84/JD82/ef3V9hXG3at/Nvyljp5L/MfUU9ueee/t6m/iegd7qfgfN6+y83ftF7AfmB/1vDK899gH+f/4L6QPpl/wf/d/tvPj9W/+z/Y/AR/NP7d/4P8R7Yvsh/cv2TP14/8LiTC+y8LxdU7EmF9l4Xi4EL8IlHfZeF4uqdgxpeIKF4JahIicAEkSPOp0GMoxhZ1B2EpQjua7dkbe4uckaGFlditKosS2Nzf3TcZhNTSHPNGJcKrvI06vq5mlSmhQ6PCaGnBoMf7uYTqfhLoAmW8LS2tzUzx2VxPUdsWZVo2I7oakqIJlledOEFwQXba+Yy+BCuu2Vyq7/881QGnMXfkoCLR2KyHDuQI2kSLJYmJ+HlwYiE8mLEjhMTqxYJ+Ln4d05VoJ60IAYWSwQKqhQ7+g+9AKIbEkxFFtG3gnWfpy+sWFVqIXBdgAK5Gho9glVP1bkUUcM8wJMWulOi8V+/lAlFotLyvv/zJQX8ufn2zUWXs95JOU58vAIFzUS02F2H8VxIU3YN7HlHIbxtKovOHwUPI8XdvME9FsaJmR0kXfFBiTEj18ypT+BavmORLJubA3Nt5dgMeT+hwmBzNCItU2XcMf7obEZyLWd6hpUcR6f5ZZ41fmk3n1zT/WSUnGeQRnaebMfViSa107pvCdWEkSwb4kUlLictT2vUgJFtKWoMtoU/T1JMzjZ9xOPChFYG78QKcGmYFRt2j2v/WO/Pm7PcJ+hgTPLFcUZuKFzq/qcYKwD3sda4jU2TkxouuumnDssJaP4UKD3k1Izqemil2JSJRFbDfkfxWmo41oJjGvc3o58qgmyoa/jk74xsH9qfkt1qbZuahoI+7f/9Uwd2s1jvaw9A5y7rhuUnEfOCDLNWgc2B1Hu/nadmiekUzAgk5qHl1vbVrT9maLSbPXck/mAa2v1F2Vpju3JNQs0sdh/9OhfN7T/Tym22MBae8HlO+BHM7UsmSYYgspKPXB4F/viPkaW07MQ1w92wSMSwBXtN9NU+wJUWcYNJpJ4lNqSOXPVlfNlMTdiZqOnNQnW42odr0NPtgb+Y+WnvigjJmXRt12NXKuu/i4EbbUxDWDfrs2CudQDIpUz4SBADxScZeprsPGEnkoFP0uaAA/bvSAVt3W3C+Rzk7I1WQjoC8A4AAAB0EOvsCfktMOzT7BRB+Q2fs0tqfngXXWPbbxAAAFtiCnxmYL0TId+g8AMPeQazf4L5uPzMYu3a7ySW4DAjXsQ2v1LAmUD/T/1M+aqfgW41aK+v9zjf+aQtOpwHujwEDHrqEVIpXXMI4TNsRwm+M0hLS882ESkm9ztE1FImiPwwuYL0qrzMe8FPhS5lwhiYJoOSQwdZ252NwcdHvNjfCygUoU/XQt8v9wD84+Vo4orPzw++eszcbw37tMD83+AGKbYTFOnZVLeQiL9K9SJYUFq46R3oVT0K/W1iR75/8fBD6G0GDsZ14wpVUZ7HPR3NufkUANiBCZbQZtjd6mDP9TEYpViXh55wd4klDn2eGLJMMxGKXsmjifBWGBnMYZzqe383RxdqxcDQJ+uzqbDWyHiAFUvABfYqIEO3//PHxKmsGl6neTGlkAwHSiITFSY8EExtTIS6qfMMHIh7S2+SsDvvVuaI7bbwjTKe/7EANgFbGjSxU9vvqp4EKWFk+scUDfgaEf2iEZE+5sCfPWCZqXRDq4Rjd73/6Fo6aPYY+vdXjC+0YeBS7HL6HuoKC6eMSxfz6fvtlYMLcMH6yYPN9uQwnwmj1nDv09oIlqc1EICRdIaU9+z9CUqETKbqm/cmfuLOeO5Lck8du1YEfQ3h//y2/hL6Yi8Znh0qBJqh+Wleo/+d0jzrFOejrNTYOZKzaXxfEOpM4cANqAZeBYB3qI6pFplbHS01ZWKDxgxxbZVhV4CUq+Y7DjmB1Fig/QUUTsF4+ql+DUtz0ZFB09/d/XL7WzG53CeuCa3wZ+2bynMv5SqCtDorxBKk6ZN8vxe1SBkmAk1rZzO2o5eSLbXs/KhtNYBWvDmylPcrolT9jkoNeBPQlDFBe3SYiK9Qr7++daJANf3Jx5bbBTUPN81uR4tnTZytyKeSRxVeK+sPMfUQbYv5Xr4EchBpq7Zv2eSg8VCysKVt7kb42Yrj7MMyuZpcv4+3M4NhmP5lP7XeSyI//e4OiiQnb5XHjoD109HMfWxuJ7YCBLNPcabuPXqFJ0BqZmNZIIe2ZjMs1oXgTMfwlLkLuTVSsWRWs0SAPrTYrzVcuHpY1hgR6Yax+oZDLvdkCfPoa+t9r6TYwx7Ft9eMSFmXflaCTTWYiyHfWD/3jnAMj97eWhxNtd7K4Jn/z060RY2UsH19XaNqAxtdApMV+XDvYSzK4lQkurh/kyls9mg2+24JyXkje+DwGCFkBxuohIdpF6V0byw53b6hT3EpysZyWFescgDOy1Ar2ErXahi/mm7A8UUz5+mP8WnVdPPcdz1e04ZGlQDBztydv3VN2PoV7z2Ot3lhA444OiKbH5K2A1ZqRzyDsqVsf9V0T8Z+1I6DzviynoF/eN0mQp6iSc/nEg7zQzkUX9ZwRQbJZd5KQgC/QTHXHrqC0MU5/5qifab7X3sM8LnB4wlW+pRzmG59HKgRH7uWMkqfxXVyhLm/Bfx4wVBL3jcTmaP9RPYBzfua/4hPMvcTorKlK7/9/gYM55lxqEdxio7KbRXg2NKeCZVcUGCtZHRYEInTiKtK7eu4+UZ2VnqsOkvL9V+V4hx9t5tQQEP6NZgjcitwVD8f4ecPXVyVA/Zwh1fsZaOBjTG/ffJRm6OC5idlgPtv/8NtYuXhm4i5Gh8kOKJb3YLFhZcoK/pzhSPVAPPw+pMnL5b9DkdV1zVJMmsDfARl6ZcV+qmq471Inn8lwWgnrmt650/K2linXgvoHunEuWkkFzNnGNbC/LXQzQxOlp4SVnR+FElbVkHISFrFeH3mtj54Dbn2fyIknuMpj6vUNW9QaKDG9tVPkPUz7oiQk2VOKmm4yGTQikiSlcfkx/mnZF9O44nccKvZTyaAv+QCN80KTF7EVZNQXfJhtz4BoAZctoElfbIw5XlM3tS29FzCxqbfbNQXiUelypq8SV1arP1KIN97IB4XxqbWllZGfXG7SAsQZDuNngxbdkDxpwgQ4VYxKONsud+7ah75naHPDM+sTJs8ngFB2nKmzUGVlnVv9h9gS3XL+CRbLH5Xbi2HWjKKdj3oKUUxi40umgz8fYcFFBlURgg0tdtV8mcVvJyXD7Tf2IBOQac1T0ujK3kH3PIdsoaPl//gA3Kj6IqyDxfT29RwHkdOoPOh4buwSGTvIQCZ20H/orMatMRklHl9GPyAcrYTsguyEJQ1SaU3tVJMwA5KEDUX5X0pst0OaK8FI4EKYmCry/JcgGxWH35VhRlx+knaUgpfi5wGSC3I9u/3BP2yTp1edxIY+4EbIWFNaP1NjSEje+hoeJN5QroxBHDa+P/jJMEhEQ1JsnRkTFouyYKaMZRvH3fiVr0R8On6NOdQJnG7fyri1MN5k6GLOrVLevxfsv9A4DpbXTaVlvXVnh0c5zj2dXzFAaVDJpPhr+wNxucsPaFFiqphAo7l4TlUOR2zVpgyPd11k+qTPjSXrvP5U6SwkHJnF99bd1AMfq8p/zWIwjvh5nOjR7T/96Bak/xMkfnxu8A8Dzb9Wx6GSDFO1W14ect7RK6E/EYEOLzwzeyq2ezzsqNpjmQ5hPLX9YzTR3kLF3IrWIafxcNZc+4YKpVJ/EFFLYdlKr+0Gozp+5hmymYbI3MC6WbpDPg0xARv+B9uw3WrdcRz4A1UGuGUes8GjV0iaxOinpF1YIdL8RiQeXx5USUMSb9PJ3X5CQdSR2YlOc1CQumvXzCpOh93y/SIqBZJ4TRsuvN4DD6ZxiG+E9Z4Epu3ZqOoAG9v6Z4Mj8mdmM1U0YoUli345ca522+3sWw6/S9b5cQERO9AozViao1TIJfseYY/fVgx1uzDhanlu+ctCcFQk23fqBnyaDNsvZ2f8dQdx9vXC13b0HJUTh3fcmTmoWI852PA2Ms/rhRdnRI1IJY8kuxfTZ2MMnvrO/D91sAIVgO6c7mW1TyzpQ22uXEn8vKSipMgmhuPC5Tc4EH8oB1KxMyhf5x2FuPA48zsjrH3SGsHDJUR2mQqpMesDvvWHl5VtgCG0hw+uACJKuIW7s6f4Q6KJr16bPIOSF/nXMIV9p7bHjYxdL7CWuw+dJPhuPRWrxC4I5hMvQfIyTv4Kco4uP5v/sH7M12KwsvL6Vj8tTfs2VYxYvlasrPPqtgOuRQHwSNY57dNJP5kvEz505RV3ALxrnHyqllPni41zJVWGbDR8V5lIuHlQzaCLnXPjOVVUpGJlw7oefUgccIuKNsfJ199l9vL5vDTkA2IEHtLpgUgTsur2ilZy5hRkn246b1B60LGAMJ97bK0yGfMFP7xh2TsS/MU2200UHfTsXCbjfrDsue2X5C4g7N7W8gUpGYKnadkEp0t5g5nK9HTdJrO4GB3HrKQ3Ic89lBOyZiFSSLf0piZMwOF19XoD//7E99Iih/4xY2tqnMBu1rM8aF+3HrcMtcqR4LMooZkH0hTw5ri8Sk+97wy2bIEVEliY/KFYQNtCuzf5kevKSW0QvoKFaYuaQ7XJEiTBsGMKwi1xg7CA8Z4d/71y6SRxZNs4E7LukSwYWrrts/1JilMh4P6y6fsl/zQwzBfQ7DWRqEgqz3PqEKyPL7X4ep1D/lEyQpzJw3hedYClYGtorHtsPPD1CUj2r4RNB8fGcrNlfN3BSCxZr10xAxzDrI3QdQbXuBEx7R4ENJerYmz+vzrJ5jWOCec5G559iC1zC+115cP8LaoGgtClWlku7THiAZPMtiBdmWluoRPD4D+TYBuxFMDFKUstCfbN/2c/Xq6e+iq+AY+BN0CTtUsJE5Gp3P5n9kfrXeq6YU5NYx2rYKkohco1hWLnLwnWc50fHxC+D40LTygUi4KTxrZi99+byYAZWFZdDNlgFG58pZG2qBudreIFVhE7YkOGIoZrnQmLOQ0ju4oPzEZC9xRW7Dje750/VoB9kYRxNBBEDXGqJ2L6KLtEqykhnUYKVcg0VAZ93IHmqKsrN17Gx6eWQoJwQ+dY06TikFwVQEihsKooqLYjlPvHiYUV5anhIQGgt37tbPhqafZbbBk0EKjIQm8za8M4YKSQ+AJ+sB1y5Psqgbud9zlxqstJY2yhs+M4IZmMBljUTByrRadOOPEHav05tRvNv/gxWAWoJCgM8s2cT6nWXrrygRLeZ2M6un0/x3apTSXph3Env5JUeVmzlWDcaesYGY8aGwIKYO4nZrCqw9hBhDmEzY9ERWuCeNNqamZ7h0TeR4g7HPXWbloL5lkU9IVL7IZLwcNtqsLV4EqRZi6qranJA5VXjRqXzDQlQU7oWdmwWMT3OiROUSxSqBwlYKhicYXLftj8ZRFx95WsRGA3tgFuwoCm13SEqLPIKLkDOSVLNMm442wD5E80gKjxhN+pUTw7GHAIr//6l+SSHxdfMark6WDTEmfTojq4lUyCTz5yOpPEGVNqveD/+LUfLnfJufNRui3eaUUybRQS4/FVPpJbNAMIbTZD/8NsrZwuABaZJZ0QT3RfRZeMJ7XimVmYJmTiPcls9tqrXjvdyqAGvqVLbok2qXkfOKckxesIYU48ArBxFRZEX20msIvyJuZ2ZstcJG0c6mSgKeXvNoUmjxgLSUUpvVF5wfcvgI7fNXz6LGsQbZJgkQtYev+FlXSQnJB+Yzti3GXIXFD01egwL9S65W1ofePUU36dyz3ygGnqP2wYg+0Npr9VvmUDvxwalP2H2md2usuA5goLITwY044/onbY4xdGf44Dl1yn99HMyrQ9xfCONmxVNECVdcqdbqCVK+EImK+dzN6ZvEIyFZJiUpahGsmtVhhwcQ5vGArgKwN2GhxgqQoI5SlAv6OVMwOn2mqfPN4nn3W+OpecinsnOt6qRmyKZcLN+eAeX9KoXCtxIprU9BTTwQ4167/plvj9MtdwZaheqgRtZxrZpXJsFx4Wy6ac1nVvrVZnaIBeZrNi0NI/8WQ2JlhYTHCGfvlP6Vil/+yXfGH/8GnAyPHmJ/QDOBz2SNuo1MMh8v842DvsP4S88g9viQ8ONvfM67/tQRpRKb/YaXxhs+uG2yOiHUkFJBqTLgyi/gzUtltxcLV1rfjGrNMbdP7J8N67u7eL0/Tpzi1IP4uUkvK7CEyRa8YcK632epjSrn4KHoUdfn1XEO7A8t99i4BI1e0rcR3K8eXfZ//woLUuMQXfI6C3KocZsHbNTAbzAIfhAjObnmCuYEuWUC9Y5f6zRJnTr8g3A8ef7ljL9dZmcsQzZDZ7K7qR29vW33ftyP4T3iTYy6BoxujFGqb19MAddO32fM2JHMCV0Q1VE6ZjyK3oqxIpQE53r8GVA6if7eNDRCdMBilACVUJtVsU+l1x2Q08lDU2NmVvtfDAtgwm4GLaJcC6cW09UnuoxO5OYNvU4VmwmGJhONx0Wv7+xjh3N6WW7Vf51duKhL46sXW2/3rB1BVm/oAqEUSVGfBCUVe49sQ1+Yxobfbq7pAjBB6hlQfrwQNDsezhvfOOXkzrju1v1yNQGE9BPFthZHNSdIvGymjnByDm2ZX6Ug2QnquWmI4X7yhg5nWzl/lh1HaTvTZixeYvw5eBvkWAA6MnbZVxAsuZH2iKRdZbFFr9j4Uit2SMy3PZabjz9SDiZ9nl7UskBr+145ZN14cIaPPSfGV36v1RvbsDBgZM8Q+WG8tyBNpaBHyPoX0ZR/jyvHbUjMrf+p42GKwfWFwD1XV+84cZsUbJfVv/fzIdpPfZbG0WVPBIAuEPIFV5NqV1mQIseMtd8ec7IsU01s1b77LnxyL00WyKkTCoiG5Fj6fvsDiTwGth7J0eHyeWwZs/2+sXlx68Jzdugt91P9wWUn2uNWElMZPl/X81zTNrnI2kw6JDYyuD4VEcze19Ucg3ujBqb5JraRYntFDpTiBUfwxigX4STsbJht7udFiyecItS1E5LA2pGWkvuNTx/FUXBA+NN4Qq6OWmAo1RxqSgkzBY8yojGKZ1j2ggL1FGsZdhB5YrcwL+9lz6ED8Wz4l2tEZbA6gqUUT9ig6gb4rzvXmvOBbtNFvpYnnaIqRNMkyi841HN7jy+ejTM30HllU2bGAiFdKddwyk8oBhUa00S0BGnYTg6wmP//oiUViPGwuGx/AjGgQyo1dBvMHmP7T8MCcessgFSnnHBHzTwoWt6Pov7NOx61176RpGw1CVsmjzIm9LD39iOrn1KyPotXeTVuke+teyEAodXLohL8Y7C/+uwayhAdgFT1x5CX4cFiS1oDBWPYKrMu3vxq/kE99mPA9AsleNYZDXKHTyG0N+YPuWacjsmgnWTCHuzgLzlf/3mTOQ7nP9s+iUOufvs2Y1sc7anBS/9SX6XT00D+uiA2Ia5u2L4bwD/AKI9RmY+9pa349HWoLduH85i7kl4ArNQ/wSto9yG6zcwHqwcl1BVJpG/ucaJ4PHTLxlhyh4YnmR6rizscIsLF6Yg4/2RvdesExMDaywsDpo7I+2WauVRJ2sTcdKRgC8SmJu7BklzDPdINMoT1EcBjWNaEQ2SI15KMiLy9AgJi5WLxlBEfNxoKMgu3J4i4EOvx4SD8hM/39Kcp9qI7nqkD3DwptnK9JZ4bWEff6oKjDDHOygN+N86b5uNuf49k/jqQgu1fWCDdt9I19sMb0KIq+mSsfQ/hz4nQNkDXt5ZAMj4qC5DhxQTvzaEgBbErD/W84R6iCMKphKJSprc1jqoXFiHVMM3yHR544hDihQ8LGmvugGDVjA+TfDQePZTndpsuKGEyMysCFp1bLRIpCbYV6AT1gXfQrJq2mUjy1skaf/6uQGZqwEN4YgvVx1uRCgV8jOZHECyvdrTTBnB2hFwzGofex5FvFsTNP1l5NIZkTaCKSjisAUu/mwaxXOFlTnBZWimjaQg40QoR1vL/OTXolcPkLtMGt7lSrQux63u2MhpwOJKp2VRZv9fI7Y9emSczyoRT9Cei95f2LYwUXMY3EgT32tNsHWtYm1JdEqUqrbo4TYvg4UYXuCDMtjo66InbmJAudPLhf5KKKHLcoGESXL8NscWL7DTNpsERqCMj46veFwEm+XjPvgepJotyAJuchdkYtrx0dArFG+w9al/S+d8/8ARalIrKATXiK/kUlynfnX369b8da8Zr5drYtlTtEfI5sKzyDV8b1ji7BqNPM5HWLKXdcCXqCUDeENp04QfENJJJfZf/7mOJn+logiEwpboALm4V8fQIzrxtaCwwTfKYV/E8Y/vOPpTD/wZgcj4gJrgaF/3FnUh9oexlQr/HzwOZXXO+y1DiWVKpNu5r9Gcpw5UAf8Pra1IR8M2uHCTU/0NMv7g6JUMWkonASBir/1W5vijZouSddpdwyd4D/qEDmpJGYFMaDfX5YgDIGBsCO0w78pJE4LZ6Yf376GB2qcj1w0kGUayKsaWvfrQbv/y+52zOyDvWdSYA2yAolkDDTP9Jyhuncae37kXl7WTt6IWkRHz0XGL0214Cj3sa0BJs/KymD09E7IrQwPzpqR5oSE6T7DuKUNJ0L5kQzTHbdFWwvcxJk1CXJ+Y5qjtfIxOTpQ4mAX4WhYAZBU9r1VO2ltm1VCv6mXoVctO3DGKwL/wExmXeeWH22tcXw8D29MYbzeAQ1xlZs+kun3/AmydVbGQZwYpyCyEG2UMVZJOmcJIZfcEKuv8Ouw57jzR1xlh1xycO5pcFENP+mLW39KIvqn1l/K+pAxu3J2/nYVwP5sPElLIqrFyXGDcbPpsTEnRB7Q8WgWSngcAlkIpgr2QIniul2Gd5xTZG6mJYcUp/lBpsw6s4RDRRoq1mUT56QkjodC0Ph9NxCVYA0W+bb7zPMzDRPIFF04llCv6AI0tq5KmENFE+7a114qxdasoOM9bNrJ/iSIBx188s2grPDwDG/En4eMG5/bL1chYK+qbefZd+FUjhYVVNcPW3O55aNNiJlyvhyKzkp5dr0SXluga/gVuvtDnYsq91CprcEMlCkKxWzf5FBCkU2qcgGZYj3Bwwj1KKAOCgCKvKGI5R9hoDwEV9IEpjbtTCAFCdRBaVKvQ2icxrkbAdD41kE+0uAJSLnTMELZ69COG9gBtN1sY1cuZMnyHcZUEE7j6QWwA49jRQPRglxRRyhCZMMyzYw2RA+b47ZAXolqqPuCyHtE0yci9ilNJBgyAD/XKiinyihWTSMEjd7nkF96lSb65a8apZCBi3VqbEmLG5tZWJXWj/wLRYM7bUqioyEiTu5ghFQP228keIzJsYWkYSQFGWyJQbRHWrfIi89EicOHOKV6zoiLeM2yId+cObUzgsUBc9PEXbK2aRrSQuFtSeukFgw40mJjk2wf4K2PMW3K5hv6kxpl7+2dKqR3IH+H4H4N/UeoC68BHhPNGmXJJCn4cVeaPqvsRyA5yX5G/1wpoPo1ct/4izvlTsEGg5NiZkefotpkg7b+W6Te5XNkAJ/vS2mLOXMO/f3EjYGpK6vAMsxNywBKrWR+yZTKBE20Cpaq2k0PrIpucAE9jSWDdhKGBtKsHJxd8suxSfpbJIRsidXFz3Bi6/XPjCYeohZDrmoVgMIS2Ev0JZOaS39lyD77YcJN87ErbDK2gnD67ffyLTq3LLeIjLX5/zTdLQi/pzFU+TC/n3IZwmJwGtM7JvX3+nCfRnL8Wx2inFiIC6sO3szfgJWTccZe1gTLkhd0xDkw/eX6/miVMEKOcnu984ouegDsyDzETwvWidT+PfO5wEwhYDdOYI3Py8YDcKkCBUA2VCiwBcWBwyxfv2Hb4Av25DXDq1iaOI9+5xqLQW+HDG4KoV94WzbMCLyMalmIAtJWa/Qnq0o6hAAcYkBzr6yAW5rroujF1t4k7h/WFmfvQyiicj0t0bGGvHeBmMKJDRleGtLHFkg8qNJwvKr7Apkws67rnkVmIFGMhh9EZheQq6XQelQq7Lg4E8wPuk4mgUrDEBeRY1BdqX2wAWprwYTYEmjEjqFW3ihoCvWfjir2JTretk4G+KD22yAOnz9WQly64wiDVTSckqYaJTVjrtcJHCaThUcjyU0EjT+MYQbw5wu0t34ErmRJsZCMx5P8gFl7d/xyf2NexZA64q3sDyYDTDKhoxjQH6XspV7EudUN95DXtysjwnOzUOcbtVnK5AOUd+mnLreRaQBtP3+fjd4xY0FrG0x8FRbqeoDNrzgU0GmrndhZgSupQGBwafc7BoLwMxvuw1qr2SuJD2gdP+VangGrZvA3Pr6mtWNm8hHx66r5Df+XJw/JDJEEPBVhZwhKF3dhpaq78tQF34GpHxNLPVn3hLy4mcmXdManGriC38UJqKPj2a7Mauv/aXlcrybLLQVCH752ZfacdnCib/Cg8FAseSqPf/CFW95g+dvJG7l0gOuvbZGNonnpZpEk+8xkPOGzxh7dNZ53DGkhogFz1e7qBBOz0xxIdN12sU7Jc196pomgM0AGHeMZLBiUpOTE2dgUa60DMys8hiyk74XhnS64/amKKYDJezPP7Nm27cPWa7crgqofCLfgNCNhgEeTaVtzBVfx/95aAA0moSmXUteypibJKuw8KqvSl3IWvduWw8A62wf5zHCgx0N5oBWEDjInrJOrT80fvQXXquKTarrOHbdP8YvByl09WyyGa0GrZgy1r1m9p9D3Xmh06NrKmQObXVf3mAqMW8suIJIeUnzSYozHg9xivlXxvKvIOCEGKzvGLSqxDCuutqgcdQMWbyxFR91P+QPzW3CA532vT4W/K8z1t5fxFPck/zpE6J7UTPx9WEhOL+mKLbm/nwUBZ53bPIGy6rJJGJbuRGG+J9znfdwCiiSn1ikjoyPS5Lc+y457qi5IjqaZurOhUxW/fwqV9zntzzue9dwgjuqnmY8K2fCJUmVRm+1xRZxcv6JabHua8Yy2ddNI/C5kuxUuGyViTg4cYpY+gepIdVH5WY7uO7yR1O2tSHSL3JpaoLETYFMdAiJPSDCVapWYadah0UmGMCVkSF7NRcU18G/U5EqAqJto5D1STEKg5UohI5U1JWjocnOZhmn1j0FbKHIE56JZ6drLqCSpwcdhYjQf71wSjv/iAP7Su+MTqcetuYbSXwXkFZER9++1K0YWoJPdvOfgb3ARVb/L5Qy10Y5qOKLgRnbTHWHuNS4owhQvAV+D6VOEb24aPzdjz3jqXheOTT5HqeWhcgD4r5YpoCA8BzU6A+SKrE8+r0ipcIdSEXKZ6tX+vu/+e8ms9fsLaxqX9vqWSgB2CbCFEOgB4Z7Wmfp1Ch/dqzpVWuF0UEvRenAQkdKmdcbo+MJbrkAp9RQIxBnamCOMLXiqHTDe0Y90WbgZN8htBZXlTNj+ShQX0wd6xaWHKUiEZL3AgMG3Wt0zWjopNYUOBzTsPfMmMiht8uVmWe3ZeIfHZUyv54ZiPNNwWuIgH+8b3yFaocmMcBMirEfUPddliuP6FbhAkWdjZOLPctQaUiwE73uAM+2r5m8pBGnh29oE0I3sThwRVBmfpHCMHgKDSe6W5DnB9hbRMZPV6+jTtFWxeJtF0BiLcBtZMc23NnFKCCyPSuvcyhAHpj8zbmWB1MsZAi2rZsfaHcKE+hSidvfh0lebL3GJKK8JcOzdbIhvVZIQDkDA9rVPETjkQWxTGiIwTPEpfajbn9ipDSR4N0CnDcpk/nG8E1RhgGWNp4HS7Woymg2x77Fse1sZNMKrT80Dtgqjlj8l+5nTc9yTjas1XIGNeOJBpgb47dAYC82wwFBYd9aCwKm2VPzG5jJUJVExU5nx8LgDv6pqAuIs8BsXXtnMG/Sd6aafb5kE+6ZJ2l7glVUVxUINow3nk5bVVzEZntIx9hwviJ+4XusFJfy5aw2qEbYFMLNj3tZ55+qvoqjxjpy7/0OdhxJseHAM8pP6s+3IVifRyoFwDURU7bBXxu5b6yfU9J+9uV9zXuFHSiahd5q+iQkI3K2u3OQvMULB9pinfYCzbtYLwAYOr97jDWdFt1P3tg1jyTxmTtevk23TC60nzDy3lXcXSyQ54Y+lWRzS0xZY+ibHO2XjKBhG/MpZwVQ9Y1xfTZ1bztM3hxcS5WtRUVMsj8njdmVO0XIm6Rcj59/bZhhNujFhhw+glGnXhV/W4LrT6LdqDe76bBQoyTXFUfBauwJteWJOKAj5fPS+Hi4FHizwjDCyyOrLTrYgHrZhAXO/CwV/8pwhSSxVq4fHsOJZnCeHYm/5E/SEly10GqVnvHPIZAdlWd1iObuLBUmRlmEGO4oXoxBcONAbYJs5mJQBlJiKXXE6UpiTDuWWSzAPnQmkumdPQkxBmkAB5LgLNHQVL7DrwunWUv7SvTx2YPepr+6Bf0w21KhIIJ0jqcfsoTJaBwUIJFsy/pmrT4jb0g/qK9usWKcfrxtPF6UEi3p7sPpAj/qjzHogJHx/9bhE4zjuY618Ev5jErCKZcu5Vm0imOpkjhiuBysHLJFnGyklfJNsiA7+CpEMYf4ZFzSMjlhs9Iyoybx2g3p5VJ9jzgtdFhjfrRwgwKde/XaWs+P+GJdI0WFVC80O2U1YozgV0LrIFeH74e0FnDZY33DRSrsZHfBiPakdJLGOxcRxnYf27ODKMA6WIgk/MPO24r2D7nJoTj49wAL79YPt1fgf2r/iwAfEh/ocRjzbZ/J5xDhjc7khlA47ieZeZIRetV3Bqnk/VvlC5NH6thD8mleOdKrwFDm8FuQrr+twdAV+C5RcueryLOKPnuwT9T+EpcNqJgrbePCsS6gHGASGCWmrARocKbuv/SD1vtf/mZnEgukn2MJxK90JSegveeH5vuCoCIhLnt79HRtNKCecs9JNbV7LvWlEdJPKg9lUxNULB5K2Ylb2jFfF58APdWFV8K65q4YX73SlHxvsxIESWaf7en3kfZ5zyavdleLN56+EY4EqHtbzSu81+M+eYnlv0Kt8uJoSSAW37hhstVQzZX4GVf2FxGrPaZyup6qx6Y/20wnyp1b5DrBRNueBFt9lB8wTvEl3j9tkNUkEdkGouL+wYneA2drKS+d2j6RAuNTGtTGKGJa1rOaYQpwRs2/ajBr+yDunGN8XrWs4wkq6YIsp7ny1Ob2d0z+0ugn2Pzv3DnSAoTN/1p0AosixBm7Cf6vYzSU88xgLYrKkSf+43BksGhwm5RC9OKyh5IGlIsappGPn3FjREfBFVxfDlG1iLDor78pAaVKd49UPCHCmtjWQWKlatKZU2bsVHb9yQXc6PUWBcG3tGXG06m0mPK7yRXDJTZknyJDGwp8fsU5BboYuOGFDaQoepNQXbwEdBhwy/F8msUa4XfN+Cl3NLjZgfCaoRq3X0JWOypmz9cjbsCvG3h80IUkuc57ov8iYbUimN5POiJ8KSacccM4yIZCuCOH9rVZwuDjVfNp3ORhJ8vEfqa8UetstFmo/XEFyh81+fAx6+wYopZRbfvWruZchlv/GswQBdhASBaS5m4idzeoT+IbwISls1KiOiBRshNyTrUrUuVCmGc6lqYCYNOZ/m7oYUK/vHI4Si66/yHgZXKrj0Fc+K0P/iL3svvxoCl6e/LQwymbrnwVCXc89Xxh3bloit8EwyzxJr86AfrHOHG52+zH7+j9Sy9lgnHtwm86pQhZ/m9Wg+ofzDQegd1DCaWwFNujGyFzPXPnyTF8ZBc2lvePYKbJVVWf0MnV1ITXo9KeEja0r2xxQ/gmWUfPb+o2y8vj8aW1g6bOilXb/vB0t1jhd6wa3PpaFRwgdhCeFPFwEAwiUvgYeosEZFDMcmrH8MyytEHR03JEFTFbzqedbyral4PvlrXG1uEKVhfyTRh4/rn3EMepHdrOuDV+Ky2wYOGWgU5vNKH/LcALu2ihObZQ3fnSGbRUdQgpNpfRroNL2efiPsMLFX7FOtMSVxMGGh3oOlVTzYBKK+Ap7ggOhBCJSsQ+btSt3wq/9cAEEihaM61UujEP4UAuNM94jOTk3bzkM28gHCKO8sFXzQ4FBHfIdxz+Grra4iOUOLBF2+WQigs2kIAelGvG9lyTrEdVBSpISKDZsHz4u3DmkgqTYhhsMyn2+TP9Wgpd/+lhZKmwbY1GOMHDBCYiMl5bJ2dgUXEfcIMzwjjLXpkVlQbVsED2gQDN6896kumziR3GLRMNMOmPwyeGsGL62q1VlOuT5c26410MbQamggG5MA2Bw/Cu7iUd5vdg/QvpBXIw4ge+OvaSyhI1sdtoJxHRd3A5IBzTpeDPDfdDxfNVsofHc5Tm01AE0MpIyRAW+LXDSgra98HTrJ4Xfd2eKo3H6Er00cSt9uGAUsibtV+fn8YMM4RlXDCpkIVszYYiY/E1gtKz+1Cq1CR8kAbWaZ2mMY0w4332vaKP35yCR15jNj1bwd3K8K9R6sSPggqsUvDY3XhjnsxhT/A/CatibNhV3DwYqhY4bXCt8FeaJHiqPcFldHpKt6+LJPMYAlBEXWmZ94ZGojrNQ/VHAOykE6QejareGH+6wUhFOJw8VqCysnTDsM72dnAFioUdW5NgY+A5F6AWc9CbQvURchnnB6Gek0F//EE33iOJHwK6GRp1WL+HP9KP+ktS4RhvU14Ewk0GZZy/RN9eHXkZoMqvg4xMrBXj8DD9YqTd9KzkYIDFhdsVrcIkcDwbO1D7WpYQb1fkNmongu8PI6RLR9EKD2Gvvm1njSZuOJ1rInPs/DIMNZuvuC6UqTaHu4SdZ87TeGa9Wi+gx5+6VJ03IXMqbTrBPHLers8Hi9am9fIPNl+qsCxkmTMVRDLuWu/s5dVjxmfhNWn4OXQsetyrUs7N73N9P7TNPSTK6PsPL9IX/MxRrExRTyfOoyBhOQgRShEaE+joz7gSCbhYHQxBTeSQ6ij3zLenVicSmu+q6bwP1UcC1puHm/p0vjy6WqUdK6oCAfZ+STRgaagGesCDYV2k2gb1mvpp1S1a7K6+3Z7tqileexyvBup+K06aYkvQlPNyh1deJdm8e7bJftkxDApiCK3lVyUyU5xbuFC90+M1Kg1g/ntPo3lQNgMAq3mUlqCA6h8wFtpPw5m0PfZMfh//PonwS8nQET3dm5rvB6EFvQn6LE/TcOTgKw9aWdRmiShK1JzBK8lueJg/CJ7BiDlD+RUwHodLsZN6ILdrL2D/fnBjcABwDWh3Ah09C5krOyR5Ld4G4B9i5XsUf6gHCKQo+wUgqOGXSt1WQtUvB0ibBdxD8QAAAAA==',
  'xhttp-stream-one':'data:image/webp;base64,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',
  'vmess-ws':'data:image/webp;base64,UklGRk5fAABXRUJQVlA4WAoAAAAQAAAA7wAA7wAAQUxQSEcmAAAB9yckSPD/eGtEpOYTECNbqUN5LwJeJP0XrMn7VBDR/wkY/3HjfSdgwBh7+tsACqgCKnP8Is4soepXTowxSAb374wxtoEgfweYG0BnhBnnGGYftuE1IqIbsC+2ZZ8yE8B6IbeZTdJIRmAlEPEStHdyzohs4HmeGyXtN5KR2d25vshgZkGyyJmre/Gy96GilR1Vc86n+yZJm2lcmXRnVWV2q28tc1aRmWlGkpltN7KeSQEXnwA5kWa6nZLc/XBIk3YhSTXJKrlb+pyAtrdqXXTerqiq+tDS8jmn4ZOeFxeXryDp050EUCbNG/k8a4GnOwBsmbRvmYHt7hLJY+oxSWuMcXTvLo8omC8DZGYa98yMzETluXe3JLOXMRQRAUREA0Bd8DYG1wUNd/cj88tYkbAAUH79yS8zHLSNJEmpCn/U3T33IIiICfAf0SQKyN0bUAHpTp9FBOl3WgHK2ilPbQFKK7QW3phGZgu+gJrdMi8Ak0TFJGl7AZiIrBqVPpiIB2a6dQjWrjDiWoxFprSFsaMBcZxeYOSxFOANvETAJKodCiCVXZPOhU8lsS3gcOkqGHtkkRZa5C1JAJFOCgksDgGElrYal24RQEHAyAL6UBAwAbrASGQ3iQidgGiSoCYRerOrWZXB1nZMlbWfHsW29k99S5JkSZJkW0j1/988/KBqZh65er1HxARotm1blSRJWvvc956IKKuaGpuDOQZ5UGYWU5OZ6z+qzdVlph4zMyczO0OQMSiTyLv37IaYR8PsByJiAuQ2kiRJkvnpr3MSPbtbT8/RETEBeG3bdm23UR/7Qt4rlKoqr///He9N5v07MzjnAiWAsVpETIDfG7ZXSVK9Srv+51/+j+8/nbeKop3XVpNGva5rNl3aLmytrctijaOj09Iuy1qPLyb2qkrTpVSp/tAtsW5NkqrTn//GP/q/Pulqq5gcW8006fy4tnncbGvNmljmY67Nml/P27pUXuaxX5S6IMnbhENeoauxmKbTtrM1t4Qkr+2iWduYc5p7s4ferGUeh71Zb0JKWsf8T025LkQrKhF0U+GwRU3bxrZdN9rYNKa9eB0Ea+0YdlkPvj5guc5I3Yd2ecwOObK6IATIajYYUr7mDVdznbd7g0xzX66xLMwPU0Ko5swrBqGbViSCCAFSwhJGXnYfa3b5h9fsYDI/vuS+NfOqUVjIzWyu5crMwojdmO/rtv7W49zuIkvrKtFyzZLnyUyX1mAzf5mlTL+YyOFRksW3vQxahBhtmomH1LEfpaCYGGmcX5HlvYacoSXPe1BbHuf3QUZC48qEFuU9m26rZRpMrDXI8uM1uUzk4mhHryGPJc/NZ3YVpd8sitDU3FWqRaGbemhvNDLCGpn3+dmUM9E9Rax6zRbLOhDRmkyTMTnXu+W+cm/KxeVZb4bwlMk9O5bHCNGbMPHogdsSerEYeRu7YGi0ghU9jOVc8mN3Kco3bLoh5zoaeayUMejhf2ek79DkfdYaGqljJFFa7uvRW8g3bT39upJz7uuicmp77lFfA2H9irzu6f+/aR0LE5bl68N0UP8lLYuRhUb0Kfec2wl9IURyXbrKx9ynXtW3RnZAmxb3eq/zh9slr7N9G4xyzet31NDQpaPeyFynI58jOnJmc32p93mMfN3aJTsmejWRl9lcvn970g/OYe45e1M+bvvfzG9Du5353Cv9pv+enH3IvUvHtVvH80q/6VNfqBOK9Iuv08OvK0g+tqJHIX0pofuOPNxehx7m8b0/JJXnyOrIl09Rr/J+0KeVR13ys6iiX/QtiuTzXp04JXLvZ0SiH3zNUtGbnvbvhOQ5W2tNfYnI8TKfpwMoZzdaE0oe6Z2qLxAlerEeeji003OerXmW+P+TJz39v1ryPjtTyXNI+YIpiTqy3kTmVz21oi/b87Lc9Hq5LjQleW7y/74+/ftvJpoY756PCbm3oPVOXtKelB7f1atupUVd7oPqtUIL08PH3EPWgwDO2pjrgn5TO8JYfRnKePXkL3Pt0tqBLKTUdZaJkOte0BGsIK3oIARBL9a6JmghCklCgLqMTUsp0btgxRFacE/m3bxWWNLxtSRVEULgmfdZedltLXkezxapmMfGe9cSlC6RduTUOZGJiN7FmEqCjo7IP32E3fRK0U/tKXW49iDdXuek7VdvzBZ3P/u3Lk2zlCTFg770t/RQZTP2eONIHpvWaHnsJp4h0DJRBs1+3W//0u7gJz/8bz9uSaZtgZCQWK66ZeOyLCwYRct458FeWMtERsj6PCGhIvXdzh/+Azd7yxp/9u/8cktnYoyEQMY8N5tHT9OgZWbeqIWcLZPnFnkMSwgFEVaxYnr9T/7BLQlw1p/9K99uzQmgZyFQnZXnWsayJsEYSr5j0wO3FkIQCiEUKNZe+vJv+/WbnUDG7ez///TDg6MzsjZFKECBohJJwn71cnLGlpfuS7j1xLFAEmG6bjKdTtd2XvnSO69sEkZecvP58cH+49u7U5pFRISEpM94tp+tI5hG2XdT3ie61UqrnUAo+s0bN29e3tnZ2t7eWi01w2BhsK2IyLfeeuvNV65sTjs7Cg7VeVdoxz4tz0XupfdpHjuSlPPicBadlLPN3StvfPWN62t9CdlNFJbN92lMmW3deuOdr759a7Ne0EWvXkmjlGF029PHecyr7yHH6XVeiqNXu2Yvf+HtW7dubhcSLJeQZFnPkkEAcqbdr+3euv1Sfzq606Glj8x9LL/N216nPYUAsqTSlS5kU1DExitf/uoru6uznlWydAw93I/0eMSwubs1ZB62EPCMQCAQGFh1naa9znQrCZBCodZPpQ6pla2Xv/y1N66sdBKEYkcIppHljHV1ghL2+s3r4+F5SiAitIxAEtK65Tsz6Vasi8qEBeH+9juvdk8+/V6d3fzKN7+wO0mCUAhprc94bN5OHSSFiY1r11bzbA5SiQgJmWdWtk63QnchPxwJCUlXf9vvfmOl1Pd/WK9/4drMNQYsQViNYwUZDdpt1gIkKIqVa7c2zk9bV0qUrgieUQ4dubzzaDu6hO5WoJW3b287Qz6PSVgUGVlCCDWJ0aB5fSQUYNOF++0rQ7l0+/Wrm6Io7SUV2lbqouQoXxc0TnRIv+gVAozkkB0sOZZEQxhN9iYCZCBEiFjZeee3/ZZvfnW3XYxjxc9AtAvj2khJKXsIKitST3/hwoRUbLTEsnhmQQjTIOcuIyQBSEgSlZWNtdW1zfWVe0fVSClD2lddljI/bXPT//iFWdUygAwyywJET43mOdaDtMTnWgJJJkLSm+P7F2mkIKRN9+acNaFb72S7WXt/996kcYyOVJSoJGVKkhhBx9IulVBmXK7tL07nKBS5r8Ga1pJ01GWJIlkeW3RDllv/7p+6MySdE1SuKRQZBsUShh2xjkqUWBu0o/uolCMWc5+3T1V0T3JZvs49A2SS+vBvPegak5V83VzHnJNrHjcvE2RrjHTyvaqQRPbEnr7OPUrJLxPDyDhd7+11oCmfmVRSDOaH6dAtisp965b93gF83jyt23TVgy7oklsPvUiUME5yPH84gqSk+0VxlCQvi26PQUg46NYg+o2nC8lj3jBr3h49qMM6Ujph5mUeS4TsdI5yGs7NtRoa83KXc3tK0NHtM7dG8qX1swLRupb1wFQSk4rMYddSioJeRArSNp6sKwNk993mPJh0GbvMUE/sOJO3yxhbXF+vGrVjFhlrpFDEuDNUqdA85iwnhQxeKWKJRZAqut3LGeRjVKTo3eNMQv3tdb+c7q5anMug+u8gke4oJNce9gS2TJBHraAJUa1GRcRGrLn26m30H+kpVgCxevP9T3sjgSUgMDayiUBIiaALzpJfho0wQHl6r7ixNfcgI1xDhnn4Osx9Y15m7VbV35j814OQkCxZIEMT6YKeffuW41sTQgQYq3x7P0yh3QiJBBPRj86lQz43IklNXuf/VRljhEMEdjOthDokTqpI3aBfWLWkAPeXty5GY+65J0E8ueTXiZDfy2Gt/6HHvzA2dytDKmvDxjmOzaVTRBDT5Lm5wIdCOKCum5QyvfbyBpC2qw3GaIqax21GvxnHOfvJbiKkG79bOem6Mkm1sdVxvDg9PDg5u5gMnRVRTlZMyn3nsCPFZH17Z3t32kca47J7MOW+vM0f5m36BQgUol7/yqrb+VlWbGzn4uzi5ORopVeko7zKGGPuix4ku1u/snuFp4KlYjEvI+hh/cG/KpY9OWu2WhrjJO3MltvrU2eGzquQoS7RQ3vB41yru6vMWyaGmebNnsR8F04IWQBRcXMSYCsz02aysn11Necc27lc08j1MbONa732jd/4xe2fYbHYC7uZRR82+5auSzIix0WWSEoXVQqhpOtm1290j6IrQvZR2bfRQxBjfMFXf82t7ZU6uUezy8JUNKiSx+6JQiI4enpx6n4oXQxDFwo6o/DarVdvrSpxVt2/kccEScb55dfXJ6VzKE3H25Cjyq/HvQsSQvPPHiYOaShlMpl0vYIS0XJ25bVXJmd1HE91XN/U88Ys/NJqNxE50jJVUxfMd2ruMqQePK6i1ky1RjfMVgYpAtLafG3rwenF1vGthaBXnWpVioiTkNRmjO1G9R5TCgLI+dOjzJQYG3UhldnaFIcgzI3pp6cyPr6pRiv06f/OI6SQziIE2aLch/Nal6sECndr746N2iqqqKXVD6srnQWh8Xr92PjGEulYnX/+1sOuKEKOJii572Gr06hFugCSS3y1/nAu6nx0dUtslxi2tkpKlvzS449Tp//7lu7bTh3/9mgeREgkbytDZjY2nrNoloyxegmxrLL+6/b+b20tqzLdamtN7i9vhsAwXOL1Ov3vN5UxEkT1T15Ob/Uo8zhcMHL2ZdovomW2o1KsvpEnZ+dnpHHLWmtrbbqz4kQR2vrNG7PJ0PFCryDZ9ol+/JFEejJ5n0swzNfoRS9Cax5DktfXntSxGtyoma21ea6uNhtD+XVvTGZ9/4Ls9jhbcH62ceZLY78Z8nlm7MXeZfGQ+4y29k8ybYjmzJaM864f03ZSr31jbTbEC9ItJDA+YmrbIoxCfpr5bX4dbXkpaZgsAi+LJFvLRXaLBogsX74UfXlB7g3mcC6e9N11CaEsrQ0L9qqLsfamh6JF74PIq5NWmq3Ekc6WtWluCEG98VI3dC9QzzJif7HCfd62hJAzZrfcS+vNqoTs7IENwybFzQ6TzlRrtLGVkBNWbnXdC9LBPNpaHFyd4cJ+R/RAyy4vN/bmPjvns7fXOM4kBbZTWZ3qQzbS5qSLF6CCpgS5HJSbVrfeLA1zy7Js70q9yTZ/3OhYE0Ldlr87uskIk64Vl6HIoLLaR3nuco2iuBw6vjxxRO3F2BcwGqyI0qvPQy/6DWnOme3jf//kg9O0JCDJHIGuCxlcwnre8jph7nNrR73YsFst6GkZzA6D+LZXX38y1xtb9HHps/1FSpEio45uUQZAMT8t+Hl7jFTS5LW3h65EIt2GDGsSGhR5u9mLHnaMvfhtl/sM9cN3+u8djGlhnLR5qCu4pETz89VDhKhCvrVJQamwo0ioIkW3x7rE8sOOr13q1X07mIrpbX9vPgqlo5Etuw7j4r5rPF/Wkcc6pe3k0rUWEZF7GGweB5l7Cs25y/YDti/d3tYDYVSturHz6Gl1GKxMq4CVuM+az1neFhX/dXgJie93JPfNY4zGxRmN+Wl27OmH2cPaMWYUa4tHFxVkIF0UzRlWOV84n6+XtSTpn+osQxLUgXJOUqHIfbBYheWnU0fr1q2H2NNjkqCPp0/ASgKcHWmw6pF5EXI/TlT/9bdbA0Iog5zRCXIvnxtVKLMfLJttejhDOsgZxpwpgI+eNCnDyJTCopVEh3syL7ICqXt8+IsRdNFxLeg2524Ik7NvQT6OPTxz5n2ueZz157UYAcTpBSYUPOVyfUGSkkJ0n7Uf7FRHygySYDlbrj0FxfrFvG669fhrl3tIoL4b04REhk6qDOHyeNiwXoB5bFaUvn3gTyi55rGFfF11kZAqH6eOIi3/cghr1p8nKljuz5tAJcaH6zPKCxA2HUGZHX8cioKV5+WxV20eIzljvcjrZJeOQdCdrhkUUkQWJKkcH1xxiRfgPgWKydPHZWPe7rZpD2MvXs/rYsfQq+1hbwY7GCfFIatomHQFJGZ3x2vo+YmOkHuoXPqBr13WkjV5mbnn3iXSrfMSmY5Il4imo0VnbwpL2ttV18IRXTedggld+uDSeinPj9pxjkXRzd/xR3/tGkmEdCN1IIwqkmvOpBU5t3mslLJjG/ZGFlnqyU6h1EIM0+xLhDS5dPe1SQk9N6Unc03q3/n6thvDzPPYvJ7r/Dq5zttCTcz39eG7Yxo0ExnD0B0pROT6sPpSUZTn6fXOzjnPa5OM4HGNTKStHnTpqadQ7qs3U+4p7dVo+xPHuPtrPrjfl/D54d4CLcfG/I9/ovbVqBexdH9cjcIzR0oqDEKio/zweBmsp7PbfM3UnwjVjclF7eWLvRM/w2sl/+hydr6acg9S10cXnRCSGLKcWVHOfN1DevUysmAexzAZy2Z/kJLuX748n/WeHy0Ag/px+r2101fXDnz6+NUKYI8t13ahLfeEsNsPexF52WREgy1MNPaLWZg6dT+ddnl+2hrYLufd2mXyteYpzYofPZK1TB5TRnp8o61belPaCxI9IMgiGrXB9K7bcveUKIMX84XTUsY431g5V8fX24PBGf7bHWzk+ZzHtRQ3bJdrt5C3+e08B3Vk764NlBGli6jzrMaJYuxn05X6+jqW63v/4VedNrCn5NxYEeopz9nDvvy6y+Zx5KcxsQPPCI2j7ZQdi9p1/aeTfH33y/r3/2FhG2m7jNQQUa5Ps0teVn82NiEM+ZouKEROp+R0JoFQ8/npfGz63qn21dgtQvbhj9a/QUioWx6TIdaQl11YupH2vNxx3wdaGjSc69P1+k0fERhFPwh1neLfKenmCNeH9n7iza8h3iZpTFZrOddalz1YbtOsGHbZYnm5YZa9uIcR+uHPflZKdJ0iorVml0CnZHT01HVRHix+Ta948/nlzOS+Sw9lF9mezyGmhx3ZDaM+/fBTRJShDLNFnVcTwdAZ5L5bCdLstRlRPbSM5drkH2w/qUsdv23yNq93lnVeKFS6tcmYmZbi37/qkOV1okFMb68RIQxBpLyd1rEPufaXyd/n7OGHOSUUsb4tUFGE4JSvtyRE//oG3/dsebsuaz5vb/Kn/W6IfVtPJAjNrq4VhUoJQeOE1LA3RAq6N9ee1UNjdTSP09zHxozlrC+LXuxVe5rmL6cIwXDz5kpXFBGlSDpkzo6gpCOFXr5EvM6755u3c7ZF0YrdoN9E6sFv1+baj4qAc/OtV9a6EhEogo6oktdBXaDT+2mPkHZMRw+TjntTcg/Jx/IYoUt7SDF/uBQiWtl966WVPuecYsgJ7juGbTaReb5XpV3uM78sr0N+vRaL9ebHQ7/ZYTAyEbHx0tWV0lU6ebZPu3VcQ2MzHo22Np/fq7NLUIR+ERK82NEP/rBDCInIcTHd2lia6Yj+HcAu1477ENmO5lJy70p6GHqIyuNPKGfpUvLLQvaT3UDy4uTgyH3XyWybjx3xfTA27WhBbnswqAibGOqSvbgua2ixdltBrvvByjl7M+YubC/2Hj98dHjegM08jmP3NMSIoO5dwGQYOs6pNtRKR34eknslKegbSWSXbTe7TCIW+/tHB0fz1oxvs2R0yMswYjPm6SmwQe6hsuRMVuV9KR15HyW/73LtghYJUXJj7aLmohGBeR5ySHtqrmMhdHIsu2+WtMGQ6kAeeyFy791Zfj8rJc/Lfc65K198BQlKVwoKte3oy+phoaeFFRdn6/EgZpSIPJf0N+cvVk8YYmF8cTIwfMzUJmPKoZWPFTekOD9enT00n1dFUp7oTZTmuIVFb3RUwTo97/ryfx+XMKhTwnoRRkyEfPF0e0J2bZftNjik6MVzqoj53bSPybRLI9Y0wrFXZ0XX3DM+dsSZl0PMfSBZ7K1Mc89ztyjSpfauy1nk99m+GFWXc4RYEHe6TcWQ8rFNPQx7gyqChfWgbA81a5ZtuVeJg9qXx5y/Jjb3aZlEEfODlUlwbTkIIzvTLfQmmVNsZImLg9VZY2I02JMhKX9Yv0insCzk2rQ8t/7w0bVJ0K5FIWmHuTavC9LjSVTXfs0np+WxeZ9QHUXsF6+PwfL88Dwh3Tu90StMIQZ7liqrV6g6dU6fXu7Z/O1790+XosXeLOQ5lrPfXdvoknvy4cZViEIbkb3NWV5HSKHoSjcMqztffUOVKfSfvJy8TOV5W/tKegWrh6Y7/PSV9VZACZXdXb6noogo3TBM19643eNEd3nbvM6tQl43S6FwdQ+Obkp8v+PaBQIp+m5647XpYMPmvjdjvUGYf3ta1rfimMOle92usRKRaxthGUU3Xbs1JUZTxz2b3SyvkmT6ZyZZXXoqIUGrPvx4faVJOBVz/p5kEiFFN1xfN4wJdUO5F/UCidAZlVrlFV1SSWy+t9UjESk3T+6pMlm9fkUR9XQUZrfULvd8rVxa0DdTVkUvkpdR5OGsdyD1rXSUewIp1q/eCqPjx2NmCY3+u03Sq2bz43wvf6wX5DnoVnKXKmLplG8/GC+Ga73Vph/+z30+GpvPy9e871dve/CnnyfXmKzkaMJiqr6JHSMsC9Ha4nDYsKLv3/u7//DhJJGQ1NNovtfe3Hs3+Xv77l0BRuFf+w1JQjarpx3UEZAFBfms7nYOrT7+7Kf+4p++J8km8+Jc7dabH96mR7nHkp5NfO0VByK9X3XOPRMWQV9Ku7Iq5XD43f0n7/2l//lp2iDT05wf2g+u+UALltdfCsayxeWZQhbsaeTwIlwcpQwr2r6UyuDu8bg4//bxh6etZtpovVgryhD2k8n0+HWL1m1xsJ2082kEEozdEmY27AeP0ambdGXXRE6PjrNlPWoMXUt7IvciUVZy3w+Kcn1OS7jU1VCwPHbRodaZfcggFFFiOItpjdbHcUHZarJyKUCG1uWcx2zyfjoWzVHrB5VnjSvnJUCI2RhyH2aV+TgB1BXJ+9OkW6xGNxSUTSPbA7ZKnqbssmHLviUc9dtRsuUcpx9SAonPTS+iZb8VSko5HScZw9bV1bVZB6TitKyHmJHXI0wUPSyYkjddsI5rIXvU/v/qQkAsZcg9Naf0kMiOvRUounJ5XqQCijLuT3pMt44dEUSuXZaZknpz4fLYTUT0J+3Ny987ZYIqz+Xg3C2GxfkGQrvbDpYNcXwYopsS/nNOftywQr+oVZkl0QN9Pjrd2HwlJuUx+dgxQ+DmjqEz7ndW1cASCurTY2lyUib3xD41cj+86KfTMze1q/3j2k9f+dIxRnv2IVngYFpseXV7loEhBTA/VEmCysvok9xLOr53mILQ1zeP3A3nJOtdqE2vYwZKR04roN21SWVZ1ZDtpM0+uQd7sfx40CW7pU+n576NV97pxlS38rYLzeMhgwDMxVYYxY3V0irgtFtr7eLR4idizWS3yX4wIo9Lx+Jh1q0hskuX12ptKaMvYmrXNrtIBgad7ETi7uXpxEVBZrbaaquH9z/9aLnPyo78Nlujm8taMdc2MNhcW81FqxVmsz10bBuhbJ77TIJGPdpRs7svX1nphqELnLah+emf/epYixgU+gVauSbf+yGycwzDh7+ORbUMSsHck+tMm7TLo40wxUDrL8npHN1kAOX4eNIbkI7ffV7O2lgvci739WJ98YQINh/898c1nSbn6kG6aNvrgTGLhYytna5iWqVZgrAO2uYSY7bPaL8gdLsHb655XL6uVzNOxGzlwUdwcp28n9wozvfAQd7YOs9Isho5RKgebg9IyqiHlvUb5h4RuffweV2W13MXYvvwVMk5hfI5dcC67Ulm/GQMu6ubb97rrJajkZAK5YJNGyUlTN72pSSZjbWOv19vbBuGYXEksxEx9WqFOaDd2ADs8sGHvcVQ3jk57k06SYgilWGx0rEcNi1oD3s3c99EqB09LUyXifUTdtbDPZSlSmKeJyxo1zlENs5F3f/hk7CKtm4d107ZLCkCRT8bNE1oUP44IUFoSB7DMh0sn4e5Wp3f+VYLS6tTyNusSdneIpgJ2+28fvirYblj+8qpuy5TIfUqTGfbGxNSSKxlWb95ngyW88XbxfLra6m99w5L0HWZmerdGcy+eRwssi7mp09+4iBG0bF5ZRxLb0Ovoes3d67dWKsOY9JosRf7NmwN/uAPZ+vy8S8/aIjDpDAfm7/d0/PgrDBO1t9OyYBKXpw9OTytlijTrRlnJ1uHkDPooT4NxWKt47fL+jYE0PIX/u2wsbDdbMzLsYvUjp56SKgybo9eefmiCKyysr565+GToyqjfnNzCIVbhBb59SgkJJ/Xg+X7IMktP/x30+3Rn+Nal1JHMfaHdmGUUWL+4NWrFSxL3Wo7PXhyMK8LM1nb7DtptLlHDz11iYE8Vr16Xn5utzs/trG7IGtizHydj6UNu/wwnDjz8O7OtUiLCKziupjP6+joytBlWOlhLz6PceaL9WaThPZ/+snORdjGzHydmGJPl8l6yI7SZCan98fdGcsKpU3aTokSKSHW0cMeesqx64Z120jE4YcPs0YzmOf15rlN98zLLVV8ABZPH67NBtmoWLaNHUJBZkYej8kuLwdzxsc9QFFWPv1Ws4FmPj9vYxUjtGl6c4/lLuyD+ck8+i6EAOECkqwaYR1BQftAti+LdUxeDprtHNkJYNBtPpQhU9rFbntYiRF2Zq05Pzo+Ost+vbPdUKVAymTMnDteDmM3zMyOfRhaXq5pD5tNvvVrCpAAxjEvJ2mrIiKt6eExg2MNSTqdXtT9p0cXZXV7Z30yCXWh4khZGFukbUCRhYjISoKOz6VegcAgy8IYbr+Wkm1OIXqIKoJSyqqXa2w6iJll222s4azn5/v7x+cxW1ldW1nfmA7CthX9VMnnh8okTaOUs9GHnM0eEtmAQFiJKW+uzW3PIGbeT9YpYllPxnLPmWVnG5HTrpD15OxicTGZTCdDV0oBlf7yGyWXxBfma85Y9rQbus0MGwGyhVzb5HLaxtPn7ynX5LFt13aRLhbYSa2y7SS7zDGLSgSlOBB5vD4EVhBjupYl69aRkDPnkOuoI7YLpbBopdRwq4s2Lmw7SrrN2wiRlHLm1i7PMigzSTvdslHDqigignCTsp199ii6kNBZbWJYFAS5Zu2IYCF2bCENkDnoQU6Gcvidzx5XbDNmOiJsS/IYpPbNuac8mhTNdmYanLKkCCMMTccfqutBYHJtU3Iu14frMDvCmM2la6612gANn/7Ln7vy6vXZvf/+/rGXb8k8bsN8Lw4453UWYCNjlInSiZNwhIVVnKX1n+XWrAm5rst2uZ319DlfZ7baPv6n1kXXD/l///q7iq1tH7x72Fga83bzl+mUjwlAyBYG2WC7pCQLAZaVT/ZWti2w2IxOoUvCeiGiyyzY2PW/2cq0e/hv/9mjSDenqw1CiB7a/kJybPU0Lde2YZiZzdbFztSGq+vIAokEg2SQCVvLvfXQPO/BMrZInLk4z9LFkx//6dsv/fp/eO3sZIZgIjvLyZfl/mAh5HFlkyPPF5vryiKnpCCXQAZZaF00Yb0JhsEkJK6ta3H6s/+/f/N2t2OLDXlZ2R0dUyL3XFus286SXFgOHk9P1/uxy2FGarAAAQgDyX0exIIRsDFGbvLF2a/+5OL1t6bIouuMEDoOjM5RXndBS0SkjVkCeXF87+H9WJtOLm1v9koLybLB0uySirHNEEHShMnsOLzzUz/bv/769lwh52qamXN7aNfzJHq3LM8hYmyYpN0uDu59q5TpbP3aq2+VIQxh2wnmGuRxc4+QWcjgSXf83o//8N3T2ztjCpf2WmZPCJ2xuCVkPT12C/J6ZGTmuDjZj75XN9u49cv35haZyLKhAwcy1hytQqaJ0vbv/MLPffhwESY7LPzqqh2G3c7cuybyIVnLZSELYTKdbZwvFIYo/X/7L//n3YvZZOLWGhhLcs8wCGZKrraDz37uJ375QetQOgIFAbV2IO96FUKjh+eWBdkMJptNa7WNgpTQnV/9P//yX/7/T+ZrQ6Eu0rMcLdiMy2br9bF/571fee/jxxfquHDKICmkCeca8z9yh1JK3V7mZZ7nujJU55y+/+s/+uzeaVMXLQEVWUYGA8JKRfN4+L13f/LnvnOioei6XDZdTZsxtnnf20TOqPIlstYhsmLWWA69Trn30Ycff3o8mZYSARLIGIuWoslH3/vk408/vnuYXThJ29pomUF+WPvqqK/RsKe3mTTdtGGcw8mJnO9995NPv/to72hk0gth2Tj7ena6/8n773/v0WkmdnViXDDv59ebsjVtu45+QQmJjCGllFEpWuzd+eiDT79zfnWKwNhZPrrz6MFe7Kei0LKm00tbhsWa+7B/aHM5Mtpv6CYsukReC4GkMgylnjx68uo3usDO5sX/+/lY2710xbQEN7clsvHw+WP07uacWu1X06HFPCaOo2VsBPbsy9eGIOHi/3z88vWtVWomiZyZiTHzuC+45nUt6l1118v1hdLydkLr7EBCoCKc6fR0OnB2/x/PX7kSpGXbmHTiJcxnT92+rmk+5q4d67K+LGitNfc4GssGQZJmPDu6/97//kf/4PaWERgbY2wb4+bzJ4/bq1k5/+g5opPK3tFB8xhlLf/nfm3X63z6wSf/u+/vtLTBCM3H1Yv0YqL+ho44vUrRK12ua2JpEcdmtq3OeZ19nO/lYNbaDEvvmrf5ONb0Rjp9z7TMtYmbHezaFRU5KYPj68jX3eaHxXnh8JvvjZbbuXuLpiRYc+5pCH25l1qWNy6d7K8eW9blPtEIreaxnvLrHTTfJsrjXk2Y3l3bEfnCxrLM4/zxIl82JcssbDdpstaxnl4+tHea9/Pn5RvnOJezbiuYe36xlvu6fWn6s5VqVdQr6YecuS9iedn6cs9Ync0p2RlvBQkF7c3X7NvOTQmbXjxysUuCTB+w362H9TA2pprs761Q3iYtLV/zry7UspBQaIPe62MjzU9n7NW0Yik7E2IeXzh691g/ui4LE0bv1uTADF/q8M3m9+8EAFZQOCDgOAAAUKEAnQEq8ADwAD5ZIo5FI6IhGYzm5DgFhLY3caAMEa/juMBeAIEB/APwA/YD+m6oB+AD+AfgBahyP/S/xA7RLJvcfx5/of67/KLXP8J/a/8j/k/7l/5v9t8t+lnr/yuOe/+B/jP3Z/vHzg/z//a9iX9R/yn/V9wP9Rf9F/a/8p/0f8N8Xn7He6r/B/7z/k+wj+if2j/lf6L96/mL/4H/J/2nuv/vH/D/43uB/0v+uf7/2xf9f7EX+c/6H//9wj+cf337//jM/8v+8/f/6NP7N/uP/h/ov+R///oM/oH9k/7v5+f8r6AP+v6gH/U9ij+AfvP7n/XH+xfh74R/7bwd8pfvf6Q9UvF32qamvzj8df1P8b6X98vyp1CPzL+k/7P0u4POo/oEe7X2v/keI9qj+JPYA/Wj/r+tnep/h/997AH9A/wf/t/zfu2f3P/w/2/no+sv/l/sPgI/nX9t/7n7Me+97Lf3E/+Hup/s1/53cuJLiVf4Ls5vO6bel9Sc5+JRye1UEF8+d9RS0uRJA109a6RomqQezi4JGjAy60Bb7nfE61PR7hfP0HHjc92m7HLeUZCvbLUaAGy61uNy+gdzMkg3vCdjhABl3HFyVOJkx/re+QguifG5VMPV7nveZ4gqLe8nmVw9ln93RyScnr0IIeMAjPdyiIlQw1Ky6uJYHrFpLBQsD+RotwD4ibh7b9TCSyomLsz9gmQGdo4vfw7EPjJBiGnmhq5SsHt8BZ9B/DQwj+vCor9wZiK5d9JRGMZm/tH4xr/AwnPm7bOUF9Fu5Xfi0mKTilXJznVzRBuuNaJfEKdjJBmxvG3ebDhM/cf4YZq52aa8vm68uQAoaR3OEiO/NoREnRTHUlF1ES0mYvfE7m7Qf5rr7qNiIcGhTwSwI/nVIm38cm8clzpu9AJPcfo3XPEJ9I1xVpAoUHqN047evVT1eOKzqC/vNhC1f86fBsqQRBlwPHD6eZEMmY1JFBoAH4W4eSIIMpeNON7ghzoyruMjR2B4HuCANu0CkGs/en4088IGd57Aw7Ow/Fs/Xm/QQhDXjfaWNTISdOL/rkPuccLeZa6hOZQHYZOim6Cx4bPJ+Mi1uqlZn6DLswWkFkDuimXLbolULEAclxeD2klYLHJXrAQfhLSJKm1vNRY84V7pii6md1FYPNFEBfsiVBNS96pshp0M3tpEogEoR4ICkrX1a20a0Y9IwCg0IPUrToBFHKqaZo74bx6x0AEqqlcTgyY/AS4koqtPNlyjuq15T86t66pETWuzR+ThwP/Y3ebrLejNYZSWUhIHqH4tKY5goq5Y0MWpFq+gNRJOqG3jfPQbGeiM6lkEeGAu9Hyexp+pRqB7DKaUxEtDtlK4cmKLcJyNNDaS4CUTVMm3FOpwfp3/sNmfEe/NnJsjWp89jou1qMbe1VY4MWUFz7xNejFC/1kcPWf1g8xjomQ0m1HHyN/5KrmenfbbPxXB/+Tne1n//R5P7AKMucMyH2RC+7amF2uoct7T2X3CYRzjetwPy5t3ozeC489K52/EaX0KIAmZb9armr/XT2jE4wbjv4lfHBqdASKI7N0C3LqY1/QhsZ0aKrIwXREc7rG3/57EYO+i0srcDtVu4Ka+Z8OYYCgXBw3T0Lw6nc/VxYJurZtmRTblOkvGkzCCUdYNOCPxiMDgbxVUESdqrfXjIc0z3JkyzcrGwTh6HSfbM3+8ySVszikVUdxco+QgHG4cckgfQJOAAP6QHC2JilD29x47XNLANPlvVeb0p+VMtwTnzvY3QXQy+CUQqmze2dk1Rmqhd0vgGhXwI0XAT6TZsPN1Q4Ox18ZJ+8XLnPdRWjq/496K7SEv2ZLIHb/SoQcBUw4msLC4IpTHxgD/QtzaP8o2wRlFwIY2RNUeuf5m2eIytIo9YAksMn2XtkN71c6J6zg///2AqSnj1VIxLyz1KUxxDmqZ1YjP+uvEAk7BV9sX2OXy4MQc9ZIEwNggMBmFRB1gvTdQ6A7/z7ClIA3mGnVRH12OBjreQ3YGcDwYOc0RZQsPj7gyizUoB5TmFZV5Od4tYtXShFW8NbHxdiejgsz37AxyDj2eZkH7i45iwZtr8FLsezdMKzZd6FaPFzmtki1z83eHIXIKdLqI+JREz0XrKgfAuktuXGwfziUI3bjZ31IuBD0mnOdbB3LUPpYtfjbsMeF9mPnfdqWahWLlyZiCnwrgted8JX+xfb++KNfFtdWoegNcQ7yKyfQgfO2OuqeyLz1uAtGPn2jWOoEBiyPfp+kgWBUAKl80Ec4xMtFjCx3rweW7tftFO9jY1KzclkSIXZPQv5GD6UUWRhz9x3+3yacz6c3Onj26cjCXzg+CqZgEwJtmAn2F4IeUX7FoJx7/fHxanf2dTwn9zXFnX4PyrpJnxgJSX+HDoMBJjS5dIrCyexyM5XCFf4OgR8EzcytaB2LCqtn2HGNY7fFwHRXmo1TgI6FeCs6w+z06CMZMQMHc4ljWsvddM8grYVI7SkWlkOOhlMhhZXOJICXgK341FRrLPIWNbhRRvITfSJOh3Y9KDkmuQBGTU3g02nNUrqSfaCmd+uDQNxcuVLiZ4k3FqOCFEMzNlJKVMGTvqU5KLumTIEdHKRIvObMF6vGCInflN14vpSWDH9rmb6OCwRv8MaeW92XBWlTR/yTNss/6ypZrDupCxKEoEXGpZvTzQhfe0b/EDP4473G/EdoxgBdTnOPInuR9pZIHv12jhRyqeOrtwLbWke4iTrX+yroDCh849Y1oP7dhCyBTQ1NXCYkFZGHSb3ek0n0IijmFUokn+IwwOcOjh/45NgLJ0XspLTj7iAtlSiWikKZVGZujzWq5CV8G0Ykkb4LLD/8ueeTdNM+6t0m9ZoovRKzIv8m693lm2csIBokTlJIEL1txIEcArSkLxoB2P/jsb5DA6gvLzg5uaAJKVdan22QcJo+jMHm/EFMWswJABcHp/fx3hi38oE81KWfac41PtjBejK5ySvSkfwJVi8EW1YizxPgsFfcCb3/cIYnTyXlByiVgz16EIvC3/QvYngEtZQqaZuCzxU0zovqM/o7e/d5VjY5hTJin9rDrSrdm6wqTGBIUTw0SpKcb+cuWZzNN8dYlXPAsxTKu4ArP+NBU9RnlqyCacyFOScB5NP4Jiw2gPD0rd6raIX15xsA03Fss60a6rsPGEDgsJE0CySQb7xfsm8vF8gaL464bUCbMQHPoXp/cTKjxaQgMbW0OP/Quk10PI44cFBSeKB1a9hPaVVlfxYk1tIB7p2/MIXZscHvo3gWeUFZi8j8nU032qBJ3QLppyN7OxiLKPshgfZYTgQVsVAkHHlGBLaN61Y8v6wQpTofnH6vnDEdzgAl7356OmSvoGWrMj+ExESxWV3PfWzFP8MLdXyZUOtvpEOo1s0qQ8OqsNvUM2t48akut5MMyOJg5ZmedFJ72JQJuRxYiVgrPLdsMBLSqTSeGctOF6d5j8wrc6bBbmWM3wnmJOe+oBXSfZNzebO6+kOYf6yuCfKcCEKD+pJu9SZJyoAG1eY9KA6ElGp8889/md0bRaxi7XcH292BjktreHHfgQZwy21+5KX6sAF1LZDDIk0ZetTP8YFbl6/frHtsv4BLeH5WvGXC3NL7zc3Wv/5/iB69dvq+a+68JrRzXMjeHIMd9mRTWotft9JdDa2XRxJpaiNYBYj8lrK+zeyQyPIjSWspYiPPDcOktZTgB044XepSS/CASYwUoHJcarScIcV/sNlRf5VeN6+6n7HUB4CtdTgqHI/LXSGfV/5xRMcfiGCkPIRAmaOvfKuVJRfnY/XAgiuTbQNciQXHbxfRE9ljWmvWcsC+XR6A4nmZmKsP57TUXPEhRDyJ77LSXFCkHipMa7VjwQ9fe6ZmkBaJskBISW9g23HWqq/TKuz+uAMPgBS+oSe6HaHO6EED9yRXnJ6CGPcTU/b+8jEwTfoLhy7jIU8FnH/h29sI1unjRt9yXzVWar5OAYFHCT2ky1Qd2Y9nNx3JJsZO0qw4l+I3t/whXqbgRHF1oWwHnQtbmSfB/l//dZ6AGYTw/W42wjnxlkuUqvxwCNnPcsIExpaH2Y9bgkAiv5hEfzFCSfczwUFMPp1EFpEoalRI3xQsn/00ez4qQlPoPpi0ECsrVlhlfdJ/UFBmCHSjexuJffWO41C2VWXGY3V3TQXLKyUizzBgUyMe0/IbMMy3klXpjNf6R18AN1WiwizmpWh6gFYi9NRCHhGSfslDmgUhkactEF64zeGkwkLpxn5tXXExAAtd5Obs1faxE6Zc+lYljVTA+OnWHwtTMNOC309MEP2XSHzYUbutLe103F6tXbiUmpuFuk0e4Dibo7yobuTbCOhxLLyUcOj3qp9JSS3VZzrcw2SuFitaw3oTPUH9CXRW1utkWy5hLr8OregIHOn2yJRNxTD9yd7CcfI1Qljbn7Btpxba1RhZvqrir8lmUTQN5vorCdbG5M5YIWrQXWOS7jkI5vk7AxITDm/oUA83xTMkr5mdL+dt6SH0AcL7LzM8Hc04ZC0507zt4w0sSWOidYfwmuBWj/S2urtdk3hmPX+wrKwo6dzvCHDfUupmPrvRa6ZakHuM3oQKgWunqvLst4eFfR0n0Uq9Wf7yn4v8kximlzhADb3g8QsOkQji8ewaNSBwLR9RaEUl+OgywahAdeGa0y42gT0cNks7tRAT4zZBaLqITW6qKRLOF8ij0DD22a8pCDN3JVEZozBYI1/sJuBJp7E+ua9apNGPRZ97kYBTjtuJ8hoiKkR97txuPdMq14hdCtJevHrv3n1JTPXM+NYYHsafqOq4FZ/zc1iB6JhdNH9IaNt8LIFi2OE5OtAzJD9YBUmJZSZGRGcWl67uCO8Y2mLxhikdPXv2l9zk5SbbSAVATSp1aVjpFvm+xsykEVps7rBl/xjBGkk0SCSRdCvaKD0uebOy14JbRj52+7SpVM6U0nqKuMzjKsPKoeVmvG1Hft0Sbr1OOApyx3+Qvx01lfTAL0W/H+k5zLP+SV7r2JSYvd1JWAEPGgJpyv7VLLCqgZ/uELcot2jq15+2rowwmmgOB+leKauq6dmdGZs8DoX0KQzf5WRL+HYtStZqq4a6MkBKWcz00Ay+LJlxrkGJ1h2UjjWv5IMWwxIe8zOFb0kinfATkB2HuG478fxR5ALa4Y+RvUAUrmGo7AHlXQ+BH1L47v+eFhMtmtJXGH1LPb3DWF9MqeOj/B4y9o4BSPytxaRTCYjnAxrM/iawS4cseccwlbIXHmse/ryFDHw5m5HP2xx6lqD7l8sIiDOmchSDwl3iYkCWmk2BTXjG+Lt9qCwH+tNHXPAtpwOv6sEG/rIDhlX1PIoEL1H6zY7Dwwiv4LjwvdIJ2E3VQ1CUEIsHCRHbeq2nprZkxK4JyBk9gEZ6FfpLNCT2hPpL4oc+OYWgMsOBoARme1Lug5+Ei6PXQ8bVHNxMLD47hJBspyMDW9yZQyl9+s5WylRNVY/kGLpYXZU7zTtZJTWc5+UM45E83I7ip988XYVBGSx4xPw6W8XvL78TcnJ1ueCZNvl2JuLDuqsMal4yb2Kh+23M7r+WhBCk+eC+eXcenysyvmbBQKkf91fh9f9dWfYU1E2h1LUhl65cdafqfQ4EbJLUr3inIfDW17vi8riEweeE4QnESN5RDbwHZonsOUm3AJ9UXstDumYbpDrEZi4Uk9Y28b4tH/TCMNoKeEdTWZHvGcwsEGRFWxHXfodnOcVe5hhRVLDe6cE+FdZuvn2R4h+l9EjEd6ZJam0lUHYdvLQknMCk5ncyGCwXJfQB/ZoNqOcrFxlR/l83PUEgAMSrtqRssXxAFKh3ypiKDdpQmVHAbqEUW2uteFYLGCbXJm+2h8nW+xltNYKPrPy/iJF40RawTNUva+utd80UDyCtcMY0p3cgO+hoaLwbymlHMWuDaKC9M7iRGu0SUgvyfySfk7ALR66uzRZXr19M+MLyU85iqMIKN/taEpeikJIeylnpUlITcYfCEXtPDB1fptMYn6DTi2tJLNcBhUt6Qv3qNYUOSY8Du/EMfQQo7iBVl23mMS6kYTqElH6Gxxt1Lrbm4HWAzfUgEKfXlQI8JykUEOj7XWsGuQoKwSW6JG5JYEmTJCz1hIrD9+pQm4ulWsi0RSpxpin7FzSfKOFHE8Le2TK58VECaHoimzlWiEg+f4EMV+UpkCcLyl7LYggOWZvwNhr9+7qk4N4Ad2q7gD63+GLnd+qi+WedpO6mbWDmrreBP59gJADULJAzJS6pOfLU2sJb4SXYR9oZO3WNT2ANIh9UNRHAejI3Vc5WjKbUC5y2J6ozn2wgAENW935ikSyCIzLcV2Wod+clCjH83zd0eqQp1n7pWWR8wHoQxcibXmvAzjvCV2MRTMJukslOBlW5ah5sw0Yk8BKUqLy9CgD0Z2mxV/yGLIs6wuApK1AH9vRQhFvtSZAEIIntgT15IEfLPZB9HC82A60pEOK+OvyO/QuWR1xgY/O4kWF+k7akp+l7sw9FWoRnBuioJwXOuNw1Qvu7Jzuht3ccbJSvEC5RSZA2lPzFrtKWS5XeRvj59zJob1oI8oYkouYC2v7Qc9Hk7iDtio+WWsIJdF9UqUU5x3j51/xDprEdqJlzfL3DH2RjgNY61jeDOYRUyUq7YQsZNRWG9S+EDXOoGFhW2OTdNtros+vjCFwH79h7tJqZjGeysxCxeOuG0HnnXma0Scj0yMbH1I4BEQl+Fkj3MkroSL4xCdlYsBCHyRd1atMEF3Yg0Rqf+pFs6/zdjAkco64jAvBCH8kL/Bn+AL7T0768tzcBWkE6TXFPReH7cRehb7MX6DkZcYdqhY4SS8G2sOMxQuLktW6z9Aro3u1S+faZSp7eQR4TZ4fGiYc+uJ4gMQtAscsybVr4Q0jPKCNI0r3x9cV5AoDuv8ZDsw5lbz4TPgYX18dQVMR2U682emKFSlj0/hiG6xawURDbTyTdE04BsJkLRdWoZ5+90rTjYlALD6rgu6IyiRNSRE/WvTVwX9ftRcF2f0KxRnuPbssZ4IM9CukoUDEUKofSnjh1knwQ7U3fQD5Mrp2zqPYdmeCkbJ3Nz+Ac57PPMfvDRtDlGhNiZpmXBb9jcUg5HfOUY9OzLCaejT5e/aWrtMcCh1wMHvwbnpQXGuvdyZbHLcs0a80ZjbHxVP8QoMAjA0CI5NKT9Ly+6SgWJKIrmzgCkOxZbZENIPhM8kDcK63mjSKhnSP++gj7F6VJu82ICP5aMusgm7B4Rgl2JLD2jtEvkLvrrcjELxpUGY4yAu4E2fwwwMovzxeobYEDj+PewZkZ1075eI6ENKlhUNVUQsgbSqsLPuquQmQNtmJJWFGWGMacWh3bLcvOH+hD04J74O8l8wEbT4CCY58Xi/fZFjJlaB+TuqR/uYIaKldAvSICm/tF6J6g4TKjYER1PSGhAbzDpyo4VhJwTi5y6g+6IQF2uL/NzeOBn4YtkFB7qANMNv05n0DCmc1R/CJZ30ttVX6cDpa9Y8dXS58PLuEx+1O81VVSFn1MiSdVbCz9uzFSuFE+37eJxFb5HZ0uNvf7y2SjQXeGWHwUU1Fyu64g8bavBWBsDbyvx5VXCzMgRb4ociolpIfPt9bXEA74ds5LNLl7wSudiYiAf/WfBFmZtoGg9AUm4BG4ZRR3BeVO0eHjMR8h98w/8HPxHD9OvmeDhgv0BMqwMDwUr6q9onubzgZSuWyBjrZw34ghpvug59zJoKLap8vc5fMuXNQeX7BAIYj7N1Zixc81V92tsXnJzAv3npkG4Qd5tOFCBuVLN0TqzoXKlPuazMn/yGPAqTspfKwrUwmOaPvfgDIKduY4J5lLdjQAP1fjpESnkm8yslEbIOtWOPO195HF/jWGwDLuuSXwsIk8Ds3yhZY5TUbQUmoHx9wGYhRyiUAiFU+ApzK3GaClJOQdMUp6wj9okUeTVM2QYhQ2A9b9XBsawzwFK7AUtztaprzfFHdGNaMQtdUNYtyEgNiZm3700K/1pkwyJ6I7+690+OFCxBkqEVVvoZALkn3CpNqVLeIdv/0fwBjI0cB+AiMUd2TsZWPmZl68PZNxA8K2ohvSy4xPQLPqUrZngwGfWFbdVRCwJMRPmNg9wX54ZImgP04vwx+gRo94aapJgpvEaX6dzSuNaejNRm2ygV2ijV6q0i0v62QZK8rC1H7ie44VtcrtGmPVt2HdkrPilvYVGKPl/05y3ScDOpKIlY5iVk9ZtMlFlF7iWixdF3yUk2QsvzhZR51M0PqYgMZ0N2XrQ+8Hv8b2i2ZRZhQRZddWg2xbn961KmwZFHhaZCS+Qr7CVbgvsk/7fkHFUgsAqHaVdM2BBXOT7lbaELK7NALYFw76zqHEg56+ML2087WfAi8a8ilmr0D8VFfcCY6Cw9bKdPJTN7XNfSzzTTVzDx2JazbH9pNvV1nVTK+sVcxepyxsp4wuOSJRa00G8mTJp4+ilSf4760GXGpVNYkX5wcQSJTCFtElgbZlvpSUzq5clxNxH2Tpkvv3bJBfuM6n+w1rC6hy0/7GVKhE1Eivx6JHKZeDk1j8D3ISEOHo2rQ54IG1Oc1tHw7ZryOPXs3zDzy+NUZTWNwqM3w6e7IxlEYwHFYU5BUHd8TcdCgP/t66oSqDkv8qjT1YIHud8kRG2AW8TK0eYB1thcxxyiTe3kOMsrrYc/JFrghvl+VFA7qVxSvYlHPgXc0U/t0jhkPf6LgH901c+fvKdmfcl7R5r4pfmnu5fKn2jy0Lb1dKB/41Mt2S0XPhkLd2qolJcVwdWd4msyzReWnEGRvNrXiUbI0Cia4Cni9Y7UdcG+gOQBEoJiLjr3BMV9IWHoJzBe1trTnM0alXLZMcN+8SaLBVgyJH6KX4Eu/8tqm0JybijVB+gFC6bkCJFfDPAl4bq2e81SZBnZtDI+aTbiuLL0jgL+Z74SfKdTwtzktQj7gLRvufdEmTcpr53pfbk5GniHOS4w0+FXsWUBAoQzJf2Ow6mup8gfCwXBSGTkkitDcTKlLYA0AaVCVyfmGRFbl73fvTmoj7xoQSyKxmDoE6inTK2BidC/xJN2cRVxeC8FkeIFM+F9KKBIPXQRq8D1JP+vxfqvZfWqLgm1YEFR06JZdh2w73sxjiNMqMdtxUTPg214bSS5EI38SdDCoTelvEWEwcaOHWQQGZGLDaGff4hz7SA6mcdBOTlBwX7ky503af3u1yUxOLUfZwIWPstb1/mbIzWcLY3zdqQzGq9dUTLU4SGJ90gbh7j0bgAOQrUZncrLk+Qp9+PCOuOJ2v5ra5e7QwvAteIscfr1S2yZ/0zIiwWSxisAFtXfsY2mbjYAb7yMQqYxJlTKHk7l9l3xE2r2V1f/zelpOSNKDTe5HW7gA8//+VPj3yHGJB+E6zFp1Jz4letb80iph3oUng9yJQuD9GWsGu9zPUxHNUzo+INmWVmKcbLtonErzcfQ1Vwf9cuIhcXbSI9pAUM2MwL3o10GxOYukNm1IU/e3zkoDbwoU0zwFLLy0JAF+ZWiNwh404k7+DhFsn4A5WYvdx2qIX7IMUWvbh45yE2JmUBV7+UTiBn8dF0RdItC2y/ZJQvjKm9FLsPbl3z0teHZNog2SCHDKweq4lvkXTjcl0C5GXuG01Z6ilvTM/WIe5/7n2SZK0mk5MnjgO9VT+7fssORXcXVpA03Hqs1Rl2AUTQ4sDv5KjGcfaZLOVzX+kYUyW71iyUT1aiUNBSfgzK6vuKuaRrRHBenS4t4kVHpqldI+lOiHGGZ3m4JSkX5rHEUV+nqGvnbN42FjLj9Cxw7J7POKynE1TqU25N4O4ZDnSPUJr9emqpdsJemywmA9JRIaOM+ufslfqeBLjYk/Yfs/Zry0tnC6P/uIkwQ3sm8+R1ZRQD74xl4irlLNHsorbRKvraeaQtGFsbbBefmZq9Giehltezgrya9OHK+q0mNKnq6Oa09l28bPpsNEXVbk63ahArYqHhL8WTKP1AU1RwJ/xZJXMqnceHx/8VZlvx4V3gMb/yrq4r/g0lAtnOOqmiWeZ0oVXsDbYydTxYlQu5/GTeVtdLM2wbkq99MJh30mtr0QolCQU6SJiEnTydefzNLhNPDMtM2cOzvfqtPyMwDcsMbsGLDoUQ3XgNJVoOp8Wxzf+PRQ0EOc2PoLWWANPQveOoW0pqvi+7bndxLNAW3m8YDZIY+KWnQOjASRSe2K0HQQjgdwa13a70CtGBLE2ndFax4A87dr3Hyw+jgalGB+0te460BSsR/TKASUu6z0lK+os3D5MywPI22I9EJh1zU9JaPn2s5eYESvE5CtyTFHync3OnYsYuuWd7NXhLdjL8e+5SLHkWOh7DSJzEm5oSuBVBBBcGtpVmv4vy6ZQpMrINusKScXxmu3RTvZgXpbbyJC4JLKj3ojydHCUrzFashQczKdUjF2V2we3+s2hLeGbBfFq54J8bIQdaPh7HyQHsYlIEWENammUhlVqOeCBaTiaDB4nkL7QsmelE/O0HKtZYyzxqi4HThJnTVDBvGlN8BsLI/eyBD35F+rQ7XusY4vhPXXMU9ajY0U7+namk8+HUQZ4UFQHnCp1sLklhRNTlUEBuZCadWrf8IpIoeNGTsVM3zXEwhUf85Ztlj5uuhPldoVYOfnYz2SHWA4hEXoAdetTXYV/jE1Iob9aIUlKwBAzjtqlFzaTVjSA1Bj33RB+slbdwSaEwf0U5HCUAtrKyzQll485ZOn8MUZ7ZelxpKEErPQuOL/901K4qKlcw26m5drSwZXVUaVFwU1YIKG4XDtcjyJg0PMVRAguw4d4t/NEc44ESN2El6OU06ZhQ01LgjaGdIdlNj0cXbnOEDF+ekRjpicBb/R1gMHEFUfeb4aVpL8qAdxtYkz2/YMa+aRcIYT5LOLb6Nb3i4Pa/0KCIwUlSQHRtN6UCYbY4K4hChtkfIiMmKXlNJI/84yc4ptyXhYs2s/dQUm6COqTpNGQ6PFJCMUaDj0tBue7qq4Pz0r9d0CZ6VpxuhMG04Ip7Lh2rlpCVyNfRdLLUv9Zdp8r3oRw4Gy1JLtwBXbR+Li46s4jV/wQaBS0DBUmx7SDbAoyrrkBUlbuX1x+Z+FjhFxQ0zqcfNusGqhRsN/bn9ovUuEovejfP9AB8oEuCda6K1tFP2JtSUOnEtns6AdvjOR9w5quOyWgTMdNQW+1QSCPjgETVrYkRbTfxX5k3Mmrz1ZPHvbUyieEczNbvfmAC2y+ELUrl9KtmwZQ/HiVw/9+dU4z+X5Alk88HbOf83bXjqBCI94DkjMPO4yPAnb53Tg4NZnwAxTIU7yp1AqALDNHq9nLEHM0ljdMt9nkaRfdIE/wrbRZbD22gNvBXtonJ0liCG9x+ZkKUsJOQKJRT+q5FVrVFOGJx0f2bIuhlxb+KwAej/RJ9AcG27EXEwnbX4g35S6v8b5J1RcSPWp5+Icr4mfLaqZToEKuVfuRSjACAwUU0WTbMWCEqJqrlGwHFipHuX9Vz+SHN9+XsjbPWO1p10uqaBSuovnFIDZfvAH76qs4IIylFO7IjPPlw0qkcy1N0RORVSFHIQixO6bGj7dT/5ky2vbtnIIFYoAJDBvKb404MAC5cNFz/RveDkBrGUPnCTOwC/wMFgnvbp+tjAkZ1MS3+Kt7xwVtT+PkzORJb+KLJFos2ww3Q6orTRoSDmIjwE99XJv/GmD/gfJwHbHCa2npEay5oN12IzoJB4/Z+FeJCyM1LNGYmy41E97NsHOpePzaS+EqbTJtAlw+tJYBpVN0sfc27UxhnJ8rtGEQfgdySeJk5RxyEFBLqBxoa+isc1NfaBQUGM1QINOxwtidbRXmuvYtGDLWEeNjIEXQq1UQKw0KtwpOTyUYi2PGUkUjVnP5iqbMpcTcM+K6O2cakWgTKKE9y9mYHDWEnAyzR5fJYZLVCTQMtpwrVLuzbxIscswZspzi7dm+HPS3E7yCme7EY9wFd8SPn7JZE9Yj4ZPWNyf1CS9B+p/qkhM1t4n5XefaFEiugq4HT/a8fSTetfPM3ZhhBHtl+yogfnxqHno9bS/nv/czegEeg2W64f423XBV/iRk8jP8Podu5+u42CDmVPV9WZLXw9Q31LTmfslMfhHAorN8vAvdam0SNsQHsGJYP9uRQ9FuWIuC0iaMkWC4QL7E/lJjml5eeL6g//iWI4OEymXJTpp/NRZcABGo1prMwtqrIdpz5WM2JO3shvu0atHyhrjLbLnxsrYgJIQEh7nL+GEvZfs1+X402SrlSctemzW75jkeFXH1pZsn/32XrE+8B/XDJ+NZ3aRgJOw4b/UE1ZXbbbL6WRce58uIdQbE493HrU45chSj/odreLbfi04Jvo8sjFpj0JkJISrVyR2T4jbMJLX4G/HvBKwCor3XM6og1pj7U7YHadupBzHpNsp+h38FEHUyQJd+Yro5xGx7iN4A9XuAEpl2u5xNZEy/p0SU4VC+wClsydN/GPV3YTbbC+Laak+GZG/CX5KTKyV5vhqFzyjs42BuaB3gsj/LhK0YX+sy+4BkyZyzEfCrbo6NO907fCa15wgp7bRZMhfykqaTYCI/oXz7w6g6PA6ewlBopKIs+qL94YVHQUXj5GqIPsywyCMOY/0q3MnIKE1gE8yftMPjk7NkGbacGKn68kYv2dRfas3fZ63eplq/qTAZHc6BKEi9WszV4xlXRUxcESqaCtSlNb2cxXok9jofgZyQKx/3qSvcPlbYGWbGFpZ4f6St2wG2p0yy4+cyJbr/quHmz9fbeJnSZctAa6/3CH1fow56+hvIOrFofMO8ZYDJlG5IKjJiLRFeCnQujZFs7b+uiVQz7dp+u16E9j6DoEsxA3JIDCz0jFJW9QRBWB2AsDygmSwa9DuhBo/qlDI4RgzrotVQXmT3lSO22xAOrdYZQ/gnN8BoyVcW0sTv2ne32GYDrwZwqigxSO8gM/w8C8Cv4tDKPLDWFmmBp2tuvZaZUw10BAC99sFpsH6q6Fj2iRteiFPcy3+s/LrcR+OCxYJa1Z5YRRJELtr4zH9mUR58EncVMggcS9349GNoJxHmY6/ih2275rlH5M9/zkyAhrT+hNEwMg9pmoMM0Geb3eNDvjTjWUmdKohYiV/aysw0vtRf8CXnf34L/FR68NPFdYeW0rWAcP0g1Mju6wZs2iHgVozLx7VKpMmXHpGOHo93e1x05xRipJl1ZasJJcYDUeWfbwjm7+LAC15mj1azzBiU/Ks1kvaUr09eFXPPwOKx4oYfQS18IkxaM6oJGcfLCn4GVgHHDSbk8N+rc7XsHe6NQPXP6qHJ0cj/X1tmc5USA/Q2tjAzZgxerKHBAuZI46lFIY7AdghjOeQRewX/tRRZwYKi38hMO7EtVpEC6Lj1b89SWLGgt9yAMKJe7PtQwnkpho5LOZ6DcmOUrzJUFz67ULGWL89o4UH5/Jnxx16bd1b0YNCMhL9yy7LRUwL92iNJ9xJqDifPDrErgqyHetiEW05y/vGdAw6M9Mpp1NrekmyVWEO2SrG/PD2+9xvmmqD6v+RqPD37+7l9LWLhDl2hjBEwDXZy+XXqidk1iyuw+oO8mN4Xvm5SACfHoCwwuqCHjldf0Fy3DNJHyzRcxBR59+pX++l9wi5ZI2OW0MtmfgIE2KA7DuPhLuhZlIxe5EXPx3GSTfaoty4JuwVlJwQ+twLNbuBbkwBsi2vhqKz2ILFGQ8+R7XnxlOqYJB/v7y9Jv1Qx8mQsE5H3VIpLjW5ZI+LC4ULc3R/SE5QR05QaJUiPOoaM4h8MhRGNIVYhJDYTxILDTg3eBzYEb8WkwpxMYE5JvjUf6eGITmLEBDAoLgD/suPE/1xYhHKmi3X0As2n7u43UAJD9RrCf6tendHVYJqNSyYoWghk9ywWsteODsUOMWbEnoLCv35vvBA3vJtZisIrO8GFwNsPErmMiyXFn7p0hJtjfaqCtwZYlpUnBEMG5ToP00rlvjKdGxZpsVfJZSPFzwD4rXH6HKBfWYXRZmu0G7zOM4KjTNcvtrZxzKUApY/xfe+No0hCRa7Wo5AJf7QzzKkJgWDr5ND5NARJ62dka8lpiOFhkRPobVCt8Ou2U7UC1EkNRAeYEx4rhQxt6FuC2vNCVkVZVifdso7Ezm82djlGYYa3/aMQxyf/wkoo7Ye0cJm7j6PAL7XPwYiLA5Py6iqpnzxCEubbihMZIGheePCx8N74RJH5sSwj74R0Cq8r3HTPUV6ciVOD8uOnOKoImW+ybYDEdbbcELw4yEIgaemjcZLs20cDdSQNP7Fgc6SfBNRS3ohy0DuMrWvmS3GZTxUYgQ3l1rrnOwWMCi9aIgDnWm/bJzx0ahl8bCKuqV327ZOEDPgekSa8eZQHc8cC1KTZnrtOcx8aDZpH4gaXnka6UoRdM7gZdUShckgQgEI8cHL38+72ADV+HyI+JcrLpE/4XvHiein2/W/9y2qzcfqtTyymtgMptYP6hhGwfq/FWzcHbshz84j+dItWxv2ZIiDdMaghSeP5NCQLhRn8iaDw3aSlT3hmSQapdoUAyydJVTIgVJrVwkUS3cwL/1e9I4b6nmpWoQvg/cffAS2+qjgic8VBdk2RpBQ7GLoT+ZYuk/jc/1fs/0MQT8BQw/dzkeWQgLFa3wbwCPSB4JnqaD+T32GK5GlW51yQSShnLgxhSMWD1c6PNrGRbKC3EuY0VrnJyhPBsc6+EeE8okBZQJLQCotRrP25flzn6jWxlR0v0QvNxzMzyIBM+wzJs+zPN7jp9kDh1oBcfCHEsq9hvQr3PVUvd9t5CqTznm7qK5T/3gWK9c9BVOHnUS5NifUaYMUlp9bG/fEMMYJ2hmY1FfYsehBp/57RYohXRAAn7BViIl6jXN6BrwAzrfpXcqBrlDA+MKLQg8/OLcE5MAcMW2fUot4SWpjoA70AVdwBeI68TJP2SOal6WqlrfvjiXzFjhSoNziKdcVuraI2kqUS3YevvVk/gl+tKjcRsPHWDhj3G6/RFIVb78GgtLHCOnw4fKXkSHMwNAQbvt1ViYdi08zQTvEropI7wAF5oQS9y3Q0jlfJePOV8hGURqwWyin0psz1jBB5ODcFiXpPypGXXD9DRi3s2q0EvEMQscfRHhS6lO8hKQkbf+vV1F83F3cfJDfEVhzD+slA0bR4dKmkOVheIHgHWTld+KpME9YlrIYDhXM/k/+Ha4Y2l0v+4QNIxN+fPV7PRYR4r5y7Xtk2CWR5AeLPG19Q9vcrqQLetMUqE6cs4S6+zSG7F3c8ZXKdfzZ5JY6g646irV84VdthClKBu8TOXHvLU+9PZ/W6BzJx1Io1+q23+QOygOObsDJJkb58NNlXSVAP9vDIOlm5e7Wwk988QYi9oQaFfx7zpGMhDwKFXiD+ZFh3Xi3lkSFAZ/Go5PohV0K+kOL5HxbuQC9seTy7IjmVna8+wXHc22wiApzFSXbyJkSroX3b1Wco78kADKV/dehGf5/Q9qKFrMEdiPk9gaI/pZdm+8WoRJ5nyQ9EK7yruIiSNscISj+9kKkB/O52hmsevUxF+2h/wMGbYA89aOUZuXJ8G468vF/35L3cAeZgxM1xoZejrNckZs/XWXH0Jy77nwHfxIhAimO1lbKrzeCkcMLSJocOU3Oy3I/9WviU/ljtXGGB71C3KIJbWnv0BOxdqdKq0+6XRU4mfFmIaz1XMkdxdxscgErt4G5aN6efe00coREcJppuBwV3mwAyRo8RrPx4wE2pFm2cRqTvr4YG5veL/YC4sYtWEHLssF4TbSBM1E0AXGyEavWkxQhtbdsRtVXltvlFqvmtmf4Kl3hh1lEWktI46m54LVARHJ5wTk7yrS/hl6rMVxPRz2yzuXzuPbuRxR2/Njq7eBdrt7/B7pIj/VJZ8J56HHIghT4h66QaE2iSUcdpmAKt9WKMGA0MDEqPC5FJ/4mjztX7sbpzNkvI0xAVoPAr3w1UqMtvNs7x489At4zgqwB2jO76+Dy/26r/vGYrDoPaxd2TGVr7oRuQwsXf17fzg2U21+coRRhHurVt84y1/3EqV3nWmxWt3MihgLfffGws2yXEWp+A2xP5vCPP31NV9R77x/7F0EQ1c5X4XCSZg7I6CvbDAGK4oPUqGPm9XUNEvEyBgOpLZbm/aTZ+tAvrWVa/D1KemkRarMG0TwrVfEZHD28FZxq/0ZxDFxOvJQVq8g7P5BcEjfMu2LugzIB9WGagJfKrbIW7cG1jrONyFctbGSJYLuRlq1fc5TcqZP2HPsXoZdQDNWakAEJVxmtMZyuIDLE6QlWHItUaKTcq9OhYmPjY7lQ8Qp0uNlyMj1skXhZeLs78iOoxtCCQXLAP0bZDM8/aXUt4StuxrsxYAvqKTKp3E4M+ItaES0R73w04tlBpeGT05KZpGNnUrt0+MfSCR39hzvWpko4OvzhWoStTUyGbtDRkIqcnMSSDjtPiQLIVxsmHLxpc2uah4AH5L3fAWy0xarRwYZlX5GWnlmc7WYjUIJOae7ByLNTJ0+XytyMFS0sn8puiDz4KU6c6HcFI2B/d5A5J9WkZe21Z5nY7Ce14mQLdzq9VsftSOmuFPyKMZAc3GS2XoKFFZmXh+8CZH91NAhaJcgXILha1TsgT3dD+/FMqSmhsWqMNliMK3wlbltz+SSL+68t7eHrSp/GHSepMuv/5WQuDnaZXgPPxpulHRXoPKfCqccs+WQpFQ/0utTjBq4PMyX83H8TTgJPNtwQDPPnikV3N/WAf9dEaoAiScr4hLYLvhWPvqrpoMxAuHZJ34PBcDdw3U+/PIUSzvExCSIFkMqdTpTKVvaG2VXLEUtAFhiGo3FVAYshRr3u8ORXl1ybw9mukdRh7n76pymR7f6dPkemcsP0hBsG6UN40sGJtaj1snJuHMv10gVNix9b1ydZgAonJ4vPPirTUzDPyY469Lz7rkmk3KLFiaeOZ01uU2laXU5zwu3ZFeYM156XAchI2ato7AfIRfjI2Ks1RPZZ0GWZ8lw5oFxD5k2W7llq8RMrav4eXcDfDsSgc1EYHpm7ccZ/9ggHhhlEiD3rJJ2EaKSPZ8ql+sD7gtacPT104QCW/DPoyHBWOC35F1rpeYNSSjSmlLLtmBLnDPGuxDt7sR+IwVyYcp9ETzi5M8r0g4MyRXYQEGO+oty9t9A3GIipk4XbnLDCjpb0cj4b5MO4rJ/NpltAt3B76Oh5jo4T5q2KHgC66H0LbH1pWHvcCJOxV20UymfnKqPYQ5ZBqefaIMlgTR4eRIIQwewHovotOXk4Y6UB+wyzlbOSCmYIJ/FKu38ttS8N5iMWSfqB+V+pxB8XX/dQPYOcniURDwYnwn12c2iazYCGQRewTaxLFjIHMGSSIJ3AKjeTl3RsShoxoKuDPG2r9NRU6ywKUjPRkh65stPTD2duIlYP7hx2J+nuu2jieZ2jlGQ48XAOXX3R+4CRE51UhiXQ/BXWFgufeUB4F1puv7FJKtxFNt9gQJNsiZXiWQgKxMJCffqu/Pb6cimVnvAJu+oTVXPV1uX4PSIQrhszE2yU+h5PtKUMKF6QKpnCMyloONQYPRWgsStco+akVgzc4QBxvTnrDQldnAbLlGylfV17AbQcuax+eIqU3eO1cGkoZkpthmKvKyvjMZCcr1ng9yvqgoC5Knizffe9IfPzgXuIpeSQGz+nXd8aTe7pEvaRKTlRLN0LMwIRV8eZmT1t8ew8nhHaRiRn5cVAACuv1KyWorInSUoqHmlsqd6HPIk/KVTu8Xa/+pJAeuUfe++ccl5gQNDxYR5q/M63DN62nKqblVC8mYJo5JcM4dVE5XIWUJShTQSbgb6p8gyLbwwYORvmyKxOD8L49Ch7djfIu5zlD15kbFfYWGdRgQKvmKyc0mmIb3Hi/foCQjpa49co2zG2G/IRxDk8jkqLTMGzV2IthjjFa0st5T4ZSi0ciCh+G9MtSZgTKEVr2UYofmJ2JcDLbuojVsdFOB4hA5SX+A/hJ5jfHDdzxty12+0PJJYJaKQ8rmNRAKdQXHqG3NyJa8wJukR2lTw/W4zLKlr7d8er8PKIJZdfSdTvqeL8u0KsSbvsFw8OBtOZA/pJEI0mi5gnzZCSwT9WGzsReYpOA/BP0touZ1vPyj1vtndqxfihtKXF2bwpK+JkXC6cc0QUI2/W/V6zt3SAJTSyVqhKf2TM9LgUQdYyWKHR8zNHYDa88eHUcNjsLL9I/R+0iJcCcDzytQQEHyEb60UxuSIJ/E/8UIG+c3lseMnL+dcf9xu6L8y5fpXQO+L7dol8SK3FwupKmjI7M/8aKxHyuumk9nIR4wDolNjxbDa+xFoVU6YHyYkcD0Y7nup8iM4GBgQqEVdm36+099+lsM7ylW0rlkmUtt8h3NMNZ4/dnMR0INyztLXz1kO1uai7SWtkcKv3P3ogLmTPMt4FRnHnQ60sXyCvODjd+6Thgv97aPuVZ55PabMgU09Jtgs/zXk1b9rjENCAjlpMpbSX3oSyfxTMCFFhicXvtnX6ZtwMGs4EI/L15L6MyiaL3FjNmA3BEGm2VlxECgms+rYcBJe6DVvhQsE8yTjre8IwviFMdl5aacI2A9oYPAZjKI7cZ5T7+nGD6lw17cTN1PD+OBrftMXYG24bvIj3MU9R7ITvrSicIKpctJx3SexpMMD1hOX9xodV5IOAtrcz2yADE/iJoKs33NMwb3bhqTl93TR/7AMhjydseOScwscZDX/3r87HUddp2KCIyYkeTMwkJpGksbEAOYLO9bov7mrCMYj7cSbFyAFZ4+6gTczjFJEtAPLI80NYQjpsGW+BSd4XzNK1tkHma15DM60KBdGmN3Mj1w27QtaSxIMnuN+iaKCKlnabvRAoR7VUViWanZepCg6UvU3xhnbOeBuhu93NeAMYAZv0MSR+5kIqjHy8KENHzl6KY8lLpRtrkjwljK9dYO6WdRTQLnd5XynBnpcdl6e1XABnbFx+/EbBRFxouDWYIZddJEsFJoytSjWAYOtGwDyZVkoEeqE1IB6vD9q+cQYDxhdKYhIeuGKhR4WqACEPcPSCTsULuVWsHcjIhaXObCSTsYGdit6H5ALUAAChzrnKdOM+DtO3vZIMcwbP//RR1wknDMBL9B4mzPy6u5TJhqO4EvqCvINl2MvwCcEHGiXkxqvpbQmHLEVVsfT+hMblncjLPMJsinilQKtA3fZ9T1RhyJUbyQUDxxdOBp7ZybEc62sKo3LNMYnqh2ix8uYCWVBKklDtg4CuRrr2qmh6SEuaEtCi6OPD6QugwVOS0o+w6t11mrbv8XhyTpNWWI3DcyQ3mSxEP+TqrWWk2rZW/JmQoj/BpA8K86DgvytlpL9dlcKqj9ybHyR07s097KZoFiUJq5ZQZAsUNsvFQqIHiM/iYBYiGgB+PKy0xXsN+pgIYDU8fgMcYJZtw8yFK6pS1gcxK77HVwHAbAAAAAAA==',
  'trojan-ws':'data:image/webp;base64,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',
  'shadowsocks':'data:image/webp;base64,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',
  'socks5':'data:image/webp;base64,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',
  'http':'data:image/webp;base64,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',
  'hysteria2':'data:image/webp;base64,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',
  'tuic':'data:image/webp;base64,UklGRhJeAABXRUJQVlA4WAoAAAAQAAAA7wAA7wAAQUxQSD0nAAAB/yckSPD/eGtEpO4TECPJDdsA/wTAB+n+CyYlO6kgov8TYP/dx8Dv6O4bA/iJSCdnFTCf9ASQ5EKVe9XDFe4SF0mg3JdmFV+Q7u68uLs0QZrBzODk3n4CR0jTOM1wOkmnu89rSxIAMzMgRC13SUeVdma+QEhsXQJVe+/sC67vcIzu9Wa4+8S9duy9umFmgLgk9yUp5wQKsaUImAHYN7/NWXNT0m3zMkkpu+esKvJJ5yAvuvBQH9gdmQ9n1VZJghl65se7L1wrM1P3dVTm/kQEazEiMsmLwww69s54TDFCrjHKDKhM9/1RHns7PzEGJJWZ6RJaM4Pu7t0tPV2H+5pBRsTo+yt1r0mS8QzY29GLJOztO+sVjHj1ZXc38kV+Y93t7k//k+GgbSRJSqr4o+7uuQdBREwAf+kKLn6X3SAcXJytL8LgbCkQZOBbC51hWdnaaNqmACoqQNqWs1dY2wJ4BFBlbQEnkrbgItAylbVtEOcL6pK2qDIL+pY2V6tElLWTo0NBALe4tY2Ck7UtW6cBVERJE83IAASckIL4UHCyNriFbFOVtAxUIGlblbVFANXITJlpm8gFCLQlNEk4h8oS0gJBh48ATRNwvUB1NLijvgkNvrIpcj7Am4sQFvEvPdm2Ldu23Ua1bfhAIhCklwbmgfmPMxf4rwfmXGvv94AwSkRMACS3bQRJ0v7/zz50dVWS6p1zREyA59i2XduWJKn3fe57CjnQqlKgNChtWlUilANVAr6WtYQxxvgjvfjsNXth7/sQBRExAb61bVskt7at5/3+PyKSisWS5WYLbDU3ZhrMzOMgxjadA+MWM4/dzszM1JjMtiypVK6qzIz4v3ejNOgMImIC/LdiS7rngJSuKr5KvUgvSkUR/7GIk4nxRo/o61cWKwra5AzvOHPlRRQ8qMw6BhfGaB9ytfMqKiWEqoWF3Ddn7Pk9o4rcBa3QCHJPJYgt+oPwHfWNsXmWHzxEN9LvMDLfD/KiVMpjKfpVk9Kk/4hcXJSimyg/zrPQGwmgNSI/ZZLynNe9yZ6kPFbc79co+NW0hzzLUnoHpfo7FEWqF510RN63Hob3vvJU9MC7t3xnpFLyuy8DokRG4l3Oc5dfMqWTvNEVexV0qAiXHUYKvQlRVLjyJvELig5KELFcs7zNPYEi6tCphsRFAd/MOc+igDek40oL0KVCiRR2aPYiig8SqMDVO30gCUTZ7dIwpRiUH7ColMqZkZu8Gv4Im4jc/+y/+rtz8/811xFQ7uyFn5BKREnI23mHDMzYffLPfeJvfOr4qQAX4tGZtQx4w2+9pkSKUkrqRR5bR+TwpS999iC6ZfuWQCKCFGep4kdcXTm6yc9bYenYu3/N6uug35rMRekPP+FRkaoflWv5UMkp5KISqr/zJACZ6H/XxYuT+sU9mfT52z/sr8eiUMiLV799AUHAFtAvKDimV/cuKz+MFEEhJBQKxc3P/L//8Q+1yPUjq4abUikV1tLBkAjqXflPHxT7wdCwAgQBUdj/3B968d/+QUKR96+lYnmZXyb5L7F04i0K8ssO19DFiFKH57/04Z1IZFa7ft9CEspjazwkQf0XEDnVAV365jn7ZgeSFAqCKMsXHxySqgTJi5erRFKoyKOE4KOSgDclZ8CI5C+blwtCQsW7H7qlDIjcuwcrwhk5Cy1XiRSEu3PdEhmS0G96teyhESoqztVzew0Je6v7VxzDZ1HQwgNKq8G7oqj4xJ4OVXpV1LBXBMGMHUXs7ddEXOwSirzxgVb+SCSqeBLc5urvW8TV0XJXmkqVCFIXlNBTebm1+cj28mjHUTCYsANy927qD4ekXD7tI3XW5Rv/5///R2MvXrrplNdSotK6wVru8zqvt0sXQFgRXPrIgaHKIAF5eHmwCCTCxoBkBQGF7A5f/v1f/Gbbpqoo8p81qlCaziH30S6Rb0eusp0i0NHdgym55xoS4t6BC5YljLkoKS56uP35Lz04+M6+b22b5p4IxyXRk94ieV5YUnkdEToESeTw4vWZjaLQcVryjetZEQI9wxJSLeqOnv/M5x4s1u2X7zdE3C3ITWzpi2sH3ZsfrpVf54yLjpsffq6GbDPYdAPa5fulT4WkSMvIKkLLe5/6+N2ry7rx2c88XpC3zZNpee0iSnpVvVkPWr1LiJJ9hlDuf/azl0pXhChEnq1cfmJRCEISNhChsvPSH/iDL8xKc2r+u7/oBhB7Y3VIROvqiyTRbfPjvM/zkYQoVz9/vyulPENS9ATEBw9GoYgSGKR6cOOVj334hXnikpX197y1hSrvs1AQwTrPMlj0m5cd12Eq9am1zC8vRwcWhuWXeevGEzkUtaIS9ejlz3/85iocAdbUffXnLUexNwQiH6zy++TekVB9fPqUNJMDBBj5aXB051vVilKjV3/j41/48KVipMBI6V94twCe/FICOMUh6NetZa0FWSAJ5AgFFz67JoJKrTCL+/9mGi2pdNc+/4c/tLJREBRRb2bG5+O67yIBu1xNle0XTb4MzyAIKWrsfP2rdw3vVSB39//h46mhevjJP/bJHackL0bu7YxVFOrVDltDJuqc+qanJoQgJBO11EsPvtYREkhKQChe+Odf3myGG3c+84XDhiTAIAgON9GJybcdEXDCuwfOablOoikHSCFcu+W1Kwc3L/RKXP7PP97d+sgrNy7JCkABBWrLetxFKNfeXGMI9xa5F0m5tgxqiUAEKtlydvt61wmKgg2InR/+8sfvHXSgQEYkERNcOWtVEYWtp+0ghIh3FGtP5GVMRCQhlyByuvLykR1WFITUGeIJezG5CCEsgGCGnfnTCBGi/HSEEL5TnUnOyKKRlBQJSSrj6uUrXUECyDGkoAtSCJokEM9UhxpmD7fowpw7dokdQzQK9okoRPHRQY8LLUp9SouJiC5c91a1hAQYgEbKTZhnCiwuBo3Py7ffsi0VkbMLQnm0SFRT5B65huJcAOEgIqRQqRGznWU/X652lsvZ3v/99//4kFgH+WXHKnYsd0lG7vTamJYksZuUSlgXwaJzPVms430wxLRkJKJ0s9KVfrWzf/3Fq8ud3fmsr7Wb7W+f5WVmP7nPOb/0yVOBoCIPKBxtF5TqgB1zXdPTIFdnSyhMUGarndVy98qt2zf2dhaFQJKI/g7CsiY/3THdWqO1I6TWf/2dMAJypmOUVCZXaQ1toON9LklAIFKCiOWt28/fvvXcwYAVkhRyBHV82Q8WVr4fCeTtL00KKURRclZKkEfFBkhjzvVimCES6CKHFVPb/8hnP/Tczk61k4IICZnw3WZfDLNlL5ZlQOB483dKKCKEWO5DUqYnWqZgUXb5skQlIaawaJdf+swXbs8VgQAFBEI8u1fVYA/TyNeLJ4lfeiMiQAh6EiIh4qMzVKyhdwlzDWCbiNDhJ+9312dyFKQUEkIC5PaNrdBD1qDpDYsB8vDlX7QRROiULkUPkbawgYqU5n3yNoGvXFxcD196pTx6AkURloyQQCAuLl+2mbe5Ll8PBOEffdtYYSPyckTKuYEizfkrBgsbCFG0/MDe0HH00Y99+m5NnT7upXWbrFdnr+h4u4e72sHuuzkOg6dER9myLCBIa9TJfhO9CbmmTKmlmy4/P6d74U+8cn1ZFSXx6fOHSHhofZHvJ+mpXiyL6yenzqjtpRIsyV2NMRBrRA9rXepNnpuQSp8wsrqhv/byldWtD3/4Vt+FLip8TII8z6ue31SodDhKRNNy9dCZK0giyLVG0yAgRpDqIPI8ROT9wWhhozJb3Pxzf+2v/6Uv3pyrQ2GC1dyPrMvy9Xw9+T5iykvjVjYBSaFL+aU0RjGEXCN5m2s6JOwyHF65/bk/+2c+tNv1gWRZmtKF/Kn1VYmIHu5ln49kGwjEpUM9rbeRm4JEsx9EzrDHXO3sHa4WMykEAkQkZ8tv9eXXuTxGMZVHI4JUD4JyhiH76TDTNgXbqIe0kGBVeDwfx03paokQQmAhZqPF+k3zqt4F/a3zWAVgqNTFkUpi4IZFHSIq15XM43IvZht7++Q97+4MuggCxDMr0/JzW8qm6obMZ/dUFVBCCHpjzomxVRJDW7RbOQMjTCpUF5f3ZjUVec4S5NCt/vJSsgiu/MLle2OgBGFB1mA5A4Rn2oroTqSgG+2oAEIQXV3uEDrk2i5cPBid10bI/fK1T2aAZQHGyLUhAX3YJufTDPM+ebSNJA1dmxdHaI3WYkGLfGRcyL2zz1ybJJtnAMEOx2OYGEE5WmjvXi7Lthh7M1hQnz77uK4FLQC/QIGow9MvbgSWEYTBQl8ER8jZAWF6l45KYpJc1xwCUJgvAxncg1aAEDsbZoEMRhLAsljoYTdpuUdiY657SOiKQEoOj3pLCjYf7VgrywJ3bKJDKsPIXXe6GOkK2aQIETiLPmh1cUM7eogi6NJTFIKoKvOr1186KqEAynUeI7NyF08CEvablkR0mOy6WkogPkmut6l1eTth3oaSD0c/W928f+3aUAUiNIu9miAoSG8nFBG/AKTWL87rvFNfS2ftLJfL+RDpo08VSxTEGZ5VR4ywW4QUigjq4uj5B9dW//z3nz5hyFmXilRajCxZ0l6ETPa0+XA3Mk2lqANwbjfb2dwUPukIGnOBGfmpkQItLt3anw2folOL4kaqST2lrsrx/TGnP3I/5XZ+Pq7PW1OmW5uubGBWkFxqxXbrjUSEQm3au3lpXpVyDiPlbPM8j9owXkwvzpSOWM1npZ8vQ9Wb8/NxHJ3Tw1LIPkcBiCN6I9pSdrwsFJKo2+Wdw1KE2YXl4lboVIG01xPr3RATMkWl67t+tph3he36/bO7azDxqT5cptar010SICHB0eKpsCLbbcjLctb2my49JHKN9CaD03FRitNSUS2l61c7q/79Tx+mSf4uRi5ykoYeiurS0ZFTACoaYh0hkTNKprqkPFdI15nJY/RAvP/2lLVfLgaFM4hCq4tLN+4en6OL//DZEEtPrEEPdEqI8DBsW5cSNGXMGdLYQ0zJmdd5HkRP07vveONxqrPd/VXvIFVQWe31eBX/KVPFx8ygJ+IPIjLCrGudaghpVnMQFGl6Ucmht3zZw3zdWJ+P2zadr8eN9i4vh66ohUpZO9zerfUvrYW46F1qkGUi1QMyIo6UfQSoUlmDbpTrDkY/OX6Yvhr303o9ZZvrfne7Xn9htbuYh10zuvne3rxb1GYFUUWxb01QEzRYMWKBLMp+N5SICA4il0IZM5pS5a+AjfLYQ/Ogk2mbMc16/PhhH73Yv7TTeVLpFweruipNCj1TBpi31EhAKc+ZIUw3H+YKSaJct1w7rikMKiGIFEe5dmndlme5niZTsz/N03Uznm9i79pVI3WzOtV+IqLERyQgtMvaswgThERZlYLiQqjSoOfbstxTt/KSMF83hu58aklrTXXV2MbTs3ojFNic954cJaTTt1Y1riCbAEW3IyGQQrZjvi/15lQtQ84e1nQs6uqJR1pQkxOZbdxMPcpGtjv1vCmEyXfNqfhSEMNBBSEgK8i+G7wJgYYe3pZr7g5OzmhUdEzb2k5H1SLEnbtnW4OlFTLHnESXhLEU8yvFCF+g1bLWV2XYgwDpyJfNbiL2/ERm0WBDNrK5PbdfghJl/srwcGw2KRAyIYCrPShno0DIq0uRRjKDlsF3IrIjEOhwnd3ea7l40hJXskvC6My8c2WYRZSq6y+8cZyJ4QgyMS97mDMyJCQOd1umXAeJlFaSs0Lp3IV0261gvjrbeNxipqLFalBIXcHB9ZtWAISiXNvlWrCIemP1xx/DkEepLMguZ2ifMPJ2olx9sgEamqBm2yeHck6gnF0OzIAcF/btaS+uLbKPJHl+dzY29sKU5CztibTlTL6UVtMmSRhxtEXLUtMcie7mkBiiM/tGT+1dIn2mUMTBtY5KYYfUaGleC2l6zF5lNCunmoBEtpEJWqMwYEXeWGQEFgpKX1737gwFRH3hbpmRt1Kc99O8NyN7WsBi9rgxM1PCNomrtay9AdP1gmmQD3js9lgUVZ+PTyjK8vMvUKHyuRiB4MFyTWyMtJy75VuJev2tU62VAIHYcmbUAOFWLvCizmh614iSVCrFVz/eKRWUFM05k/bp9svQlYcnsa8CE5JytC6LDW4pEXkSJs7y48gHUvDibaJcc6ZwR18Y6fr1TJYubd4c1gyQ0xaRY0ialfZ4hhTDUW3rNOxVtzMRioj6YB/Cq4/X9UZi8vKotGffrYGQdg7GNBiB1MLY75xvNhOW2q2PqkbwsQj9RWXrRSMSkpFUolz6YA8ulG4fhkCY0HctwtAdhjBIECky0MPtdjJ25K2r+QwkNm0oqNnDkhIUSNGplPsfQIAAilVBMA/l4Ytlyb6bR9XrXYQCEBYuGXoykRipXA2VoiNyI3XIDD3E3CUpyiz6/v4hEADpNj58Wxb58Rik67sOgZ4VDnFsYyde7itKicVipz5yLrsEobJAKst+3j2/IiBAukJzSG+ufbEbQvLVS3QhLEsWkuIxFGx7f4iQYogxoSSaLguCnIDKYrn44CerDDJQ0hCUe3TJvnhpIR/cLp0QCISrS3/W9xKh2YFKIBlLM6jJc8h8kkCo3zt8/k9fIRBgTyTSW4l6k5zbsXdgYvcDsyiWUFgq2cfCyw4gdislIpjhr5LKdAsRn8/fKaIr/f7te6/sE8YEsCHBYItI7h2YmbbNe6Fg9uI8FRGBwlFKmS37mUoQszyxZNT8ZZC3kSAUrjEMs8Vi5/rzV7scEGLoeuNBl7ObyimCdPSEJEr78uNI5ECySj787oKIyK79+XYFEBejO0pJINSrWy53dlerZS/3YBlxwms5vyxI0IFsVygAUb/y3UDIiii1lkfH/YXib/33eZ/hVHDUy4FQKaXGbLVaVTlVshhDmF4huLj9eGIXQF9+HQlJirKYxfmEUMRrb+3NTL4wPyoKRVcjoutn4XbRC0BMD33rSeSLKu4CSflbZy1QVrXmWqbJIijvvT4FzHQA5xGC1NUodN0wMLVxo40TxPQUx76yoCSQcLz3xnlvanY+36anKZ0tHr8utm3bAIzDdpkdZynRqe+GpVobx5PT13Y/Jts9scSKyLUXVK4hQFZ550kUUWvvFtnSTp29NUVcNjdCZPY6SnzW5+9UopZ+sVsV6c3xt7/7nY+AEKKpqrbglz1kawkwdsbyzWqVuprNJRnJmzdO05xXBB3UjrNWPqGuzFeLbVURJ6+++vj945QCAfyeZ30TAgK1cvPVCMXO0e5QQgDH33o8jQkVqAiThMiWIBhPTtYtulJK6frp+On90+0SBOU7u/Xipyl//MOj3+5ni0sf//iqSLa9SamTYsNsMX4QhiDWx49OWpSI6PpFbNdP2/0TEIDf8firdbk3/Y4Xlz/2qbsEIluUWmsVMSRPnRYIHBDrhw/XNSCEw+OGy/3uRMDUjB05ccy+WrmONvHds9uf+vztimScrRSrFGvKghBGV+pDqlqFzaOH7lXE+ul5y/H8cvl8IQhaU7RxZZYuPWU6SlLa4Wc/cVglU6bH7x2fT9OUgD8oAeqoazmkKPTrd48J4bOnZ5vJ4/pyuXuO89TMQg7SsEZP5MzrdliDdl66PasOT+Ppq288en+zbQn4D+PjmmldUYT62fHbUxC0bcuWyu1aD89FgBYsgshea/QgoVfzNqJFLQFNPn7nZL3etGyWCIpA5NiGJA4VivrlG6eKmM9rF7KhwdNjIvX5Ok0pX9UL9JCcIeEpnhxnm6YpM43gMqGcx5piQUqhEmVx9ChFd/NgmHWBcZP9OXofjyEr6Y43lUJv7osJEuRmPa5VW2ZzS+vCVpGciamZZwNWqd2wf2XldO91YgTYpz/2qrHBsm49PNOCbDaFXSYgJCTl++evXr++iaZZq4MQEKn8q4naBUBIXVlcXTlchjqUIhSS2PzUt5SY8qjDuRuIFin4EoGQ7NwDkghAp099c3l1qRgqEAWCCJ5I8SIwQpESrPZ62726GgpFqaV045dfN6YxhI2cQiAsPQLNy6MUZwBC4/FaoAoQp6FcsIi5GsLO5r0ahaptuhmhKLX3psP4JOyBnA3Gu6tzQWYGYJbH9fk6awI7SYhl1CW7ACr29jSGEKrr9XZM21JEKeN8xjOzhV6HOVPfk+gMIYhpvTk/O9ssZwKqCJBGq84uCCKn88dDh6g+O21TCiFUY+9KCMx2xXd2/Ge0pCOSYX+f9enZZrugBAJC0Crlr2YHEERU+8zLEGW+Pt8kTttOYve5XsIcCvYq37twwrElOY188LmD3GzHcU0VyKlSrYwss66cdwPFXX+6HlMYZ7acP7+DFDwzkIB4sS5i9ipcnWtKfu5PHBSTWcVpEIFHnSyt6aZu+Hp5+NwlwnH2xmI1BAJkHf2xO1FCiAjp0rFppfJnOitXyShOt7MOIWNztoIeaNtztF1ezVZXV5I4PdkZHEUISZ/5k0UXUaJakDlnoCqdrnzzVoLt2KPgD2dYA6EzPQreDLPDwaD1dhG2IlG0o798z2Eh5GzShB1/8i4kPdWhjCHSBmQPgyW7+86aPZC4RbcKgpjGDgpGxPbzf3gIJAMfcr3kL1iH4A1zWjMwNsIM5j7v6wuluIskatQOEYpsRU2Swtvf93ITIMS9oPyFhei8ZAITq2MsieS60ha9kWDRPSREZBPSkCOhRFJ797yv4GwY5W2bvQm5VelNh5ngU2ExiJn1tfHJkEo55y+ZhgBZORMDQ11bSkuR7/3CD/zs6xsHzS69SPLljm2zN4Hgix3HOW0qX766Z1ssYv1JQTpHIlu5PUMh9cN5agpCop1+80f/zX/9ka+euAjpQWZPIl7O/AAElFKPOtoxNZfvfOf2clJ45B4qE8EGUG2YlZ1rVWT70R95tB4bEZZS4LJ7+5UPP4gQzwxJ3st7OBVEGdp3Zy/yUgpFzh6fXl0EZZg0S79AU2S7NJjUt3/snY2pskh7KgDzqx/5Vgv7gpD5Mi85kch6mR/nzW7zbK3/8ZjbBhPygWJFsO77ZtvvPJ5cewrgJoNL6Q9//avghkPK3gkQekPfdHudukwCj/rOfwtA5Od7I8E2YCps1rOWoLCi1JLKTEgnUjc8/Oo7fXNCSnmrAFIpeUO0d/uqPEvk5Ldf3UOOoX5Tb4i0C0YNP52imRA0K92YjFszEMP27M0UeFMK6pJQL715XNbhecKZ0xtjw+myeczBS1UGSlAJT4+2zbWEoW1EtmzJmE6hDq2PU2GO6+ZPl/6eCF1miwh1j08ZgA3JY7QKMgQaYc5efy9nRShF33ACY5uwo+uHsj4ppVAqiETtsG+Hb05F1PG9RBUOuin1gsEuPDiz5fr1h1cGBbb392upin69bS2bu92dQefTEFa5DmQ/J8j0Y8dKlPL2xkngobzMyZ7QSGNQCoSLG5/futaBwS41huVqas7cJl1EKS3mW1aCdlQPed2wEQt5APPsunz+pU4BgnkZPagXotUyz7ZtzO6ta1UJpNT3y13lRlO2Tam1Rt/q/phEzmC6vW0RHcQahBeerYijO7OCLkxKD0p5MKkrLbq4wJv6xdGlHgRINfph6LfBeetKH0Pt2oecR0T5YYh9oVhU3thC2vvIKkOSfII8pw5Fy5IyaIzxhr3Oao3adbYlCJV+Ed1irH0Mtata1ANBvQu5t73QLJDBEO3+AwvwZvJaSFWuqSIgHRA0a6FOm7WGvoZBLpK7vquLYdYPXZS/q09Ct8UX55NWIUzMMLbN3oPBCDDmdZDeYNn5g1RrVhbaOL7/+DjJNk2OyCJlP/SzoSL+/vOpKNfydVDr2EJ0BBiQzunyHk4DKfVCRFPTIKFrQkDNEkzbcXP65OGbb5+cvL+Z952kikoERfHpdM+11ItrY16GmdHYzu1p640z/UzzcqpgzTWYJh1xtFE6W5vGaX16cvLk8clsGPq+iwpGSNlo0wiRPzFJGuLRTNotVhFgTDLvC4L0hpmzzCbYqX3fmf35dt1KxLBYrGoJYUsRKYTMBUFpznU9rVst60mAsbdlQfe3zea3+7MwfSMxf4CAs2ZGuLbt+bRdNzSvfa3UqHXoQ0VNQnFhanmsdVHrlSSjmKakGCIVTH8K9oWj8SAzBbq39JS5WZ9v2KQGqajMu24whggBCNo3XZayDuQFQqL0tSN0sXCRN0MMe9orad3FIIIGrGDV2p0j0TLdRorHZFSbmMbHs2WYIvFPALtKi7JEl7wQCMpqIV0wQp76Yi0UMmO+1I6ORDTRGc006yrjpmitAalomlq2ko+3/arLeVG21TJVzkKZpIRAIanu7QboQpTWUkR7B6ZuB5tnhQiKWk2QNGzTsCJbm5I43a7Xrjc64xY0LGtZE4lEAgao75YiQBimivXwvDmTvHV2oxfIaQk5I7Ft5IZa2m5yO29yufPpPjSty8qf2YKz5ebL32tkX0ByOi/HjhkGqAPeZh1gxnmhhBSQUqaNUm4xxXz3+h/9Q50HCu6svFwre/exhj/2h6Orr/3wD7+J84L+gHxbb5K3gxBml3W8bFrOlnz2CQkDhqPnagh6kte5FigEyCAjLFIy2BF+/t+vv//R35+edyxOpXAv8iqnTmhHQ+vW4rLQSCDBZNUXbxg7ft7EMI4FYGVgYUiyJZuHr7/27W9954efrbUqCKV2YYf5Vl6DdeHW2zw2yELUBBJCux9dTEWzp94VUa5BkFIYowy7jdt0e/PHfvHd9z763R1MGZmQmmtGfQUJEDSWSQfpoofnljRJkFLz7ssbBfT0bUqiSDCRSizImtPmPLfvnX/3e7+ytfYKpQhSPdhlx8T0HRIxUhXhwZdZTwSJQJvK4nM728p9qPqmRYKIascSKuLktG395JvfePzdJwXaPhFlnMtyD2LEYspvBSkz3meahlhHE4Hgoumlz5yp+JLfzuuYYh8R3j598vpbrw8h97em83Vm2gEIEcaL0ctZHvNbpTesACkRSSYOTUC5QffHd8+qdUyX1Jt0mUaVbLM9f+s7bz7ddPPbeGd1eJTTNNlmPHvTCLLbBg050xHRLYg2SCBgzevWhRoh28YP/uFHEs+oHcW7nDHW08P1/x//49dvv346XL9ysL8q1Canc6JhDx7fRKMRDUUed4nojQJYd51zLKwangSYJN7VJWRjgXlmvq3jf/v0sz/c/ff244//99k12Pfrfp1iaKrY4MVakcj8PMhjmLqiRWKNkLtQ5OtDJBct/g/3xZzG2OUH3/3L/++envZF1VrXVTBFMTnkOSXEgmHJTCTXSrepK2euWhJaD6KOT3YB28gg+cj7QgI78vH3/nJ3e91X1TCzmiiIKDL04nQEEdS02FGI+ot0KXZZR6Q41wzGpXSD5QtNAvP9Ggbk8uR3f++z/brXisbOKU8IZubHUdBksdxrzjjgPsHQhJ31bl3AUPLKXqSdnlw3x/uD0Ls4x7D86q999zEzMQMZEcNpQIChF+sLFmGh6bKc/TW6yMtgfCRLpnWxbjIlPjJrtDZOwbd//a2/ci0jb8Mahtl8+xunbZyY6swBZxtDZgvC0kP5toRkiEpBEWLXjxMkImp5mQVGmq59wc6RYfO1X/7Fb+08wfww5zLef4ibhyEmDDMSIAADy9vpTc4ojTlHS1hBuVUA57F1wwHJ6YN7m1a7N77nn/yDd93upG3pIYhr/lajyZiKioQEMt4w87iQevFySM5UhILhMyt1uUYpD/7ZK8S3f/T7vratrwWCYnacGyByvpTA3sxvg+INVZTDdDkbWc4qAHJ/R0m8CKQSf+dvnv7eD//017ZDF0/bPGcnBBQBCSluXCoRCEH6xdtOAEV39EqlUsKFOMCee5T0QFCmD/6rs//1c69niRCz8azBjuQoGODw3qoYZFiGtVi7VdQbhERUjuuWg3TmAfKNBfFiIvLa5776aiAoLs6aCybnAITAauOVS32VzYV70vLTFQJIKE9HEYvBTpAknghJqgUJSbps0yYUuQvYoeNxd6cLIZksjaTSd0UhIp1RShEfOsqOgpLHLBEVAhFW7JfF6SsQyvjOW2PtauDEdi3SfBtY5a42lCK1FIPfWvNcdgARKISEQlM2HGuEwky8+avffPh+MxdlzjVfD6JEeSn9oST4JW/b2AOCEPGMoQHEGFDN9s1f+e6j4/OxYWwuLN9PBGDOHk77iXTy4RBn1K3UEAmblq2SNqicSvbmG398eL4+7zMVx5kfKoigAmIN+NIbBgHKWCecxZiGNDY2wgw1ZeTUlvDxk1zTNFAQ5csYDAgIMrIvMAIEUQG7Lsy9VdkAy8FGA+JimSVrDAgsaO6LJRVZypWTv7xjevOYsmkfS8sZgAhmiL6vHJOXdS/IBJlrBSOTRMAJ55adfYEkPgrNBwlPI0uWpUIJCHmI56koyu25awgjPeqNvpAocFeNAaxd27M+JFLizcekSQS8bBsRwkd/N1l2DtW6SF05f8+9LgRiLy1nJChfOAtAxrhySsf0UPEhWwcgwPPl4+NtjVAIDeRFEUsknxmE4fmLRik9kJSWDAZMOXn0tIPiMI8BFwrKPC0L8tlFsFfIMrZIOR3lzdfWMzDCaD1IRJBNZzU7po5EQbCLyujJB4kMyN3Zb3973fZJkHypggiKiA4SOwRxTpSS2BQRNU/JuA9L8O5X3qW1psgwvQBkLcixBfUknQlzc42gIDaQ66wnMa1Ux5SLk6m0TALidJ7DZ0fmPKc6lJl5TJI9i2wMh6WYNBXQcU8I+Sw4qEuHljMy7VAynpXzYKc3yAYEeSvXhuwjmZKbKvJwgoUuJt2mceKfdBESGOJtvl/IjOeUFGVmKkISueX8H/6LG+LlzWu/LRQclQcfDuhSUZDUr//j/9kxHEW+1AMFnGNHD4hOooqiytAihB3/rvtGxzREbF5HCKeCjPYkoTwqyIUKypw6xBlf16wlJGDvBMEjuTvy+nFjoqBT5AyTHSPMFMR1D0il3B1JPbhwHkVlZopu4BFEAOqRR8UKLyuplOAh04vAQ2zLkSADIkVAMBsE+ebS5SR4uKFO4FBG1+SaIuNUxabTG3TrUSmovCqDS8QhkZKceVxr+b1y6Sv3h0S2RcQJZ057uiQ6Wd6W5E/2hvSdXHBHEUQm1iWGRrTUsY6JnHVc+cW6VYLsCzgDKaJgG6mESc6cCQj6ERHdREgUdUNEZGyUiCh9V3ohJKlIpRQiS/FIr0BdoocTIq7GJw+U5AdELQjJWURAapxG4QVSKl0UVYgi8mWUxyBCREFKJ0QIBE8Ax11vKCSKyL2RNHwbUeVeCXkrcIQyvy7dzjzLvb3cc0VvoiLymDMf8eXLzl47y7tvLIUo2yvfdEOl3kVFa7I36CL/nBII4iUv876j5MsKOW2xC9kNWTrkw4tq0S0VEaU34lEskGVcA0HBfy1xCKrD0RPSAaEkgv8folIKUxEF/ShT05wBRBIi4L/330AFAFZQOCCuNgAA8J8AnQEq8ADwAD5hJI5FJD+hGLxugfgGBLY3caO4szhr+AZIZsH4i/Yr+n5AD+AfwD8DP2G/nusAfwD8AP2q/qtr/5S5+AfgBZgxT/cfyS8Gysfb/63+v35AfJjWf7d/Z/0x/c//d/u/lj0x9e+VJzx/vv8R+6f+g/////+5v+w/4nsX/Uf/S9wL9Tv9h/b/8B/4f7x8XX+q/rnu6/aX8r/gR/SP61/wP9n++HzHf7z/jf533Uf3P/T/+P3BP6h/ZP+b7Y3+49if/E/8b/7e4B/Jf7V/zPXC/8P+z/f/6MP6x/rv/d/o/9t///oL/m39t/8H7V//z/o/QB/v//p7AH/E/9vuU/wD95fb36i/238hPdF4Y/kPyu86/KX9I/feJrFZ708gu+353agX5h/RP91wDYB/rF+xXkPasXjP2AP1n9SP9p4aPpP7P/AF/NP7d/6v9P7uH+L/6v+B+Z3t6+sf/d/rvgH/m/9l/7P+N9tL/ze6H9vP/P7oX6w/9N0mg0L6k3s1CK4nVCP4Nto8ikotFKjNt+JPrRus5nzTKC8zViClAljV/R0U2xfp7PvX4qcJCyx452jgsBymMb4nuO8AvyhTFWBBTXnOjse/26D5hedszYQXeKiccSXD/Ia+hP2OlxtAOyPwVAppswTBx9PEEnnV9COyVHNxTM2MsSMKvNxUuBtbXh01KVV9iI8NYCn8dMkDkD6LkbW0olZxln463a15c/5emYO3Sp7DijzVkloO6yn3XX861MGHzRv6DbDmKZxHl86iaAKx0UmVsDe6lkaOxXIfJl/YWIgtgQ/5te343dPfnBdNUAvJKHZVUQj4xakwV+TJzohYsqMoAuu9xqWrDvuAgyA3ObHnQXf8EsUeWyMGl+DYZi4CBk8ne8uZSsNmisdw1LBN3MGBJ/SZOm8XQRSsiutu/ValvYehA2+xY5kT7Ka5kSJG3tkLn3iiR1dmOqgWo+E7PcrPo1iRyXSFaPTFg8DIR27REoU6Uo4oZs9rHXwp5R0b5rsKeIPTUKIQbdj3VfSQeYhcqAfwFslaM8/eYmL4Jke2nt+EGSHcM8f4Q5snmkrjXcm2BS6zesiCQR7GhywRQ98U4jW37QiqhDPpJ9J7QqD//5iN373jtWZo8EQUfwbRjKjUnpfza4Rsrdr41P/JGFDDqk1b5udfz6e3PRiVnamRU2KIm2fr/wmjrY1y87N4zj2GNPeOBL/64V2rZWKpIMelu2PbD1Ns+ukU1eh6v3EiidfXW4ryHbn1Fo3df/u9XT//cHbtAHxJrZ1GJ2HTrwqJqQL87Km45SZoOZIL+crpLQskAL3kxxzrZoOP4Z4lTcMUcyBg3bRZxgMwD7pA/mbC41YvpKVdv/bb+fwAT3JRi6b/o4UrHmv6cGvTJwLNXlvHkfwpmnCLtqpzh0+iu0QhO9BWkfdSORespHvHKPTo268kE8EPT1aYPA/0IW7OC7Z4IZ79dnKYze1Y7OrZK8zFCi4GUOSdn0HnMyO+QQBwxZpUmi6tlX+my0WcsIXT6BhkNa+hH2Hk3EunasMqY97kqPShUQbfcMBAzbQGx2XyvbUDzFfSWw3Nu5Oh/EUQo4wu5aYPylNXH2gn//jBdlVQq5EVIsNToZHy/Dy14eyMomot/z8VXeNJELvhyD+1vYuG5g2tncrF22dnGuxCMVQKtn1KQSJzdQYWLV0gosTWNP6qb0sdYYpReAD9RLSaujUKoNZc+6MklXoDvTwrxqbstPnXgMC8YvlzQCFYpxjwsNP8T9WMCSOQ2rPdlfBcenlQybWkErSIZT/rb///CO2ws03aiY0StxX7rABdluZwFKmEH7uk3o2Ibf4xE8BK9DLS2W3TmBHVDlT8DBm1sSaOYLO/PbxTMfVRgEPMGQr1AY5dV6+hxGP8IGKa6mTHKuMx09n2ObANZkAJ0rVaO7XGTBcenlzydu7y8TmTwLJG2R//+Zin6ZBbc4b6dLYIix2KFVpe8HNd+H0QAsiMxPv/mx/SfNsj3wfExNwwNovrjYnz5c3IwOMOI4DTeFRMVrmvp7LSFrff9m3x5ftzlXnF+VptcWjoF6ZHkRRRqPqXJoV3O80dKi9QIwbbt/XzSzVRYwtnnz/LrtDGNqrJJPLq2xEkoBU/NR2QSySjWuajsSsUsYQU1Ah2gBidnJ9gRyjMhFrI3nMpKXpHaHEUy8ZpsLk6/57p5NNA3dQ+FdfOnDq00ltLw4ysRLiEd9+vZsCU9VY6vF3QWGa15C9x6zztt5hipFhBTKOhpTQ84M4nMXYm1qSO3Xx1Nu8lwPWNB3RMOY/PSkl0jTK+StUdIzltFt6u6KWhn0Gw3vdWm+b06IswlE1ChJ1eTaKlaJGX4Uk3OAg/1XP/t8Zq56F/K8cyrisixQmThEFQJ6gaS/kyJOe2OJ0pmJHY5JcoL55r9c4TTx6y6ujPcEr6YD8ABB3lsSgFmiEeNuGh7CqQ1U46hn7V/c/J55GOInYaTSzkBKEWA84HhfO0EBQAorGPjs25rv/Lnn8QkWeyd4KGawjnf+Rc/BKe/5fouS9TnhR1wI2kcZOx1DAqAZLTnik09DvTI2wZdJb3Bpde2h/47p4neLlY80HD8VsnBavolKhxqAgNbTJPYOF0ztBbK3QOmhHozRHfyaVUCmowaE+RP6MNgTbfgC6DEAbDF1UM6EGouHXJ3ETQhBkQwYu97Oj89NUiKqvRYxslF7U+g7O9U7+6y5jr/ZQ86wBCRngYudGUqhCrIqADELnMWUAdOO/kDPq0dhTZoH9IpU2wrZQL1EgOvkA3ywc/UaS6Tvoil7WxeZwaDkb4fedd7oxmGbtG7ePduWmLwDlCCcvsanoTv6XPnTICR7r/75XKJVGOnM7wNEO9oGPr2ast/yvfVAw7C9BAxLrwI1a9URzKulRT22UkH9ksQRIcC2jmP/ECZAZq5oXL5phgIevd3UTZsOqSFnjl4N9cOQwK5IFT/IeqhisIrmIscKqTPMdy0KBLjHsUv+lvkPbGfUqb/lBoHjDVlThjcR9M1K+dUfdTTTxBrbhUCN8AEa+I2qZlWkkgRFK+HdP/RZcs4laFWAGiftP9r3//ZZ5b7hxXK9l2YkUbCWvTagu5ODmzfYap1qTdDfdoUBSDNvj50z+iJCB/EwIlWMnZaiWzjsYUl+ZITtYdP/Axdo6rKT/nu9yt3vYhsXi4QNmhxNhz4+rspkQwFuUFLx8Zt4VcRf6p/g+uSVcfe+/tuAWYpDBeg12J96zxY7nZGBBS5qribQUu/2A7F/36f6n+b0UZEM3IVpAl+rSItLo51PXfexUn6+XbMwEIlEuFd0wjaxgfJbYOcx29kijI8xAJGRyXuH50cb8PxPuV3nnPPiVDlh8kk+FeqnrfPmZPINpXMyIX02XMoTU11dir+CTKZe2XfE3/Jlt8RtwE3DthcCXNKKb35lKJMzA0+sGgz8KQCOmSYISiVFURwTjRNRX1mcVsnoInklf6wBJGYB53YjsstFgQsU41cK9gMqPSM6+KFdROrbJYAyZgV9TdRO4a+yBPmG31PLaqSIqOg7mM3SnGM4lh/9tKiSBNsGxYrVgInAt9wS+D3mCdZKPT4CnZu5vZrBB4GFYp+xY51bS+qFrn5FFRA+YN5SgxUiGLH4w0wF8Yvo97enhe9YI2EsxKT7NO5ioagvvIbItyuQR1F8Q6U2w5dQ/RygT23OD6AUMxLo/XWsq2NUPMmVxKDguH/D8tdvvPkdBbKvFHiTdPilw8bJScg5YLddxqUwfARCy+2QyKIVXltw1YqriFv4Jvdy0k90VxQdnJBapnGkOnxLIzwvlecCeQjgdXg13oWWRXchMLFg18Lsax4AOchyfRBbB0kkmTD29GlG/A0uBb1zIglqD6zrDP7kbWmFTvuXF5X+4ePpZvk6iE3RjUDv2+mH4H40hf7hmBvmCxkYeDaMZBUCuv0REaeARwas/PRxPaAWlNNGCsvxgmSj9YyFr0wodh+V9ebT1LLONKXLWevVp8vq7SWN2q8AbNUUfm3hpio6zAjh6jeDAXj2YDsYDp+WlyjYYo+TcabJvxj0uVTc0CeAXDvdvT2ym+SqWkQzRpBjLYMBdoioWHYK/n1ziL1IgA1A+1KbO6NNDBu5mQ9d8vdPJuyj/05yCfwJQSeOXh90lWKESmnXUdAd3RyHznW8K4LA2sfQqexnw2G+kyRYS/FchRma7HDN8HImElbT4F/P7lXduuU7KW+xHZBQ2FLHDs6gyV6jjB3Af4kkBytvFWnm4Ym0SJ7hgYCHb7UwSEkEFTD9go1WKil3Kxs8J6oLN10sOB7jqTGrOCcF2QU/QfZ/S+B2Ym1vZkUyOTiYaj+Bxu51I3JSUTOvq/gwX6my6bD2S7aZrZ2bpHYAIRrle8fohssGlOGKFR9n1nLPgREPkUW5I2rCDLtx6uBNXG30fdsX1842/exnveCT4E42qmsRUs2AcIDGrQ2Y5YnFNgmEsSFQ3Z7v48kBV1lDBGgrWubtQXawuaO9U9MxxP7ZakoT+TXY2viq44rnzlQ6eEOfJINFMzetmDdtIFA5qsZ7l6CmsXsZYvZVX5nC2oIBo9o7hYJOGGYW4a5PGRdn81/UolnnJ7Dy+q7+aaMc4CRLLlcIJLq8z0qwoKZcUeVmedOCvGShstmEBlmSTpQYaRS5ID4GwFKoKwFTAnK3YJPOF6s4qPVWSOx2Nn844nejBrPbtoKM+aL6rbdw7eLWk5V9kPXvjZ27IEtNIgVo5Ddlolb7myIvLYTFU3NRLClEMfCJ5Qucfmmt8G8BjP5whDnE8NeNzQVg1PWItsgr0C5aOm0nCSlWmqiFQxTdUFwtL3CnlwyIiwyfx7nWDIIbxQRWgXmZstaXCKqBdOe16WTrajAoPn4JvWjZ9UOsuJ0Lx2xt1hYQzHIBaX2+RS3KX+xUg8wCiTISEf5ThOMVj4bEHlORWX95YnN/cO1o6hy0Jg9bW4VUu78uM/yrpkLl8bK3K3A4zoq8+QtsrDh8XNGFhux7vZguATEim+0Dv28cSX+sDprBcn/d/xSZCNj20PjCouXHi6/ZiYOBQL8iiynMs5bCJHA5U4oX1axuprQA4USxDRm3t2dQoUQ82V+S9InT/7uB4hFXzYPaKHsYFvvmrlX8UVDCfc6buHqcuJqRsPxMDuRmF9cSzEn2492O+syl81tadRJxnrDIwhPyv6fHgpK1ihdhaF1hHpk4gfuYFRpKZq2WQXVoOkZm7IiuKtiipsZfX5Cc7MIOySnkwmw2VAh08UD261dbkBUOs8zDo9lFiYZAM/xkYgLX4eLfWluUDX2K2MB+kkT9ls61J+nLgEa+ze+gRgtmT0U52I4O6cV1h2LWf7cNba/J9ndCtSJnSn7RMyUUaqSxLIhVqsTqL/M0Zoc6Yw6kw/re8tkTBqzOzV8crYPpsmpXk0dZdGu/w/KzoA/KxrHwYO1Ee0F7zKeY4JsPwuHc+M3EaVyNxD+LjAUf6qvlb4W67O70bX+thJqbsdgpZaiyro+eB22qHKMrWdci47v9tuBoW6AN02hhNjN4oNupEjUtXb8j5U18IBQJ46LaHe7hsSu+Qu0wKfe9yWx58Spq7gItQIK/nKCHN1qsqJtE228wqBgg0vl2OKUDxl5CFmmB3cDFBroYeCWyMr4EBak3kunLyZKTxIzAaendAZBgHVNoF4BLnsC4yJWn5aI2NE4FTBtrdZsTeriNjIxuJgYaUUJglcsuEt7D+SiiXh/5NwyM0/fyf97Y06zaGoLSfhbB2DrqMp/qS59T35j0jYhk/b7X7DtLeCn++b/p/u1DN/mICZtNsYcuj92jisWcHXKUU7epTpjLAnObD1q4XSAlmsqAKiFOoH7E1LYfJhkQhC7V4iEuax74T/dPnCBIeZkx/eU0BLHOEjDfLCqWW7p5Ezo2y9nqVaBgnKfPvkltng25VT1ntrdjFDDFHfxNcMfm6PSvRBXRvdUSHttwd9OM/brL8n3soKMaippYCNSyAIkNqFQhHRvRKYUL2j/pA777pgzUBMK68QQxHzjUufIZ8mu7joJqsOpS1Po4tbjrg8ltGYuIkYfyhdvcho/Tnz5kL4MHWPAb4cpm1zCeVQoj7G3Gfu3emqxqoOASYNOy8KP4NvIoJs+dCy/eB/YV8DVIJ92XCmh6wffWiLJnpg3BrFT505+ctO6T/afjKEyhAyQaABSRL2HFewxniiO84Hf58kCz+Q7yha8sAwQuQYBxqYHi0TqV0rOHtmwK2YzWR094M1j22cc8y2NOS6M0qzTTJh5s7Lfnk3iZ1fhY80yDJnR+K4JDzyTF2ikAf2i98+5qoWSegmHo2Fot+SlKf60cVnuueDgBfo2qKNv+P5iiSJhaAZcpby3oq95tqWJbd5bMbM+qanzVbGNv2I9s0qb2Whyia52P/FHtWIfVsEVlyhGx0CB81CHCpNQC/d6uAkJW7/8t4oueGqj/F6WvTHrNwIRALQdTBYpucR4MRn+adFr6Z//LdM7nJPwKTsnFB/pQmPeL+QOSwSYK3a2gofL4u3MCbfpBZSzVH2IJS1YsMLdxe5Mtiu3PlOSgfDQtUswdIhJbiwWxmxaO2LXiZYBvrVK9HRB/DCQZ+6tvF4Iy4zYwsBe9ydnCLkholiY/fRZ6DS/K3jtSrS04MrdX22QAEdiuo0q4+/PB5S9KEnXsJUPJ662pxWr0NS8iXm5E1gsH6gfDh7awUeoAe4Skn1y6y3ehlkFLGkEq/1C0L1n/o42dnK+c5cVgv99i4+l0m3RQgdo4e4tDngyvVrOMUi1A7/tBy1j2vfBZqgXXpundsBs3vvMcmfSJd6T76MTDbq1upNrsukj9DqpevIIl1c6M4ACIGExKshVp59h7xOpUe3xilQoUiYAPf4PuilUTF8FqAKWVDxGouqLCu61hjEA6Ndzyc4SlnZ19EbUk4fpXG0gSkRCfzs+o5eioclo/0DSup2TSUOxJ/4W1nGwzU99tMfa5adXU08W48k5aaLJYfJjav1RU9sBHQ8eczWS+t8ynC73BkkmzRgL/N2vCApx/1QWC3AyPC4cjriBPzSmMoYqVNiMgZ1XI14fCIR5GOsOK5IiKWwiCl5H+iaa1dldNAxt7k3tgnRHvYee5VHzKuTGHJCz38lSeFS9LeAaSXxBEBwVwEqZnTQD75dr6Ne8ZEO3bYKp8YhjD1Kfhr5hEdAlejt1VpQL4JOFfAF5xNBecgcd04o78MisZMlKzj9lIzl2oMVgeAAxWjY9VrdygzPBB2S02wjs/CHA4VgbqH44il2kR+NWSnicDWyZRCvx6rHXt70LyyLrLqxdXzQT6GMt4KI0A+uudNHlNrvbMNWXBw69RJtXcrhF+mpKBuq7U2XC1LKa7ZiAaM2m/dyGtu3Uhhp38t8Cw1Fb/SoDZK6Gz/kyTFLfDhXeV/RTHHIT/0lO02hML0U8LKIV/4QRBXSymOPC63xhya+gJiEYXFIw6usHCTxtmkBK/g9onaXkHr2EYOmWGVYo8Z9oiei+mL4Ngx1XaVscv6NzLw19HTBWhxc+NLe5Jntx8x7IGaN17MMvaip27czS8q4Ebbb4m0dxjPORfy9Pu8B3uH+TOkU8Cy/5G+bcuWI6uT3T/GP2BxiMckViDItCGQHCRnAV7PNMaZvqAeE8NXoxlKy7ZTCUZFu0xo+n6DjUxo+VTxhqy31N/F3eCT+ovjBbml/T1Z2O/Hpmprq8nvxkQuIrB3KCsl0BxE3NMFt443ngfgscN/U/YWxo5mYKA/R7VTs3utyOyRVspqSsQ8Zz4VYAkS1dQ1A27bhdqSLxPQAQisNSM6m/l9mbvcDfCkzu6wiSWMAR5dTZW4wYNrYNMY65yfUzcHeTQJxvrvnPvLWlIfx5wl+rUNGpB993idm6TucxgqwC+QdG7dhsrPy1K+nuFhhlrul9+ksw4q570/FGlemkRBAlvVxYlZS56lnhLZZZC3xbHV6XjNZunIuEcakIcIAZtv1awjD3ZW60Ml3TW4t3EH+tXY6A57zQQNvOvfh+IINDNQ4U3J42N6E344Xrs0+8mwSNa0CIwUIMCrUfhg5kJMq6eURwZkUYSk2xqFX3tLMNkTcFlH31Fupe40oBGIr4kFcQFA3DVNPj26F6aEa0M9Kusru5e+ukPVfmlM1MZFw084iOzeVIaOt5SIk51Vp2z+lZYPDqIppuJFPX257/K7zc07VgIIPmqHWu7IQ5Los/oi9o768PAvEyTjAJHxFzBJh3tnM8XJI/+d77hH/ZS9WJ8LADIe9D9CshR/yPmhjo3jBwADSJTA01MSUvqDqNl5WNWML2zUZhbGgYUOR4TX+tqfvkcNvprQPU2PqvfbdI9j7Ie7V05tI9g6vJnOs0F6wShqfjAUIIAtI6FD/0reXbYKuqquCPIEf/uEjd2nXSE+t2wwXZQLtreOFkXtTlJThOPKs6DN6RVzQD3fY9HFEaeQHWrHN8ZtRzdoLJZSBHOkFovOEawbaQ7+IzZZKeXka7kL7+Ai26lKFQRJzWTNQmBlFCt+topisnPnJ7jxAhyNuXPMvGRmV5ZXFHTdngCg7YRX8hFw34pTqyNPaus7UFgi/UhqbZAaYjaI1wjXxOKI4BHfXqJ7E/ZqG1vi2k6SAsyhGswyl8x8sKadAP8dBslXPTrAHrCzMnpbnqWOuUYKhYsiG17zjWULk6BmyIa3ZoOLomczue7RIHddjjbLNDb0WfSMvpYX0Djo+0Bu1ocpjy6j28g0m74XJUWhe8A0qWyMsrV6kNOn/o1Tb1Xv/X5sToWLg3r+wmCHMp0DBbTiPOnjXYqAlZ4MMqIp3NnUW41j0RzWmdE0MQGp5qKEs3ZQ3mLd2UJ0RGoSzSlKnNRcY9Lu8lMuv049gP7UMRf2zDyCyXVo81HxCfAwo7PPXb8fq2u1oBB/Ri18RnAtLa0ngmmsUuzKTF83UKRJkP6KPsJTzyYsBkZutlvRYIapvv5Tdupq7W16uIIDHJSxvRxYAWvlcBATWUSQDLoxjdmCceLcguPGQ3vjM/qPIBpDZthRk2O2nW5YlAQXVvc7Q5rOm+8V8PmkdRhW+Ouh1HZ69Sb5mKZwdU9lexKn+ZjFzBYgrVT1Pk6fUcf2JM9a3h9w62kvJfOHHMJYag03RliJpcoThBf7ZoDDmLPUpxH49lW4/0UwPHmS9ZQ/eWfjpuBJTxnMV9LODpxPHtb1Hi4m/CeOToq1Z7BKq+Axjo0GkcyM8cFSsmdrSwV2seJNV6JV6hrf1xAt6e0NChZNE+QKlvNREePfnEvocRqc0UeY6N4igJtfyvtDfqGaw0IZEDF+4nzsREOWuuI5tn6j6eks/vScT3wb2BT+xj7UI8EDL0sqKn7Xe0vKGwV/3+Da3pyd9Lq7IH2Znzep3CBIN3zAFAOSjvGxR8PfgFQdbWtiOsKVABFVIgMuVTl9nKOGeYM2Aen4JxW+T+8vekQrrenbW55GqaVFfk/r7OZd5D2u7rRXmlz95uVMiuhAW0LQ4NiuaFzZuComNynp9HvrJIbr8edGIdFTELtZw+D7vPtqfD7C7G0BnJDrAn2IecVaDzG1tUmd74m+cTvsMUcyzur8JLZML1feLBiE2SLrQutZGxn0vhVgQ5MxSlNWa+uxywsSKB/qPXHP9bou8oNxcQ412GgFoofOdUiUiSoZISaFUS/WAWtGo/Mhz3Ey7qo2gHg0C6wxmKcIznD3Bt2L28Bu2vaxrNglxm1guX+OMkdTg8nI44QXj/Jrbn/ViENpN4MJ/2FNZvoz+hQwaDTLo4z+tSAmVXcd9xFTxjk3nhYFEvyt3t9vlvd1QZfmJJMPBBK3lqwl1VrKg64XJ/bIyJpDW3mMKxEcchHX9bTJ2tHwJoAqC/FlBmN1lZdno6ppLWcQmPwWpLO5tccabsW5cYz1ZkeIFZ5cDbwPXP45RzB8aCpcypr5ycrcwUig38bjbrMjy6bUtCDDrLauz2x5BKP7kboRfOGPqO1A4GR6z3+WxQxm3lWAWCBAOtfHsjsl/d1AN1Lb147gY+T6VEM0PeWQ7NEtuokbkm6WaiUw9upZ4ahRsMhRVr6pGtQL4+HWP6XdfDGXl3WmIpTr2T1Ax9bk7tJontSkkNat4oigDEVYp6bBxqxXXS8N4IAj9QCN+vejdYfbPlAq/rHukDRcT4yRbJ5t691DnN0CGtkvJz/NP3GxM4cLpQRsJWQkNnbJG9N9+pfNrq2KLZTwWXrfEO+h9y2QpSxBVdAS/xII22LxLvC6YiavHTp6fXBb5yQIR81Yo6UgoK2GZXK14F7721HeCuLGdSSToyMDAGj9aInl2+bFQmlgNnBwnLsRnEGkr7e+IpyCXBgPQljMY/oBHsg8TpzDgTNFzQss183intWOQUuGfQ6LAuZKRqswP0/2MTMhy+KmSGrIJu0Jdkl2pQgbMldvMQkY14ttpminP9jjIDsi3tjw2YnJYIdWM2XGWQ8WIdIL0X+CA3c0dCYgyIfJdWICezqpvEopwyLiFDcjQI+/JIZ23NchkFupa8tXf47cwX502SoOMb6DqDPUPfhrgdTh9T0zc6Tjzv7Q29B3xVNSCJABWVTP5J6VuwUBsmrcS8PBp5prhwjo1OhOyqRBbnY58EhHwQy7YX8hthNlpWFZtho35RfxWgwOIMIobnnbNFhOKhJSEWdlj1mqBRIt79ElLwo2VuW5Wy+xFBHOQlysYsQjHoEqwUYO1nmAh/4kLYAytXEJkiiDtWoujY/UWq5/EpyeNKfxX+d/EuYF1OaDoop8yaWporSawi0h+X6W5iLeB5RZiK07nuY2dJz59swArs0XRo9aGQUD+p3VzxdnvmbKH+VdgMiyevDHIJgq/nFoobB+sM0tFC4//8WYyE3MJkDkRM6Kt5hJtTfvw6BaIl3KXuEEJ4EKHAFe+y9OX2JpyeJJm1YHCdxrtK0ZvZy87q052zHzgckLlWwiU4ycBik8mmgz6cVDmNUXSLuJpWRBpKibzo63ow6l1mBULEjTt+KdsYOnu0xHCTTf4mdH+EMYRlESrpGVyr2gk2gTXUEP04phbpo9svGgk1JBE1050/+3jYxBzn32V7PgFT9M7HHlqJnY9oAGIXQ96W1JRkLjO2JKM0p3jYDiTFSOs6Loym+MxH8K5984lALePj6bdztCep73v/LCc+C2CsMMCeSz6Z6gUxjeX+0iwcErsIhDJuzUmpQdyrzDShEkyrDvteXFsumptMDAynBRwjuf5PMaSl5f5ZZkEYWXY2eMGBrfTuG26Pwi6lfdHkIo0vXrWZWiF9Cx9UG516qZJw896ecAzchDSNb0SFFYIcwPfUxZtY63eh3wpwrWIrX7CJmpsgBga01u17/Tl0qwV6SYJKqripi/f2Bw47Non4jn2OFZQ7YLKjSwCGsyuIpQBru+dUIH8oPT9s7obt0quFFKfw8SfeNtxzvjLWt5yvI/eF4mLtEdnT7c3kO2DSlWikuXJQoxxwVB/ib9POR1lS9QPwjzWr7zk6X2hKxVdk7s8lcHcS5eHcjK0MMj119VojVAOmSaeIyiTWJLTcMq0duHdGRZUESbUNnPSH4BN0yEEHnu8czxGAEGST97kvrPbEOZRCXytiMzC8ZjeQvskN0/aF14p70mdvKEoSOD4ksDH3sz04ndDry1xrH6nL3PVorUgtRh+pRFM2uAllPbBrZ+c1emDDUFHTXdXI6gDPOOurS0tfHzFaHRnY2YsnXs9tn3+YB9V3ko2QTXK3RuT3m9UwjfDj6u55gJg/rKVM4+e8RPEk9snYw6MRF91/5rUtJXHAjnCgVulcQzXTc6lQXF3rCAbP8nBgw3pTjozC1pPOna0YeZsQTZwaBSjz8VbGx7o4jBxpo95B+O0rm4bLyawFNbznb+hotCI1bAQTYdOfncLsWgIzLWorS0myQ3PDGCS9003iho5FfF2/epitqdDmfE7jKX/ciMjBegd2uwv0PGqiqF+7fORbz6eHSTUFUWrvCmG1Dhf7zFG/Cioon3JckP/xLrcf5eGvYzr/qafdNyd2dfybxw6r7CNs3Nlc1WnoHV/rRZiZ4e/irgpPhj/mFfJHPgdhLh23pgiZbC6B22TdRY74SgfsJXgKhor89ngEdFBch7ge/iZ9i2P7WcftMxfisI0SyAS371QKbFay81fAYgSqymeS+RlxlM3IbahmcGxX9m1wrznneetuOAbHQQWWa1zT3sj4s/ZDzFQaKlcOkTuPCjR/hcIFe92uTdoan2zxSZdCPhZRvuePq8UECdP19FoVVWibCe56HckmeDTJUEIvPttkIvnMbCP4S6+3RVcryuEzJI+qDo6S5qatX7f25LWXfoi/d4BkXhUVjnkvJ3M+JPx1MxXL2srQqo/v//Swh1cP2+TUVwaZPXcq8XI32O98j4iPHVP0IHkbbGuf4Hs6Q5eQ1VwwdetKn/oymdltk9WxFn7CwHp+eY9Z47frrqRn9UwXXdkvZhmFDJbXWnPDIpjDA/Lh94Fj+/WHwH5R9t90fD5yQTfQJV91pI5v6XTGhHLehZl6OaI48GO0ihbwSfdAA94Mm6PhyTwt3R716+qf/9hzgy58Oebnz6JNISmkkbOigSZO93XScxreZlSCdsCv0BXWJP4Nn9Z5q6t0Pjg9Jsw7P2iNdhXZfUgOryoN1FXmYcZqVroKfXClHt38PKDZILnYah3dqjA7+0eqA96Ig4Q24ILUG4vOCZVzoFWKmrgJ029iepgb1BSYhebpg5Sq6sVtvryhXP9voN7zcgGz8VV2TaPyMhfJQ+Yc65t4C3CvQot0s4rlvlshIviSvZvIhYd7pR26ME5mxsOR0UI2b3NhKaVv2LS5xvLz9oI468Fnp1p+FMPCRtjm3Wh2A2F+p4ZumSCMp9xk/mJBS8aTw1S/5dsb8LH1tDVO7Lns1oi0wbW9od6DeyeOB5NmqQv5N7hfNFzHlSkIjSTplOkuUWabCnGWRK3DH59b+0EruVR8nMeRV0NnGK3FC0PDuXDQKBJeFRMOqZT/Qw58JE5B37XDa33WzvsHqCIS3e7/dDLpWi9Jg/by5Kbw9R/bouVLYkQfQ2sNSoSsAsr/5mJ/onbIPLYo61yYMiZJtXV/GN2yT1Ojj3cPR3h325ERj4sdQ+xEZTkrhhjuyk5QgsnoJ+OqZmHDH9TlVOC8BA4xhRCkA8Qo7AQjAO0ms8RCr1HJEJzf/BjB0bKcrjK1S27zPuO0ZiPTNH40Ec6JVYSg1P224Zuc4jF4vSZHu8XXCn7h7a459FTylZ90EQCPPJVuMjq1hX/L678lXa0VH34g+xoy1lPjAyQXFLsPxP6smp82CdDnv/UC4/EBOU7Jkey4FobD3wqUaDFzMRixhV4ooKJJsj2ZxFONWsGAc8x7hqIy3RfTYhi5NnDttvtLIYkWgCTvqOAXQydGj4AydE6gEcWdEpUjRKIOHjwncS3LCiAvbmYeNM9ZqO/a0OWLHXYN8E7Vj1txy3B2buZ/FMo8hfbPdfQemBavJDhiDMKuPYfzDat9L7414MG9N3Y9QAbZthvXLOf5cnx7wBT5O3TaoRp+bK78W8CofXj1sXKJ43uZFQnNHgNChUoBeKtBghUe+vD/yJ182ImyxbmNe9tNi5ZViWQi4KqX1I5x0TPF8LRCUoxEZuKR0muqyblfCNbL6wviKpsQSmKhVg/P1Q+s/TqJQWbqtLnz8woQ0ivyB7DGtnCKp6nrIUGtWB1UTtJecP8PhuL5hHIa24G9QpN/wjGIDzRc4wUUq+t869/4Ay6UWQOybywyLBJj8oEHyzDYcD9XN7qfe98I1de0/43CMhvc7bGbr3VB1XL7I8nxEAlx1B6jrZkGDdNDEcz5n64vwDGf+e2GfuyOkL5Mn3sxOaXGhtbDzh3x6EnLxYMHuuTzJJAEyKGt1xcqju3yfo+j7eJHOYnGo3ch8WYNyRKOUCOBS7AoMMHMLKzpoB8oe2HIaeCVNvheYMdOPVh6N2Sx1moWkra9a2GXkijY1Lie2iQLPLrmmIjT3SWXjowYI+9MoOzZax3Ea2tAgRh7TAs5zIom3nTe3p8zg6FIIOR2rxeJD6fWJfK/iaYziigjr6avXJ7CcuLa4HSWubuPpADjZd6DTrVDES5fOZEP1YuUz0z8iPg922eodwUn9GpWsf8S2myVZbWJ3MRK0phXzYO4xvd58RNb3xF+MNHJAMng5/6wwVLS9bzG2jHNcFa+Ui6tz00resMliPWrKla0ooez/3zrKE739VMPVWZUSKjTVh8bNSfAbWGI23EkijN2XwpjxT7ZvRJ4VZcV5L9X+bFeROKO/jjyuQSuhAvW0HYMrjXY3SubJm5ZlXKBofPzzwnETN6AsFQgEZWESRPmkvue1XQjaWE6N3inW17nczoEWO4NLLsi7koAExVzUR35pDAhRwzN8ICDfRx4t7WwE+Y1EoYah1yu0LGLxQdpKojxEUyFvpyd6EpjppHzNLEMfmPEKBNG5bOetYvcZiI8naZ1QIh56fQiPkqyPTyao9IrI9SUChtZPiaJLG89vHYp9uQHuiFfpjUSZRgZUGMPW3S1Pj+ktGx59Ba8UEFnHaRMgEYUcWJxm5ec5p1En4MxH1esUFSQq/O+icDkSofxhAnhfJpso7hLVsruJ8xbqNHfsSoupEzxEyp4P59FKERJIHhxYhxa09FEgDEMd50exBkYEKZeKliVaIpPdlx+itQFukWaWmDGBBMLd6mxxQumOv7WXl50OcG7zodidg7vXltrG7d2Nz9FVvwDAeI79cpeHiI7NwSTKPG/LpKMZ7P0WKCIQ0RcBP7CO0EHWTF+hADJkOWebj+GyQILAZnh+Cs0hhMMAeks7UYUe6DURBS97gAL1oS2x0Pq1DSRDA3Z2P3UxMPom2lQzySg/+syT5dZXsvfHalNe/Tw8btBKEOkbklejlfeQMWl3Qo2vUhA2fn+9o+zqnluPcxlyq+Dsqczl9dMZZnAujegrFDPqGXonMLPMpjmQCYW8ppWNxXbkJ0D1/5hsoSHgR+5DkCb1pi35BL3ZapBHOaAGIgonTbFWKHCaQPUgeCxMp/mrlYFN0KPgCeFsXX8a/Lx124ARQo5xsa6m554/yJ+R5zZ3ljC/LgM+bLvzn83g6t9hftZ3NwzDjYfAEU/Y0jVH4zsFtMsOI0L34pIeI6UusWdNtkMAmOWqNpTS3uuB9oYwQVI6qR1m7ivq3htBvRpMx+eENAolVl2/9FflLbAPfdRK8IMh6eBr5qITEZGvVb3d+YhmLx41aU4sEp/A/P1K9YFh/5Q2j2wJcOJLrTCs1tGlHFt1sW6+Nq9u8vzVpZK5FZ1DK9ZS3p2r6OIWONM/3DHTxE9Lbz87wjkk2o5WKaqmCUK3gWcfQcsaMv0NyGp8km/FtNuYlyzLE3ciMjH3/TYLAOY+XUgafc+UprtyPw3s9kdaVlCK1Lcrf0V4DTOl/pr/wpEOImpsyA+9jsJ7QyLz4bv+JUnEOkUZhPqnb+7Tp9vrHQBXjtcElsgSXk+OzbMEJFxNK9UT3Cq7PdN5GiR/Zij1qBTuhV3Ss/7AYJu1TeqjfqvBC7Q1ImEp1bhNfxrNLDI5TayXVf8PoypZRlrOqPi6PO48vTy1SwKCENc2rQsFKWrZOMBHO+ZzM57HYvGj4/gSdbFGrx6nDfeokJIoTqwrB0nSFR5TZIBz1qYyK0TW6nb0y8ke95Aos+Zu5rJgrRfGLv7xWv8JRu3L1LTbJGIZFbDF/a7TfKAG+Gz8auGnIdbMhAVqAFtbJZ6WiDSOvy6RndriPVcWGEU8La2WELL6OLN9WtxpHiF2PS0pHWWjqw0JFEiywXCAbjNuBQF1rKRW9/ig9+DGKBI9IBWcfWAAbTEOyr9KDjow6L1RKIYvxgbSVhG4DnTsOJw6kgtUolZ4FZbjD5XAYHk8cAxag4wM7DXTT6j+0ViteeyvPGuq36Wp0t67V/9dSb0fzmbs+DHwkdc0JudfgRblS1OPyx2kbeCt/xnak1qwsfMi+b27lOgdWydtLZL9lqWzXz45Cg55MJMq67OyWVLTFtMFuwp3xQHWQS7QhPZf8Aw1itugZFAC6Es5QKf+gHkDCi17X4DGVhLdBLuDuH1aIrH+2AZ67kQvOxVR3WytsFjLmyHJg6lataazT5DvI7GNj47OQhvRJFj3MlSIgv8iEL8KOX+E5/xYlZW6rMXjkXPAvyFjJEPJ4IfWlj46tMnEadvekhE9C7iGMlARNWNbGijnnb8hM1WTPB8QloCQyLajgEWHSfsMCttnqC/dck+oV/5d1Hg1vg3Hhsk3EV0M05uySUqAsu7TgmSPCcXMrhoFH00/41jDtTmlqd1XlYJbVXytKX+GZoH1VIesLYfMvcM7sWn1HGbZ4axkUb5X1GFVstffjZf8ADV7uNsN1bChO0gWocNqPbdvdEpudiqS1qEDYxMH3UywX+CwWuEcytRurQwsdWiXMsbQOael9pjGAoAEXF1KDYOKIxMfmVvUfBxN/slL9vMrZmAqguFqlcn0kdBRoV3GlUrzvY2069z3y5hy7v/i/Dt5PBgdC9zW+vM4T3Q68txu4Scj2H9TwcoUN7oIBFq04B6vnHHxV+X/Rqojp8323GRr/1W39YGkGmTEPydF4R1WxqHi/kuwKTFCOu3X+ywfVT2NC+acx6gsRnzNaIVHfY1KFReUIgAdJN53KDBdcBcw/opJ9YaDLWu2BpCJvRifq57zIrbR99H1Hew5VON/ng23sX7D6KyJ0jv3Jr1jVFuSGBYM0r2YGlgJcpBHICouhbVzh9JSmWzCJVrX22Yxm8Ds7bG24I7XFqiESht+VlQCZgvqh7t78THPWBh+D+Y63smsbkkLB0wVMK5vOo5W94JScUxq/09Hd4KTnVDwSCH8wZGd4adwsm2Ke1nuHnua+p2BtTwyk4W1Ub4/6jGbihnAZ8zsr4SUnu5MZQ+V9qsszWWU3B4ItUBC/WsvekVKWndlImWYz6v6iIehZInS514WBWfxIczXrO7r5QVL0qZ777VQqAE2Z2QW9G+CNJMxgWj+VwkKJ7+LflyZNIYV/gK/En9qZ51wdBAAuFD/2ZKA9qT/4gT8WXcNTDZtouf4mxnFBtvA/m8yMvVncuqjf+mfDPkBCO6iCQkAmc3pwHhUTFVYApp4y+Aa+J8ZFYR/JFRrml56XOHxIHeuGZaXiYTPvsBW7Iul1eXfyTZVgqwmx+UKZQlpA69eXRXcAAFiHjwgIwpUSiGCC3p2eiLmrfFEAojxp+CMDurtJmgCw7oarL3k8tfNsMLPVRU7MWXS0diBZAID91P+xqKOXbteWt4vOPrLoxsspIboNor61irDbBYINkBq29vKoMsmTlYG9yvexyb+fR0hMrEUMss+LyChWI4lF8gMCB5sOFXjbKxs9Bs+fjex9rw1Qw1vx8wivxx/C9njWRSpLZ0JsArqUfMJ320orNm+mTIM33GIH3zUZqC9Fc1bGhsDwTwrZj3oygoDjJMB/r1WB4ixQAeLv0ccJjkeGF/KdCCJY7lkI/UiGctQKX4nXOx3I0H3aBJIclrzIXE/r4/iT026B0P1jjuj0rvoBLgfa9WearDbeUcfEcgGU53LT+GVygUdJtk7i5iySAptSWZpxV+5m79GSQ5h9ppsyOOgCPt0d6N1WOxJw+QmZHjlxtjdMi0vG38Y6e1NiN1ZaJXqvatPLiSI5gEo9sSjNyx2y8Rstiw3tyBRUPRD3mte+uaUyEIMZvA7IcIEbqEt3uLlSKDbSvow/LpJakaCWYLjXoOfqnSRk+SqfLzmX6X3qioSLHA2Z0aEZWkzM9XnyAGuXW5QRjU8oY32QZRT1SMpWrHVmyQlHWnPYvzSnO0ZeHXeIAeePkJl1V5ulOs1TIGZ0BDr7vU0rtxVMTvjaQ2vXVmp+sY77ZKRM8dFIAGGuI+2IfAhB+2yZwRGa0rpNh0gx47NIbZYLQHy3FVCs6TX5m6VkVfr+HvIhqGtoOKq+r2rCNddg4ThOueg6Ayl4nL3+jDWpmmXRtzrd4+Xr3DVsft5J3hEsRcXiZupKYgpMyRMnbmGQBK+w6+aBy46w/FSJrxhwlPkBS0MfKnrPRi1cwTlow7hLLarZ/X+YHTNeUh2YrRBUIbEHughER6lDQj8b+paqvo9IUaygxCWy8Ys/Sw/3PRAXdDqpLycEwXdkmwcR4iWkqjlVl+JmstKemaW1CK+fWcJIehWZKuC4lTLfA5C+2yZOuYLLHMDAMuGNAuN7tM8wl8xSU3/mrCHODX+iOnddNlFj/tEgj1vztDecmnxclolG9EA1sXm+9jE4sItbtmW15uP59l1puDN72JjAN6bYpEfO04oYF1pZdI5vIPdO4HwbXoT0zzyTpnIUC9rYLTq9SJ+2Gh/hcqQnWyBkz555sDpNGDltcDL/sUY9pqSGskDTddEytbVjLFbVR4uwCNnVHcENzC3uDF86HeZi5lfS/xIu5L8YRZBrc+6yd1xAvr5HB3z6sQxS2TK/FN2sukZ6+dV71RKU0vA64dcwILVnvYSI0Ma4LwTWLLNu7q9jRe2fwb16ERbbNfr7hN2LeZefE6G+heO7ja1NNHVrolD4MR8qbLwQ2Dilq1TAAEENYThe1c4SfZrTKMXcKpIcRtrN7mqJ7cf5rkiOR4Chsr+ilhxaAGZe8AAAA',
  'wireguard':'data:image/webp;base64,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',
  'highspeed-demo':'data:image/webp;base64,UklGRgwDAABXRUJQVlA4WAoAAAAQAAAA7wAA7wAAQUxQSFYCAAABDzABERGCDm1tiuTmVW0NiFvMUouZWVGJWXbEzGyHTsvM9hyHPJGZmZk5ZGaIdBwJount/j8xBRH9nwAOZfvRs+qK9OR8pBeOkizNkLa8ZqrTPDtwaq64I6NyVurJHpr7DconR71KVqrucIrrsmqlc/p8hTI1c83gYRJ6TRVErpHAgLGjBBnbLj/O2cHLr3yK8sVdowSJY0+eLtn22DRnB0+PPUfSqn2Isr3oN8nUj6ZKElrff5ikjTYX7dlepHbVfLn95iDaOwfR3j+DoACC05yDMMEVTpATl6Md5gVzOeMcVyWUoUn9agXQc/fqrXJA6EjZDWcwoBKlc6ZWuaUXtLqJ67mzys5+8OXMotZEsir/1eDLUESk8qO9oFWQoCdXVdnZBz5c3/FmdsMKUqV+kPIO5jI1YMGgAojY5AWB3FdrQpxY4DmWyv91QeYLTO8GHlxhd4kj7QwkZ9Qb2FHHPEDaAZlie+AExTeNuU2IVvlfBI996//AQ77IVwmQvZpfc6crMj0WplLsLYATuulpsR4edCQ4Y1CXBfDh2xQOMJoK5NhnMDe5wDCjE4A2q7GOQE40S+OAiL2nzoeCzvWipYI6TU6wS+8CgwQzgWR3w81IW5cAb9p9eJkDord6cyYdmH/f0TZLvuPNhlVx9CL2pDdFba+JA0vkJmhjVxlngSh0dZcsqFMCw0hZZ4Av06xwRocwE8md5if27LYoF+1/N0UHJ/M9yjDsUbtlFB1cTHuC726PD6I9vrdIHJ3mzX9EQzRnbNHEWRoy0VEGfxLJ+2qGcUgYVlA4IJAAAABQDwCdASrwAPAAPmEwlkikIyIhICgAgAwJaW7hdrEbQAnsA99snIe+2TkPfbJyHvtk5D32ych77ZOQ99snIe+2TkPfbJyHvtk5D32ych77ZOQ99snIe+2TkPfbJyHvtk5D32ych77ZOQ99snIe+2TkPfbJyHvtk5D32ych77ZOQ99YAAD+/9zlAAAAAAAAAAA=',
  'gaming-lite-demo':'data:image/webp;base64,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