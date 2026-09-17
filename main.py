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
APP_VERSION = "1.0.1"

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
# PANEL UPDATES
# ============================================================
# Public release metadata lives in the GitHub repository.
# Railway credentials stay server-side in environment variables.
UPDATE_REPO = os.environ.get("ONEX_UPDATE_REPO", "HajMeTiV2/ONEX").strip()
UPDATE_BRANCH = os.environ.get("ONEX_UPDATE_BRANCH", "main").strip() or "main"
UPDATE_VERSION_URL = f"https://raw.githubusercontent.com/{UPDATE_REPO}/{UPDATE_BRANCH}/version.json"
UPDATE_GITHUB_API = f"https://api.github.com/repos/{UPDATE_REPO}"
RAILWAY_API_URL = os.environ.get("RAILWAY_API_URL", "https://backboard.railway.com/graphql/v2").strip()
RAILWAY_API_TOKEN = os.environ.get("RAILWAY_API_TOKEN", "").strip()
RAILWAY_SERVICE_ID = os.environ.get("RAILWAY_SERVICE_ID", "").strip()
RAILWAY_ENVIRONMENT_ID = os.environ.get("RAILWAY_ENVIRONMENT_ID", "").strip()


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

<style>
/* ONEX VERSION STRIP — final responsive rules */
.dashboard-hero{grid-template-columns:minmax(0,1fr) auto;grid-template-areas:"hero version";align-items:end}
.dashboard-hero .hero-main{grid-area:hero}
.dashboard-hero .hero-version-strip{grid-area:version}
.dashboard-hero .hero-actions{display:none!important}
.hero-version-strip{justify-content:flex-start}
@media(max-width:768px){
  #page-dash .dashboard-hero{display:grid!important;grid-template-columns:minmax(0,1fr) auto!important;grid-template-areas:"hero version"!important;align-items:center!important;gap:7px!important;margin:0 0 10px!important}
  #page-dash .dashboard-hero .hero-main{grid-area:hero!important;min-width:0}
  #page-dash .dashboard-hero .hero-version-strip{grid-area:version!important;display:flex!important;flex-direction:column!important;gap:5px!important;align-self:center!important}
  #page-dash .dashboard-hero .hero-actions{display:none!important}
  #page-dash .version-mini-card{min-width:105px!important;min-height:43px!important;padding:5px 6px!important;border-radius:11px!important;gap:5px!important}
  #page-dash .version-mini-icon{width:24px!important;height:24px!important;flex-basis:24px!important;border-radius:7px!important;font-size:10px!important}
  #page-dash .version-mini-copy b{font-size:6.5px!important}
  #page-dash .version-mini-copy strong{font-size:10px!important}
  #page-dash .version-live-dot{width:5px!important;height:5px!important;flex-basis:5px!important}
}
@media(max-width:380px){
  #page-dash .dashboard-hero{grid-template-columns:minmax(0,1fr) 98px!important;gap:5px!important}
  #page-dash .version-mini-card{min-width:98px!important;padding:4px!important}
  #page-dash .version-mini-copy b{font-size:6px!important}
  #page-dash .version-mini-copy strong{font-size:9px!important}
}
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
# MULTI-PROTOCOL CREATE
# ============================================================

async def create_all_protocols_sub(request: Request, *, label: str, category_id: str = "0", config_count: int = 1, limit_bytes: int = 0, expires_at: str | None = None, note: str = "", ip_limit: int = 0, speed_limit_bytes: int = 0, connection_limit: int = 0, fragment: str = "off", clean_ips=None, alarm_enabled: bool = False, fingerprint: str = DEFAULT_FINGERPRINT, auto_profiles: dict | None = None):
    base_label = sanitize_config_name((label or "لینک جدید").strip() or project_config_name())
    sub_id, sub = await create_sub_group(name=base_label[:60], desc="ساخت همه پروتکل‌ها باهم")
    sub["all_protocols"] = True
    if isinstance(clean_ips, list):
        clean = [str(x).strip() for x in clean_ips if str(x).strip()]
    else:
        clean = [x.strip() for x in str(clean_ips or "").replace(",", "\n").splitlines() if x.strip()]
    created = []
    for proto in PROTOCOLS:
        cfg = (auto_profiles or {}).get(proto, {})
        uid, link = await make_link(
            label=f"{base_label}-{PROTOCOL_LABELS.get(proto, proto)}",
            limit_bytes=int(cfg.get("limit_bytes", limit_bytes) or 0),
            expires_at=cfg.get("expires_at", expires_at),
            note=cfg.get("note", note),
            sub_id=sub_id, protocol=proto,
            fingerprint=cfg.get("fingerprint", fingerprint),
            alpn=cfg.get("alpn", DEFAULT_ALPN_BY_PROTOCOL.get(proto, "")),
            port=int(cfg.get("port", DEFAULT_PORT) or DEFAULT_PORT),
            ip_limit=int(cfg.get("ip_limit", ip_limit) or 0),
            speed_limit_bytes=int(cfg.get("speed_limit_bytes", speed_limit_bytes) or 0),
            connection_limit=int(cfg.get("connection_limit", connection_limit) or 0),
            fragment=cfg.get("fragment", fragment), clean_ips=cfg.get("clean_ips", clean),
            alarm_enabled=bool(cfg.get("alarm_enabled", alarm_enabled)), category_id=category_id, config_count=config_count)
        created.append((uid, link))
    host=get_host(request)
    first_uid, first_link=created[0]
    result={**get_link_info(first_link, first_uid, host), "ok": True, "all_protocols": True, "created_protocols": len(created), "created_links":[get_link_info(link, uid, host) for uid, link in created], "sub_id": sub_id}
    return result


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

    if bool(body.get("all_protocols", False)):
        limit_value=safe_float(body.get("limit_value", 0))
        limit_unit=str(body.get("limit_unit", "GB") or "GB").upper()
        limit_bytes=0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        expires_days=safe_int(body.get("expires_days", 0), minimum=0)
        expires_at=(datetime.now()+timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
        category_id=str(body.get("category_id") or "0")
        if category_id not in CATEGORIES: category_id="0"
        cat=CATEGORIES.get(category_id) or {}
        if cat.get("limit_bytes") and limit_bytes <= 0: limit_bytes=int(cat["limit_bytes"])
        if cat.get("expires_days") and expires_days <= 0:
            expires_days=int(cat["expires_days"]); expires_at=(datetime.now()+timedelta(days=expires_days)).isoformat()
        label_val=body.get("label", "")
        label_val=project_config_name() if cat.get("random_name") or not str(label_val).strip() else sanitize_config_name(str(label_val))
        return await create_all_protocols_sub(request, label=label_val, category_id=category_id, config_count=safe_int(body.get("config_count",1), minimum=1, maximum=40), limit_bytes=limit_bytes, expires_at=expires_at, note=body.get("note", ""), ip_limit=safe_int(body.get("ip_limit",0),minimum=0), speed_limit_bytes=parse_speed_to_bytes(safe_float(body.get("speed_limit_value",0)), str(body.get("speed_limit_unit","MBIT") or "MBIT").upper()) if safe_float(body.get("speed_limit_value",0))>0 else 0, connection_limit=safe_int(body.get("connection_limit",0),minimum=0), fragment=str(body.get("fragment","off") or "off"), clean_ips=body.get("clean_ips") or body.get("clean_ip") or "", alarm_enabled=bool(body.get("alarm_enabled",False)))

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
    if bool(body.get("all_protocols", False)):
        count=safe_int(body.get("config_count",1), minimum=1, maximum=40)
        profiles={"normal":{"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},"balanced":{"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},"gaming":{"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},"maximum":{"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"}}
        profile=str(body.get("profile","balanced")).strip().lower(); cfg=profiles.get(profile,profiles["balanced"])
        auto_profiles={p:{"ip_limit":cfg["ip"],"connection_limit":cfg["conn"],"speed_limit_bytes":cfg["speed"],"fingerprint":cfg["fp"],"fragment":cfg["fragment"],"note":f"Auto generated by ONEX | profile={profile}"} for p in PROTOCOLS}
        return await create_all_protocols_sub(request,label=project_config_name(),config_count=count,auto_profiles=auto_profiles)
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
    if link.get("sub_id"):
        async with SUBS_LOCK:
            sub = SUBS.get(link.get("sub_id"))
        if sub and sub.get("all_protocols"):
            async with LINKS_LOCK:
                group_links=[(uid2, LINKS.get(uid2)) for uid2 in sub.get("link_ids", [])]
            lines=[]
            total_used=0; total_limit=0; expiries=[]
            for uid2, item in group_links:
                if not item or not is_link_allowed(item): continue
                lines.append(vless_link_for_link(item, uid2, host))
                total_used += int(item.get("used_bytes",0) or 0)
                total_limit += int(item.get("limit_bytes",0) or 0)
                if item.get("expires_at"): expiries.append(str(item["expires_at"]))
                cc=max(1,min(40,int(item.get("config_count") or 1)))
                for _ in range(cc-1): lines.append(vless_link_for_link(item, uid2, host))
            content=base64.b64encode("\n".join(lines).encode()).decode()
            expiry=min(expiries) if expiries else None
            headers=subscription_metadata_headers(total_used,total_limit,expiry,host,f"https://{host}/info/{uuid}",f"{sub.get('name','Subscription')} | همه پروتکل‌ها")
            return Response(content=content,media_type="text/plain; charset=utf-8",headers=headers)
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


def _version_tuple(value):
    """Return a comparable numeric version tuple such as (1, 2, 3)."""
    raw = str(value or "0").strip().lstrip("vV")
    parts = raw.split(".")
    out = []
    for part in parts[:8]:
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits or "0"))
    while len(out) < 3:
        out.append(0)
    return tuple(out)


def _is_newer_version(remote, local):
    return _version_tuple(remote) > _version_tuple(local)


async def fetch_update_info():
    """Read public release metadata and the latest GitHub commit."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ONEX-Panel-Updater",
    }
    timeout = httpx.Timeout(10.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        version_resp = await client.get(UPDATE_VERSION_URL, headers=headers)
        version_resp.raise_for_status()
        meta = version_resp.json()
        if not isinstance(meta, dict):
            raise ValueError("version.json must contain a JSON object")

        commit_resp = await client.get(
            f"{UPDATE_GITHUB_API}/commits/{quote(UPDATE_BRANCH, safe='')}",
            headers=headers,
        )
        commit_resp.raise_for_status()
        commit_data = commit_resp.json()
        sha = str(commit_data.get("sha") or "").strip()
        return {
            "version": str(meta.get("version") or "").strip(),
            "title": str(meta.get("title") or "").strip(),
            "message": str(meta.get("message") or "").strip(),
            "changelog": meta.get("changelog") if isinstance(meta.get("changelog"), list) else [],
            "published_at": str(meta.get("published_at") or "").strip(),
            "commit_sha": sha,
            "repo": UPDATE_REPO,
            "branch": UPDATE_BRANCH,
        }


@app.get("/api/update/check")
async def api_update_check(token=Depends(require_auth)):
    try:
        remote = await fetch_update_info()
        remote_version = remote.get("version") or APP_VERSION
        return {
            "ok": True,
            "current_version": APP_VERSION,
            "latest_version": remote_version,
            "update_available": _is_newer_version(remote_version, APP_VERSION),
            "title": remote.get("title", ""),
            "message": remote.get("message", ""),
            "changelog": remote.get("changelog", []),
            "published_at": remote.get("published_at", ""),
            "configured": bool(RAILWAY_API_TOKEN and RAILWAY_SERVICE_ID and RAILWAY_ENVIRONMENT_ID),
        }
    except Exception as exc:
        logger.warning("Update check failed: %s", exc)
        return {
            "ok": False,
            "current_version": APP_VERSION,
            "latest_version": None,
            "update_available": False,
            "message": "بررسی نسخه جدید انجام نشد",
        }


@app.post("/api/update/deploy")
async def api_update_deploy(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل می‌تواند پنل را بروزرسانی کند")

    if not (RAILWAY_API_TOKEN and RAILWAY_SERVICE_ID and RAILWAY_ENVIRONMENT_ID):
        raise HTTPException(503, detail="تنظیمات اتصال امن Railway برای بروزرسانی کامل نشده است")

    try:
        remote = await fetch_update_info()
        remote_version = remote.get("version") or APP_VERSION
        if not _is_newer_version(remote_version, APP_VERSION):
            return {
                "ok": True,
                "update_available": False,
                "message": "پنل شما آخرین نسخه را دارد",
                "current_version": APP_VERSION,
                "latest_version": remote_version,
            }

        commit_sha = remote.get("commit_sha")
        if not commit_sha:
            raise RuntimeError("GitHub commit SHA not found")

        mutation = """
        mutation ServiceInstanceDeployV2($serviceId: String!, $environmentId: String!, $commitSha: String) {
          serviceInstanceDeployV2(serviceId: $serviceId, environmentId: $environmentId, commitSha: $commitSha)
        }
        """
        payload = {
            "query": mutation,
            "variables": {
                "serviceId": RAILWAY_SERVICE_ID,
                "environmentId": RAILWAY_ENVIRONMENT_ID,
                "commitSha": commit_sha,
            },
        }
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=8.0)) as client:
            response = await client.post(
                RAILWAY_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {RAILWAY_API_TOKEN}",
                    "Content-Type": "application/json",
                    "User-Agent": "ONEX-Panel-Updater",
                },
            )
            response.raise_for_status()
            data = response.json()

        if data.get("errors"):
            raise RuntimeError(str(data["errors"]))
        deployment_id = ((data.get("data") or {}).get("serviceInstanceDeployV2") or "").strip()
        if not deployment_id:
            raise RuntimeError("Railway did not return a deployment id")

        log_activity("system", f"بروزرسانی پنل به نسخه {remote_version} شروع شد", "ok")
        return {
            "ok": True,
            "update_started": True,
            "current_version": APP_VERSION,
            "latest_version": remote_version,
            "deployment_id": deployment_id,
            "message": "بروزرسانی شروع شد؛ پنل پس از استقرار نسخه جدید دوباره در دسترس قرار می‌گیرد.",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Panel update deployment failed")
        raise HTTPException(502, detail=f"شروع بروزرسانی ناموفق بود: {exc}")


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
.dashboard-hero{display:grid;grid-template-columns:minmax(0,1fr) auto auto;align-items:end;gap:12px;margin:0 2px 18px}.hero-main{min-width:0}.hero-version-strip{display:flex;align-items:stretch;gap:8px}.version-mini-card{min-width:128px;min-height:58px;padding:8px 10px;border:1px solid rgba(96,165,250,.18);border-radius:15px;background:linear-gradient(145deg,rgba(12,29,56,.88),rgba(5,13,28,.78));display:flex;align-items:center;gap:8px;box-shadow:0 10px 24px rgba(0,0,0,.20),inset 0 1px rgba(255,255,255,.06)}.version-mini-icon{width:30px;height:30px;flex:0 0 30px;border-radius:10px;display:grid;place-items:center;color:#60a5fa;background:linear-gradient(145deg,rgba(37,99,235,.34),rgba(14,165,233,.14));border:1px solid rgba(96,165,250,.22);font-size:14px;font-weight:900}.version-mini-copy{display:flex;flex-direction:column;gap:2px;min-width:0}.version-mini-copy b{font-size:9px;color:var(--t3);font-weight:700;white-space:nowrap}.version-mini-copy strong{font-size:13px;color:var(--t1);font-weight:900;direction:ltr;text-align:left;white-space:nowrap}.version-live-dot{width:7px;height:7px;flex:0 0 7px;border-radius:50%;background:#22c55e;box-shadow:0 0 10px #22c55e}.dashboard-hero .hero-actions{display:flex;gap:8px;flex-wrap:wrap}.hero-kicker{font-size:10px;letter-spacing:.2em;color:#60a5fa;font-weight:800;text-transform:uppercase}.hero-title{font-size:27px;font-weight:900;line-height:1.25;margin-top:6px}.hero-title span{color:#60a5fa;text-shadow:0 0 22px rgba(96,165,250,.35)}.hero-sub{margin-top:6px;color:var(--t3);font-size:12px}.hero-actions{display:flex;gap:8px;flex-wrap:wrap}
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

  .dashboard-hero{width:100%;margin-bottom:14px;gap:8px;align-items:stretch;grid-template-columns:minmax(0,1fr) auto;grid-template-areas:"hero version" "actions actions"}
  .dashboard-hero .hero-main{grid-area:hero;align-self:center}.hero-version-strip{grid-area:version;display:flex;flex-direction:column;gap:6px;align-self:stretch}.version-mini-card{min-width:116px;min-height:47px;padding:6px 7px;border-radius:12px;gap:6px}.version-mini-icon{width:25px;height:25px;flex-basis:25px;border-radius:8px;font-size:11px}.version-mini-copy b{font-size:7px}.version-mini-copy strong{font-size:11px}.version-live-dot{width:6px;height:6px;flex-basis:6px}.dashboard-hero .hero-actions{grid-area:actions;width:100%;justify-content:stretch}
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
  .hero-title{font-size:22px}.hero-kicker{font-size:8px}.version-mini-card{min-width:104px;min-height:44px;padding:5px}.version-mini-copy b{font-size:6.5px}.version-mini-copy strong{font-size:10px}.dashboard-hero .hero-actions{width:100%;justify-content:stretch}.hero-actions .btn{flex:1;font-size:9px}
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

/* ---------- TOP LANGUAGE / NOTIFICATIONS ---------- */
.top-setting-group{display:flex;align-items:center;gap:3px;padding:3px;border:1px solid var(--card-b);border-radius:11px;background:rgba(255,255,255,.025);box-shadow:inset 0 1px rgba(255,255,255,.04)}
.top-setting-btn{border:0;border-radius:8px;padding:6px 8px;background:transparent;color:var(--t3);font:inherit;font-size:9px;line-height:1;cursor:pointer;transition:.16s ease;white-space:nowrap}.top-setting-btn:hover{color:var(--t1);background:rgba(59,130,246,.10)}.top-setting-btn.active{color:#fff;background:linear-gradient(135deg,#2563eb,#6366f1);box-shadow:0 4px 12px rgba(37,99,235,.25)}
.top-notify-wrap{position:relative}.top-notify-btn{display:flex;align-items:center;gap:5px;border:1px solid var(--card-b);border-radius:11px;padding:7px 9px;background:rgba(255,255,255,.025);color:var(--t2);font:inherit;font-size:9px;cursor:pointer;position:relative;transition:.16s ease}.top-notify-btn:hover{border-color:rgba(59,130,246,.35);color:var(--t1);transform:translateY(-1px)}.notify-bell{font-size:11px;line-height:1}.notify-badge{display:none;min-width:15px;height:15px;padding:0 4px;align-items:center;justify-content:center;border-radius:999px;background:#ef4444;color:#fff;font-size:8px;font-weight:800}.notify-badge.show{display:inline-flex}
.top-notify-panel{position:absolute;top:calc(100% + 9px);right:0;width:300px;max-width:min(300px,calc(100vw - 24px));z-index:1200;border:1px solid rgba(88,180,255,.24);border-radius:16px;background:linear-gradient(145deg,rgba(9,22,43,.96),rgba(2,9,20,.94));box-shadow:0 22px 70px rgba(0,0,0,.42),inset 0 1px rgba(255,255,255,.07);backdrop-filter:blur(25px) saturate(130%);overflow:hidden}.top-notify-panel[hidden]{display:none}.notify-panel-head{display:flex;align-items:center;justify-content:space-between;padding:11px 13px;border-bottom:1px solid rgba(122,180,235,.12);color:var(--t1);font-size:12px}.notify-panel-head button{border:0;background:transparent;color:var(--t3);font-size:20px;cursor:pointer;line-height:1}.notify-list{padding:8px;max-height:360px;overflow:auto}.notify-empty{padding:18px 10px;text-align:center;color:var(--t3);font-size:11px}.notify-item{padding:11px 12px;border:1px solid rgba(88,180,255,.15);border-radius:12px;background:rgba(22,140,255,.045);margin-bottom:7px}.notify-item-title{font-weight:800;color:var(--t1);font-size:12px;margin-bottom:5px}.notify-item-text{color:var(--t2);font-size:11px;line-height:1.8}.notify-item-meta{color:var(--t3);font-size:9px;margin-top:5px}.notify-update-btn{width:100%;border:0;border-radius:9px;padding:8px;background:linear-gradient(135deg,#2563eb,#6366f1);color:#fff;font:inherit;font-size:10px;font-weight:800;cursor:pointer;margin-top:9px}
html.light .top-setting-group,html.light .top-notify-btn{background:#fff!important;border-color:rgba(15,23,42,.10)!important}html.light .top-setting-btn{color:#64748b}html.light .top-setting-btn:hover{background:#f1f5f9;color:#0f172a}html.light .top-notify-panel{background:#fff!important;border-color:rgba(15,23,42,.10)!important;box-shadow:0 18px 50px rgba(15,23,42,.14)!important;backdrop-filter:none}
@media(max-width:700px){.notify-label{display:none}.top-notify-btn{padding:7px 8px}.top-notify-panel{right:-42px;width:290px}}
\n/* ============================================================\n   ONEX THEME ENFORCER — SECONDARY PAGES + NESTED COMPONENTS\n   This block intentionally comes last so old hard-coded dashboard\n   colors cannot win over the selected global theme.\n   ============================================================ */\n\n/* DARK: login glass recipe applied to every structural surface. */\nhtml:not(.light) .page .card,\nhtml:not(.light) .page .metric,\nhtml:not(.light) .page .table-wrap,\nhtml:not(.light) .page .support-tile,\nhtml:not(.light) .page .link-box,\nhtml:not(.light) .page .sub-box,\nhtml:not(.light) .page .quick-item,\nhtml:not(.light) .page .range-tabs,\nhtml:not(.light) .page .range-mini,\nhtml:not(.light) .page .mini-action,\nhtml:not(.light) .page .chart-badge,\nhtml:not(.light) .page .health-track,\nhtml:not(.light) .page .xray-state,\nhtml:not(.light) .page .recent-table,\nhtml:not(.light) .page .recent-table th,\nhtml:not(.light) .page .recent-table td,\nhtml:not(.light) .page .field input,\nhtml:not(.light) .page .field select,\nhtml:not(.light) .page .field textarea{\n  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;\n  border-color:rgba(88,180,255,.18) !important;\n  box-shadow:inset 0 1px rgba(255,255,255,.055),inset 0 0 32px rgba(22,140,255,.035),0 14px 38px rgba(0,0,0,.18) !important;\n  backdrop-filter:blur(25px) saturate(120%) !important;\n  -webkit-backdrop-filter:blur(25px) saturate(120%) !important;\n}\nhtml:not(.light) .page .card,\nhtml:not(.light) .page .metric{\n  box-shadow:0 18px 50px rgba(0,0,0,.34),inset 0 1px rgba(255,255,255,.075),inset 0 0 38px rgba(22,140,255,.045) !important;\n}\nhtml:not(.light) .page .field input,\nhtml:not(.light) .page .field select,\nhtml:not(.light) .page .field textarea{\n  background:linear-gradient(145deg,rgba(2,11,24,.68),rgba(4,14,29,.52)) !important;\n  color:#f8fbff !important;\n}\nhtml:not(.light) .page .page-title,\nhtml:not(.light) .page .card-title,\nhtml:not(.light) .page .metric-val,\nhtml:not(.light) .page .quick-name{color:#f8fbff !important}\nhtml:not(.light) .page .page-sub,\nhtml:not(.light) .page .field label,\nhtml:not(.light) .page .metric-label,\nhtml:not(.light) .page .quick-desc{color:rgba(248,250,252,.55) !important}\n\n/* Preserve intentional accent controls/badges in dark mode. */\nhtml:not(.light) .page .btn-p,\nhtml:not(.light) .page .btn-d,\nhtml:not(.light) .page .range-tab.on,\nhtml:not(.light) .page .conn-badge,\nhtml:not(.light) .page .support-icon,\nhtml:not(.light) .page .quick-icon,\nhtml:not(.light) .page .metric-icon{\n  backdrop-filter:none !important;-webkit-backdrop-filter:none !important;\n}\n\n/* LIGHT: every structural panel becomes pure white, not gray. */\nhtml.light .page,\nhtml.light .page.on{color:#0f172a !important}\nhtml.light .page .card,\nhtml.light .page .metric,\nhtml.light .page .table-wrap,\nhtml.light .page .support-tile,\nhtml.light .page .link-box,\nhtml.light .page .sub-box,\nhtml.light .page .quick-item,\nhtml.light .page .range-tabs,\nhtml.light .page .range-mini,\nhtml.light .page .mini-action,\nhtml.light .page .chart-badge,\nhtml.light .page .health-track,\nhtml.light .page .xray-state,\nhtml.light .page .recent-table,\nhtml.light .page .recent-table th,\nhtml.light .page .recent-table td,\nhtml.light .page .field input,\nhtml.light .page .field select,\nhtml.light .page .field textarea,\nhtml.light .page .onex-topbar,\nhtml.light .page .onex-control-dock,\nhtml.light .page .onex-card,\nhtml.light .page .onex-metric{\n  background:#fff !important;\n  color:#0f172a !important;\n  border-color:rgba(15,23,42,.10) !important;\n  box-shadow:0 10px 30px rgba(15,23,42,.07),inset 0 1px rgba(255,255,255,.98) !important;\n  backdrop-filter:none !important;\n  -webkit-backdrop-filter:none !important;\n}\nhtml.light .page .field input,\nhtml.light .page .field select,\nhtml.light .page .field textarea{\n  background:#fff !important;color:#0f172a !important;border-color:rgba(15,23,42,.14) !important;\n}\nhtml.light .page .page-title,\nhtml.light .page .card-title,\nhtml.light .page .metric-val,\nhtml.light .page .quick-name,\nhtml.light .page .support-val{color:#0f172a !important}\nhtml.light .page .page-sub,\nhtml.light .page .field label,\nhtml.light .page .metric-label,\nhtml.light .page .quick-desc,\nhtml.light .page .support-label,\nhtml.light .page .log-time,\nhtml.light .page .health-name,\nhtml.light .page .health-pct{color:#64748b !important}\nhtml.light .page .log-msg{color:#334155 !important}\nhtml.light .page .onex-card-head,\nhtml.light .page .sb-foot{border-color:rgba(15,23,42,.08) !important}\nhtml.light .page th{background:#fff !important;color:#64748b !important}\nhtml.light .page td{background:#fff !important;color:#334155 !important;border-color:rgba(15,23,42,.08) !important}\nhtml.light .page tr:hover td{background:#f8fafc !important}\n\n/* Inline background declarations on secondary pages: normalize containers\n   while leaving action buttons, badges and icons untouched. */\nhtml.light .page div[style*="background:"],\nhtml.light .page section[style*="background:"],\nhtml.light .page article[style*="background:"],\nhtml.light .page aside[style*="background:"]{\n  background:#fff !important;\n  color:inherit;\n}\nhtml:not(.light) .page div[style*="background:"],\nhtml:not(.light) .page section[style*="background:"],\nhtml:not(.light) .page article[style*="background:"],\nhtml:not(.light) .page aside[style*="background:"]{\n  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;\n}\n/* Re-apply accent colors to controls after the broad inline rule. */\nhtml.light .page .btn-p{background:linear-gradient(135deg,#3b82f6,#6366f1) !important;color:#fff !important;border-color:transparent !important}\nhtml.light .page .btn-d{background:rgba(239,68,68,.08) !important;color:#dc2626 !important;border-color:rgba(239,68,68,.20) !important}\nhtml.light .page .range-tab.on{background:#2563eb !important;color:#fff !important}\nhtml.light .page .switch .slider{background:rgba(148,163,184,.35) !important}\nhtml.light .page .switch input:checked + .slider{background:#16a34a !important}\nhtml.light .page .quick-icon,\nhtml.light .page .support-icon,\nhtml.light .page .metric-icon{background:#f1f5f9 !important}\n\n/* Drawer and mobile top bar use exactly the same theme surfaces. */\nhtml.light .sidebar,html.light .mob-bar{\n  background:#fff !important;color:#0f172a !important;border-color:rgba(15,23,42,.10) !important;\n  box-shadow:0 18px 50px rgba(15,23,42,.12) !important;backdrop-filter:none !important;-webkit-backdrop-filter:none !important;\n}\nhtml:not(.light) .sidebar,html:not(.light) .mob-bar{\n  background:linear-gradient(145deg,rgba(9,22,43,.78),rgba(2,9,20,.68)) !important;\n}\n\n/* Theme switch itself is instant enough that pages never look half-painted. */\nhtml,body,.sidebar,.mob-bar,.main,.page,.page .card,.page .metric,.page .onex-card,.page .onex-metric,\n.page .field input,.page .field select,.page .field textarea,.page .table-wrap,.page .link-box,.page .sub-box{\n  transition:background-color .12s ease,background .12s ease,color .12s ease,border-color .12s ease,box-shadow .12s ease !important;\n}\n/* ============================================================
   LIGHT STATIC 3D PROTOCOL PICKER
   ============================================================ */
#page-create select.protocol-native,#page-create .protocol-field select{display:none!important;position:absolute!important;left:-9999px!important;width:1px!important;height:1px!important;opacity:0!important;pointer-events:none!important;visibility:hidden!important}
#page-create .protocol-field{position:relative}
#page-create .protocol-trigger{width:100%;min-height:46px;display:flex!important;align-items:center;justify-content:space-between;gap:12px;padding:8px 12px;border-radius:13px;border:1px solid rgba(96,165,250,.22);background:linear-gradient(145deg,rgba(18,31,58,.88),rgba(7,14,29,.94));color:var(--t1);cursor:pointer;position:relative;overflow:hidden;box-shadow:inset 0 1px rgba(255,255,255,.06),0 8px 22px rgba(0,0,0,.16)}
#page-create .protocol-trigger:after{content:'⌄';position:absolute;inset-inline-end:10px;top:50%;transform:translateY(-50%);font-size:16px;color:#60a5fa;pointer-events:none}
#page-create .protocol-trigger-main{display:flex;align-items:center;gap:8px;min-width:0;text-align:right}
#page-create .protocol-trigger-icon{width:38px;height:38px;display:grid;place-items:center;flex:0 0 auto}
#page-create .protocol-trigger-icon .protocol-option-icon{margin:0!important;width:38px!important;height:38px!important}.protocol-trigger-icon .static-icon{width:38px!important;height:38px!important}
#page-create .protocol-trigger-text{min-width:0;display:flex;flex-direction:column;gap:1px}.protocol-trigger-name{font-size:12px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.protocol-trigger-sub{font-size:9px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.protocol-picker-bg{position:fixed;inset:0;z-index:1200;display:none;align-items:center;justify-content:center;padding:16px;background:rgba(1,5,14,.62);backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}.protocol-picker-bg.open{display:flex!important}
.protocol-picker{width:min(620px,calc(100vw - 24px));max-height:min(88vh,760px);overflow:hidden;border-radius:24px;border:1px solid rgba(96,165,250,.35);background:linear-gradient(145deg,rgba(7,19,39,.98),rgba(5,11,24,.985));box-shadow:0 30px 90px rgba(0,0,0,.55),0 0 55px rgba(37,99,235,.13);color:var(--t1);display:flex;flex-direction:column}
.protocol-picker-head{padding:17px 18px 15px;border-bottom:1px solid rgba(148,163,184,.12);display:flex;align-items:center;gap:12px;flex:0 0 auto}.protocol-picker-head-icon{width:45px;height:45px;border-radius:14px;display:grid;place-items:center;font-size:24px;background:linear-gradient(145deg,#0ea5e9,#2563eb 55%,#7c3aed);box-shadow:0 10px 26px rgba(37,99,235,.35);border:1px solid rgba(255,255,255,.2)}.protocol-picker-head-text{flex:1;min-width:0}.protocol-picker-title{font-size:17px;font-weight:900}.protocol-picker-subtitle{font-size:10px;color:var(--t3);margin-top:3px}.protocol-picker-close{width:34px;height:34px;border:1px solid rgba(148,163,184,.16);border-radius:10px;background:rgba(255,255,255,.035);color:var(--t2);cursor:pointer;font-size:20px;display:grid;place-items:center}
.protocol-picker-scroll{overflow:auto;padding:14px 16px 16px}.protocol-section{margin-bottom:17px}.protocol-section-title{display:flex;align-items:center;gap:9px;margin:0 2px 9px;color:#93c5fd;font-size:11px;font-weight:900}.protocol-section-title:before{content:"";height:1px;flex:1;background:linear-gradient(90deg,rgba(59,130,246,.05),rgba(59,130,246,.38));order:2}.protocol-section-title span{order:1}.protocol-section-title b{font-size:13px;order:3;font-weight:500}
.protocol-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.protocol-option{position:relative;min-height:108px;border-radius:16px;border:1px solid rgba(96,165,250,.16);background:linear-gradient(145deg,rgba(17,34,62,.74),rgba(7,16,32,.82));padding:7px 10px 10px;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;overflow:hidden;box-shadow:inset 0 1px rgba(255,255,255,.045)}.protocol-option:hover{border-color:rgba(96,165,250,.42)}.protocol-option.selected{border-color:#38bdf8;box-shadow:0 0 0 1px rgba(56,189,248,.18),0 0 22px rgba(37,99,235,.20);background:linear-gradient(145deg,rgba(18,53,91,.88),rgba(22,18,63,.86))}.protocol-option.selected:after{content:"✓";position:absolute;top:7px;right:7px;width:21px;height:21px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(145deg,#38bdf8,#6366f1);color:#fff;font-size:12px;font-weight:900}.protocol-option-radio{position:absolute;top:10px;left:10px;width:16px;height:16px;border-radius:50%;border:2px solid rgba(191,219,254,.65);background:transparent}.protocol-option.selected .protocol-option-radio{border-color:#22d3ee}
.protocol-option-icon.proto-3d{width:76px;height:76px;display:grid;place-items:center;position:relative;z-index:1;flex:0 0 auto}.proto-3d .static-icon{width:74px;height:74px;display:block;object-fit:contain;filter:drop-shadow(0 7px 10px rgba(0,0,0,.30))}.protocol-option-name{font-size:11px;font-weight:900;position:relative;z-index:1;color:#f8fafc}.protocol-option-desc{font-size:8.5px;color:var(--t3);margin-top:2px;position:relative;z-index:1}
.protocol-picker-foot{padding:11px 16px 15px;border-top:1px solid rgba(148,163,184,.12);background:linear-gradient(180deg,rgba(5,13,27,.72),rgba(5,11,24,.98));display:flex;align-items:center;gap:10px;direction:rtl;flex:0 0 auto}.protocol-selected-info{flex:1;min-width:0;height:38px;border-radius:12px;border:1px solid rgba(96,165,250,.16);background:rgba(15,35,64,.55);display:flex;align-items:center;justify-content:center;color:#93c5fd;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding:0 10px}.protocol-picker-confirm{flex:0 0 auto;height:42px;padding:0 18px;border:0;border-radius:12px;background:linear-gradient(135deg,#2196f3,#7c4dff);color:#fff;font-family:inherit;font-size:11px;font-weight:900;cursor:pointer;box-shadow:0 8px 20px rgba(37,99,235,.22)}
html.light .protocol-picker-bg{background:rgba(15,23,42,.28)}html.light .protocol-picker{background:linear-gradient(145deg,#fff,#f7fbff);color:#0f172a}html.light .protocol-option{background:linear-gradient(145deg,#fff,#f7faff)}html.light .protocol-option-name{color:#0f172a}html.light .protocol-option-desc{color:#64748b}html.light .protocol-selected-info{background:#eff6ff;border-color:#bfdbfe;color:#2563eb}
@media(max-width:560px){.protocol-picker-bg{padding:8px}.protocol-picker{width:calc(100vw - 16px);max-height:90vh;border-radius:20px}.protocol-picker-head{padding:13px 14px 12px}.protocol-picker-title{font-size:15px}.protocol-picker-scroll{padding:11px}.protocol-grid{gap:7px}.protocol-option{min-height:104px;padding:7px}.protocol-option-icon.proto-3d{width:64px;height:64px}.proto-3d .static-icon{width:62px;height:62px}.protocol-option-name{font-size:10px}.protocol-option-desc{font-size:7.5px}.protocol-picker-foot{padding:9px 11px 11px;gap:7px}.protocol-selected-info{height:34px;font-size:8px}.protocol-picker-confirm{height:40px;padding:0 12px;font-size:10px}}
@media(max-width:360px){.protocol-grid{grid-template-columns:1fr}.protocol-option{min-height:90px}}
#page-create .field label[data-i18n="label_proto"]:before{content:"✦ ";}
/* Hard guarantee: the two protocol controls are custom buttons, never native selects. */
#page-create .protocol-field{position:relative}
#page-create .protocol-field > .protocol-trigger{display:flex!important;visibility:visible!important;opacity:1!important;position:relative!important;z-index:20!important;width:100%!important;min-height:46px!important}
#page-create .protocol-field > select.protocol-native{display:none!important;pointer-events:none!important}
@media(max-width:560px){#page-create .protocol-field > .protocol-trigger{min-height:48px!important;border-radius:14px!important}.protocol-picker{width:calc(100vw - 20px)!important;max-height:88vh!important}.protocol-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}}

/* Final protocol-picker visibility guard */
#page-create .field:has(> select.protocol-native) { position:relative; }
#page-create .field > select.protocol-native + .protocol-trigger { display:flex!important; visibility:visible!important; opacity:1!important; position:relative!important; z-index:5!important; }
.protocol-picker-bg.open { display:flex!important; }
.protocol-picker { pointer-events:auto; }
@media (max-width:560px){
  .protocol-picker-bg{padding:7px!important;align-items:center!important}
  .protocol-picker{width:min(94vw,620px)!important;max-height:92vh!important;border-radius:22px!important}
  .protocol-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}
  .protocol-option{min-height:88px!important}
}



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


/* ============================================================
   FINAL PROTOCOL UI — COLLAPSED BAR + MODAL ONLY
   Protocol cards must never occupy the create page itself.
   ============================================================ */
#page-create .protocol-field .inline-protocol-picker,
#page-create .inline-protocol-picker{
  display:none !important;
  visibility:hidden !important;
  width:0 !important;
  height:0 !important;
  max-height:0 !important;
  margin:0 !important;
  padding:0 !important;
  overflow:hidden !important;
}
#page-create .protocol-field{position:relative !important;}
#page-create .protocol-field > select.protocol-native{
  display:none !important;
  visibility:hidden !important;
  pointer-events:none !important;
  position:absolute !important;
  width:1px !important;height:1px !important;
  opacity:0 !important;
}
#page-create .protocol-field > .protocol-trigger{
  display:flex !important;
  visibility:visible !important;
  opacity:1 !important;
  width:100% !important;
  min-height:52px !important;
  align-items:center !important;
  justify-content:space-between !important;
  cursor:pointer !important;
}
.protocol-picker-bg{
  position:fixed !important;
  inset:0 !important;
  z-index:2147483000 !important;
  display:none !important;
  align-items:center !important;
  justify-content:center !important;
  padding:12px !important;
  background:rgba(1,5,14,.70) !important;
  backdrop-filter:blur(8px) !important;
  -webkit-backdrop-filter:blur(8px) !important;
}
.protocol-picker-bg.open{
  display:flex !important;
  visibility:visible !important;
  opacity:1 !important;
}
.protocol-picker{
  width:min(680px,calc(100vw - 20px)) !important;
  max-height:min(88vh,760px) !important;
}
@media(max-width:560px){
  .protocol-picker{width:calc(100vw - 16px) !important;max-height:88vh !important;border-radius:20px !important;}
  .protocol-picker-scroll{padding:10px !important;}
  .protocol-grid{grid-template-columns:repeat(2,minmax(0,1fr)) !important;gap:8px !important;}
  .protocol-option{min-height:112px !important;}
}

/* FINAL PROTOCOL DESIGN: one unified grid, no separator bars, true inline 3D protocol cubes */
.protocol-picker-scroll{padding:16px!important;overflow:auto}
.protocol-section{margin:0!important}
.protocol-section-title{display:none!important}
.protocol-grid-all{display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:12px!important}
.protocol-option{min-height:126px!important;border-radius:18px!important;background:linear-gradient(145deg,rgba(8,27,57,.92),rgba(4,14,31,.96))!important;border:1px solid rgba(64,145,255,.24)!important;box-shadow:inset 0 1px rgba(255,255,255,.055),0 8px 24px rgba(0,0,0,.16)!important;transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease!important}
.protocol-option:hover{transform:translateY(-3px)!important;border-color:rgba(37,170,255,.75)!important;box-shadow:0 10px 28px rgba(0,123,255,.16),inset 0 1px rgba(255,255,255,.08)!important}
.protocol-option.selected{transform:translateY(-2px)!important;border-color:#22b7ff!important;box-shadow:0 0 0 1px rgba(34,183,255,.32),0 0 28px rgba(37,99,235,.28),inset 0 1px rgba(255,255,255,.08)!important}
.protocol-option-icon.proto-3d{width:82px!important;height:82px!important}
.lego-proto-svg{width:82px!important;height:82px!important;display:block;overflow:visible}
.proto-3d .static-icon{display:none!important}
#page-create .protocol-trigger-icon{width:44px!important;height:44px!important}
#page-create .protocol-trigger-icon .protocol-option-icon{width:44px!important;height:44px!important}
#page-create .protocol-trigger-icon .lego-proto-svg{width:44px!important;height:44px!important}
@media(max-width:700px){.protocol-grid-all{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:10px!important}.protocol-option{min-height:124px!important}.protocol-option-icon.proto-3d{width:78px!important;height:78px!important}.lego-proto-svg{width:78px!important;height:78px!important}}
@media(max-width:380px){.protocol-grid-all{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}.protocol-option{min-height:112px!important;padding:6px!important}.protocol-option-icon.proto-3d{width:68px!important;height:68px!important}.lego-proto-svg{width:68px!important;height:68px!important}.protocol-option-name{font-size:10px!important}}
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
  <div class="top-actions">
    <div class="top-setting-group" aria-label="Language controls">
      <button type="button" class="top-setting-btn" id="topLangFa" onclick="setLang('fa')">فارسی</button>
      <button type="button" class="top-setting-btn" id="topLangEn" onclick="setLang('en')">EN</button>
    </div>
    <div class="top-notify-wrap">
      <button type="button" class="top-notify-btn" id="topNotifyBtn" onclick="toggleNotifications()" aria-expanded="false"><span class="notify-bell">🔔</span><span class="notify-label">اعلان‌ها</span><span class="notify-badge" id="notifyBadge">0</span></button>
      <div class="top-notify-panel" id="topNotifyPanel" hidden>
        <div class="notify-panel-head"><b id="notifyPanelTitle">اعلان‌ها</b><button type="button" onclick="toggleNotifications(false)">×</button></div>
        <div id="notifyList" class="notify-list"><div class="notify-empty">اعلان جدیدی وجود ندارد.</div></div>
      </div>
    </div>
    <div class="top-avatar">N</div>
  </div>
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
    <div class="hero-main">
      <div class="hero-title">خوش آمدید به <span>ONEX</span></div>
      <div class="hero-sub" id="lastUpd" data-i18n="loading">در حال بارگذاری...</div>
    </div>
    <div class="hero-version-strip" aria-label="Panel version information">
      <div class="version-mini-card">
        <span class="version-mini-icon">▰</span>
        <span class="version-mini-copy"><b data-i18n="panel_version">نسخه پنل</b><strong id="panelVersionValue">v__ONEX_VERSION__</strong></span>
        <i class="version-live-dot"></i>
      </div>
      <div class="version-mini-card">
        <span class="version-mini-icon">↻</span>
        <span class="version-mini-copy"><b data-i18n="current_version">ورژن فعلی</b><strong id="currentVersionValue">v__ONEX_VERSION__</strong></span>
        <i class="version-live-dot"></i>
      </div>
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
      <div class="all-protocol-toggle" role="switch" aria-checked="false" tabindex="0" onclick="toggleAllProtocols('manual')"><div class="all-protocol-copy"><b>ساخت همه پروتکل‌ها باهم</b><span>همه پروتکل‌ها در یک ساب ساخته می‌شوند.</span></div><span class="all-protocol-switch" id="allProtocolsManual"><i></i></span></div>
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
      <div class="all-protocol-toggle" role="switch" aria-checked="false" tabindex="0" onclick="toggleAllProtocols('auto')"><div class="all-protocol-copy"><b>ساخت همه پروتکل‌ها باهم</b><span>همه پروتکل‌ها در یک ساب ساخته می‌شوند.</span></div><span class="all-protocol-switch" id="allProtocolsAuto"><i></i></span></div>
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


<style>
.tg-page-card{overflow:hidden}.tg-head{display:flex;align-items:center;gap:14px;margin-bottom:18px}.tg-head-icon{width:62px;height:62px;position:relative;perspective:500px;flex:0 0 auto}.tg-head-icon .cube{position:absolute;inset:7px;border-radius:14px;background:linear-gradient(145deg,#42dcff,#1687ff 55%,#5d32ff);box-shadow:inset 3px 3px 8px rgba(255,255,255,.35),inset -5px -6px 10px rgba(0,0,0,.2),0 8px 22px rgba(30,130,255,.35);transform:rotateX(-10deg) rotateY(15deg);display:flex;align-items:center;justify-content:center}.tg-head-icon svg{width:31px;height:31px;color:#fff}.tg-links{display:grid;gap:10px}.tg-link{display:flex;align-items:center;gap:13px;padding:13px 15px;border:1px solid rgba(54,151,255,.32);border-radius:17px;background:linear-gradient(135deg,rgba(10,39,78,.82),rgba(5,20,42,.78));text-decoration:none!important;transition:.2s ease}.tg-link:hover{transform:translateY(-2px);border-color:rgba(69,174,255,.8);box-shadow:0 0 22px rgba(31,137,255,.18)}.tg-logo{width:50px;height:50px;position:relative;flex:0 0 50px;perspective:450px}.tg-logo .face,.tg-logo .back{position:absolute;width:38px;height:38px;left:6px;top:6px;border-radius:10px;display:flex;align-items:center;justify-content:center;transform:rotateX(-8deg) rotateY(12deg)}.tg-logo .face{z-index:2;background:linear-gradient(145deg,#56eaff,#1489ff 55%,#5930e8);box-shadow:inset 2px 2px 6px rgba(255,255,255,.4),inset -3px -5px 8px rgba(0,0,0,.2),0 6px 15px rgba(20,125,255,.35)}.tg-logo .back{background:linear-gradient(145deg,#0b4b91,#16245f);transform:translate(6px,5px) rotateX(-8deg) rotateY(12deg)}.tg-logo svg{width:23px;height:23px;color:#fff}.tg-logo.github .face{background:linear-gradient(145deg,#eef4ff,#71839e 52%,#182234)}.tg-logo.github .back{background:linear-gradient(145deg,#44536a,#111a29)}.tg-copy{min-width:0;flex:1}.tg-copy b{display:block;color:var(--t1);font-size:14px;margin-bottom:4px}.tg-copy span{display:block;color:var(--accent2);font-size:13px;direction:ltr;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.tg-arrow{font-size:22px;color:#76bdff}@media(max-width:600px){.tg-link{padding:11px 12px}.tg-copy b{font-size:13px}.tg-copy span{font-size:12px}.tg-head-icon{width:56px;height:56px}.tg-logo{width:46px;height:46px;flex-basis:46px}}


/* ============================================================
   ONEX MOBILE DASHBOARD COMPACT — FIT ALL DASHBOARD BLOCKS
   Phone layout mirrors the compact dashboard composition:
   4 stat tiles in one row, then 2-column dashboard cards.
   ============================================================ */
@media (max-width:768px){
  #page-dash{width:100%;max-width:100%;min-width:0;overflow:visible}
  #page-dash .dashboard-hero{margin:0 0 10px;gap:8px;align-items:center}
  #page-dash .dashboard-hero .hero-actions{display:none!important}
  #page-dash .hero-title{font-size:18px;line-height:1.25;margin-top:0}
  #page-dash .hero-sub{font-size:7px;margin-top:3px}

  #page-dash .onex-metrics{width:100%;grid-template-columns:repeat(4,minmax(0,1fr));gap:5px;margin-bottom:9px}
  #page-dash .onex-metric{min-width:0;min-height:82px;padding:7px 6px;border-radius:12px;display:flex;flex-direction:column;align-items:center;text-align:center}
  #page-dash .metric-icon{width:25px;height:25px;border-radius:8px;flex:0 0 25px}
  #page-dash .metric-icon svg{width:13px;height:13px}
  #page-dash .onex-metric .metric-label{margin:5px 0 2px;font-size:6.5px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
  #page-dash .onex-metric .metric-val{font-size:13px;line-height:1.15;max-width:100%;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #page-dash .metric-trend{left:5px;bottom:5px;font-size:5px}

  #page-dash .dashboard-grid{width:100%;grid-template-columns:repeat(2,minmax(0,1fr));grid-template-areas:"traffic health" "telegram quick" "server recent";gap:8px;align-items:stretch}
  #page-dash .dashboard-grid > div:first-child,#page-dash .dashboard-grid-right{display:contents}
  #page-dash .dashboard-grid > div:first-child > .onex-card:nth-child(1){grid-area:traffic}
  #page-dash .dashboard-grid > div:first-child > .onex-card:nth-child(2){grid-area:quick}
  #page-dash .dashboard-grid > div:first-child > .onex-card:nth-child(3){grid-area:recent}
  #page-dash .dashboard-grid-right > .onex-card:nth-child(1){grid-area:health}
  #page-dash .dashboard-grid-right > .telegram-card{grid-area:telegram}
  #page-dash .dashboard-grid-right > .onex-card:nth-child(3){grid-area:server}

  #page-dash .onex-card,#page-dash .telegram-card{min-width:0;width:100%;border-radius:13px}
  #page-dash .onex-card-head{padding:9px 10px;gap:4px;min-width:0}
  #page-dash .onex-card-title{font-size:8px;gap:4px;min-width:0;white-space:nowrap}
  #page-dash .onex-card-title svg{width:12px;height:12px;flex:0 0 auto}
  #page-dash .onex-card-body{padding:9px 10px}

  #page-dash .chart-wrap{height:135px;padding:4px 4px 7px;min-width:0}
  #page-dash .chart-labels{padding:0 2px;font-size:5.5px}
  #page-dash .chart-badge{top:7px;right:24%;padding:3px 5px;font-size:5px;border-radius:7px;white-space:nowrap}
  #page-dash .range-mini{display:none}

  #page-dash .health-list{gap:7px}
  #page-dash .health-row{grid-template-columns:23px minmax(0,1fr) 24px;gap:5px}
  #page-dash .health-icon{width:23px;height:23px;border-radius:7px;font-size:7px}
  #page-dash .health-name{font-size:6.5px;margin-bottom:2px}
  #page-dash .health-pct{font-size:5.5px}
  #page-dash .health-track{height:4px}
  #page-dash .xray-state{padding:6px 7px;border-radius:7px;font-size:6px;margin-top:2px}

  #page-dash .telegram-card{padding:9px;min-height:100%;justify-content:space-between}
  #page-dash .tg-orbit{width:68px;height:68px;margin:2px auto 6px}
  #page-dash .tg-logo{width:39px;height:39px}
  #page-dash .tg-logo svg{width:20px;height:20px}
  #page-dash .tg-title{font-size:7px}
  #page-dash .tg-handle{font-size:13px;margin-top:3px}
  #page-dash .tg-desc{font-size:5.5px;margin-top:4px;line-height:1.5}
  #page-dash .tg-btn{margin-top:7px;padding:7px 5px;border-radius:8px;font-size:6.5px}

  #page-dash .quick-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:5px}
  #page-dash .quick-item{gap:4px;padding:7px;border-radius:9px;min-width:0;min-height:48px}
  #page-dash .quick-icon{width:25px;height:25px;border-radius:7px;flex:0 0 25px;font-size:15px}
  #page-dash .quick-name{font-size:6.5px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #page-dash .quick-desc{font-size:5.2px;line-height:1.2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

  #page-dash .server-info{gap:5px}
  #page-dash .info-row{padding-bottom:5px;font-size:6.5px;gap:5px}
  #page-dash .info-row span:last-child{max-width:58%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

  #page-dash .recent-card{margin-top:0;min-width:0}
  #page-dash .recent-card .btn{font-size:5.5px;padding:4px 5px;min-height:0}
  #page-dash .recent-table{width:100%;min-width:0!important;table-layout:fixed;font-size:5.5px}
  #page-dash .recent-table th,#page-dash .recent-table td{padding:5px 3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  #page-dash .recent-table th{font-size:5px}
  #page-dash .recent-table th:nth-child(5),#page-dash .recent-table td:nth-child(5){display:none}
  #page-dash .recent-table th:nth-child(1){width:30%}
  #page-dash .recent-table th:nth-child(2){width:21%}
  #page-dash .recent-table th:nth-child(3){width:22%}
  #page-dash .recent-table th:nth-child(4){width:27%}
  #page-dash .recent-card .onex-card-body > div{overflow:hidden!important}

  #page-dash .onex-footer{margin-top:7px;padding:6px 1px;font-size:5.5px;gap:8px}
}
@media (max-width:380px){
  #page-dash .onex-metrics{gap:4px}
  #page-dash .onex-metric{min-height:78px;padding:6px 4px}
  #page-dash .metric-icon{width:23px;height:23px;flex-basis:23px}
  #page-dash .metric-icon svg{width:12px;height:12px}
  #page-dash .onex-metric .metric-label{font-size:6px}
  #page-dash .onex-metric .metric-val{font-size:12px}
  #page-dash .dashboard-grid{gap:6px}
  #page-dash .onex-card-head{padding:8px}
  #page-dash .onex-card-body{padding:8px}
  #page-dash .chart-wrap{height:125px}
  #page-dash .tg-orbit{width:60px;height:60px}
  #page-dash .tg-logo{width:35px;height:35px}
  #page-dash .tg-logo svg{width:18px;height:18px}
  #page-dash .tg-handle{font-size:12px}
  #page-dash .quick-item{padding:6px}
  #page-dash .quick-icon{width:23px;height:23px;flex-basis:23px}
}

.all-protocol-toggle{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;margin:0 0 14px;border:1px solid rgba(43,155,255,.34);border-radius:16px;background:rgba(8,30,58,.55);cursor:pointer}.all-protocol-copy{flex:1;direction:rtl;text-align:right}.all-protocol-copy b{display:block;color:var(--t1);font-size:13px;margin-bottom:3px}.all-protocol-copy span{display:block;color:var(--t2);font-size:10px}.all-protocol-switch{width:50px;height:28px;flex:0 0 50px;border-radius:999px;background:rgba(100,110,125,.5);padding:3px;transition:.2s}.all-protocol-switch i{display:block;width:22px;height:22px;border-radius:50%;background:#eee;transition:.2s}.all-protocol-toggle.on{border-color:rgba(34,230,126,.75)}.all-protocol-toggle.on .all-protocol-switch{background:#18c96b;box-shadow:0 0 14px rgba(24,201,107,.35)}.all-protocol-toggle.on .all-protocol-switch i{transform:translateX(22px)}
</style>
<section class="page" id="page-news">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.7 3.3 18.2 20c-.27 1.2-.98 1.5-1.98.93l-5.22-3.85-2.5 2.4c-.28.28-.51.51-1.05.51l.37-5.3 9.67-8.74c.42-.38-.09-.59-.65-.21L5 12.85.2 11.32c-1.05-.33-1.06-1.05.22-1.55L19.02 2.55c.9-.33 1.67.2 1.58.75Z"/></svg><span>تلگرام</span></div>
    </div>
    <button class="btn btn-sm" onclick="loadNews(true)"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg> بروزرسانی</button>
  </div>
  <div class="card tg-page-card" id="newsCard">
    <div class="tg-head"><div class="tg-head-icon" aria-hidden="true"><div class="cube"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.7 3.3 18.2 20c-.27 1.2-.98 1.5-1.98.93l-5.22-3.85-2.5 2.4c-.28.28-.51.51-1.05.51l.37-5.3 9.67-8.74c.42-.38-.09-.59-.65-.21L5 12.85.2 11.32c-1.05-.33-1.06-1.05.22-1.55L19.02 2.55c.9-.33 1.67.2 1.58.75Z"/></svg></div></div><div><div class="card-title" id="newsTitle">تلگرام</div><div style="color:var(--t3);font-size:12px">آخرین اخبار و اطلاع‌رسانی‌های پروژه</div></div></div>
    <div id="newsBody" class="tg-links">
      <a class="tg-link" href="https://t.me/V2rayTun0" target="_blank" rel="noopener noreferrer"><span class="tg-logo"><span class="back"></span><span class="face"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.7 3.3 18.2 20c-.27 1.2-.98 1.5-1.98.93l-5.22-3.85-2.5 2.4c-.28.28-.51.51-1.05.51l.37-5.3 9.67-8.74c.42-.38-.09-.59-.65-.21L5 12.85.2 11.32c-1.05-.33-1.06-1.05.22-1.55L19.02 2.55c.9-.33 1.67.2 1.58.75Z"/></svg></span></span><span class="tg-copy"><b>کانال تلگرام</b><span>@V2rayTun0</span></span><span class="tg-arrow">↗</span></a>
      <a class="tg-link" href="https://t.me/Mehtif" target="_blank" rel="noopener noreferrer"><span class="tg-logo"><span class="back"></span><span class="face"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M21.7 3.3 18.2 20c-.27 1.2-.98 1.5-1.98.93l-5.22-3.85-2.5 2.4c-.28.28-.51.51-1.05.51l.37-5.3 9.67-8.74c.42-.38-.09-.59-.65-.21L5 12.85.2 11.32c-1.05-.33-1.06-1.05.22-1.55L19.02 2.55c.9-.33 1.67.2 1.58.75Z"/></svg></span></span><span class="tg-copy"><b>سازنده</b><span>@Mehtif</span></span><span class="tg-arrow">↗</span></a>
      <a class="tg-link" href="https://github.com/HajMeTiV2/ONEX" target="_blank" rel="noopener noreferrer"><span class="tg-logo github"><span class="back"></span><span class="face"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 .7a11.3 11.3 0 0 0-3.57 22.02c.56.1.77-.24.77-.54v-2.1c-3.14.68-3.8-1.33-3.8-1.33-.5-1.27-1.22-1.61-1.22-1.61-1-.69.08-.67.08-.67 1.1.08 1.68 1.13 1.68 1.13.98 1.68 2.58 1.2 3.2.92.1-.71.39-1.2.7-1.48-2.51-.29-5.15-1.26-5.15-5.6 0-1.24.44-2.25 1.13-3.05-.11-.28-.49-1.44.11-3 0 0 .92-.3 3.02 1.16A10.5 10.5 0 0 1 12 6.2c.93 0 1.86.13 2.73.37 2.1-1.46 3.02-1.16 3.02-1.16.6 1.56.22 2.72.11 3 .7.8 1.13 1.81 1.13 3.05 0 4.35-2.65 5.3-5.17 5.59.4.34.75 1.02.75 2.06v3.05c0 .3.2.65.78.54A11.3 11.3 0 0 0 12 .7Z"/></svg></span></span><span class="tg-copy"><b>گیت‌هاب پروژه</b><span>https://github.com/HajMeTiV2/ONEX</span></span><span class="tg-arrow">↗</span></a>
    </div>
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
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_groups:'گروه‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',nav_donate:'حمایت مالی',nav_news:'تلگرام',nav_admins:'ادمین‌ها',refresh_news:'بروزرسانی اطلاعیه',admins_sub:'ساخت اکانت ادمین با دسترسی سفارشی',admin_create:'ساخت اکانت ادمین',admin_user:'نام کاربری',admin_pw:'رمز عبور',admin_pw2:'تکرار رمز',admin_perms:'دسترسی‌ها',admin_btn:'ساخت اکانت',admin_list:'لیست ادمین‌ها',refresh:'بروزرسانی',refresh_stats:'بروزرسانی آمار',refresh_panel:'بروزرسانی پنل',panel_version:'نسخه پنل',current_version:'ورژن فعلی',nav_telegram:'ربات تلگرام',tg_sub:'توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک',tg_config:'پیکربندی ربات',tg_token:'توکن ربات (BotFather)',tg_admin:'آیدی عددی ادمین',tg_webhook:'فعال‌سازی Webhook (پیشنهادی روی Railway)',tg_activate:'ذخیره و فعال‌سازی ربات',tg_help:'راهنما',tg_h1:'از @BotFather یک ربات بساز و توکن را کپی کن',tg_h2:'آیدی عددی خودت را از @userinfobot بگیر',tg_h3:'ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا',auto_create:'ساخت خودکار (پیشنهادی)',auto_create_desc:'ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_proto:'پروتکل',label_count:'تعداد کانفیگ در ساب (۱–۴۰)',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',btn_auto:'ساخت خودکار',auto_desc:'با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_groups:'Groups',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',nav_donate:'Donate',nav_news:'Telegram',nav_admins:'Admins',refresh_news:'Refresh news',admins_sub:'Create admin accounts with custom access',admin_create:'Create admin account',admin_user:'Username',admin_pw:'Password',admin_pw2:'Confirm password',admin_perms:'Permissions',admin_btn:'Create account',admin_list:'Admin list',refresh:'Refresh',refresh_stats:'Refresh stats',refresh_panel:'Update panel',panel_version:'Panel version',current_version:'Current version',nav_telegram:'Telegram bot',tg_sub:'Bot token and numeric admin ID · auto activate and webhook',tg_config:'Bot configuration',tg_token:'Bot token (BotFather)',tg_admin:'Admin numeric ID',tg_webhook:'Enable Webhook (recommended on Railway)',tg_activate:'Save and activate bot',tg_help:'Guide',tg_h1:'Create a bot with @BotFather and copy the token',tg_h2:'Get your numeric ID from @userinfobot',tg_h3:'Save — webhook is set automatically on Railway domain',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed, count and expiry',auto_create:'Auto Create (Suggested)',auto_create_desc:'Quick optimal create · VLESS and Sub links',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_proto:'Protocol',label_count:'Configs in sub (1–40)',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',btn_auto:'Auto create',auto_desc:'One click creates an optimal config. VLESS and Sub links will be shown.',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
};
let lang=localStorage.getItem('px_lang')||'fa';
let statRange='month';
function t(k){return (I18N[lang]||I18N.fa)[k]||k}
function setVersionLabels(current,latest){
  const fallback=(document.getElementById('panelVersionValue')?.textContent||'v—').replace(/^v/i,'');
  const c=current||fallback, l=latest||c;
  const pv=document.getElementById('panelVersionValue');
  const cv=document.getElementById('currentVersionValue');
  if(pv)pv.textContent='v'+c;
  if(cv)cv.textContent='v'+c;
  const info=document.getElementById('panelVersionValue');
  if(info){info.title=(l!==c?'Latest: v'+l:'Current: v'+c);}
}
function applyLang(){
  document.getElementById('htmlRoot').lang=lang;
  document.getElementById('htmlRoot').dir=lang==='fa'?'rtl':'ltr';
  document.body.classList.toggle('en',lang==='en');
  document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(I18N[lang][k])el.textContent=I18N[lang][k]});
  const tl=document.getElementById('themeLabel');
  if(tl) tl.textContent=document.documentElement.classList.contains('light')?t('theme_dark'):t('theme_light');
  const lf=document.getElementById('topLangFa'),le=document.getElementById('topLangEn');
  if(lf)lf.classList.toggle('active',lang==='fa'); if(le)le.classList.toggle('active',lang==='en');
  const nb=document.getElementById('topNotifyBtn'); if(nb){const label=nb.querySelector('.notify-label');if(label)label.textContent=lang==='fa'?'اعلان‌ها':'Notifications';}
  const nt=document.getElementById('notifyPanelTitle'); if(nt)nt.textContent=lang==='fa'?'اعلان‌ها':'Notifications';
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
const __allProtocolMode={manual:false,auto:false};
function toggleAllProtocols(mode){__allProtocolMode[mode]=!__allProtocolMode[mode];const sw=document.getElementById(mode==='manual'?'allProtocolsManual':'allProtocolsAuto');const root=sw&&sw.closest('.all-protocol-toggle');if(root){root.classList.toggle('on',__allProtocolMode[mode]);root.setAttribute('aria-checked',__allProtocolMode[mode]?'true':'false')}}
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
  let r=await api('/api/links/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config_count:count,protocol,all_protocols:!!__allProtocolMode.auto})});
  if(!r){
    r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:'auto-'+Date.now().toString(36).slice(-5),limit_value:0,limit_unit:'GB',config_count:count,all_protocols:!!__allProtocolMode.auto})});
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
    speed_limit_unit:'MBIT',
    all_protocols:!!__allProtocolMode.manual
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
let __updateInfo=null;
let __updateCheckBusy=false;
let __updatePollTimer=null;
function updateText(fa,en){return lang==='fa'?fa:en}
function toggleNotifications(force){const panel=document.getElementById('topNotifyPanel'),btn=document.getElementById('topNotifyBtn');if(!panel||!btn)return;const open=typeof force==='boolean'?force:panel.hidden;panel.hidden=!open;btn.setAttribute('aria-expanded',open?'true':'false')}
function renderNotifications(){const list=document.getElementById('notifyList'),badge=document.getElementById('notifyBadge');if(!list||!badge)return;if(!__updateInfo||!__updateInfo.update_available){badge.textContent='0';badge.classList.remove('show');list.innerHTML=`<div class="notify-empty">${updateText('اعلان جدیدی وجود ندارد.','No new notifications.')}</div>`;return;}badge.textContent='1';badge.classList.add('show');const r=__updateInfo;const changes=Array.isArray(r.changelog)&&r.changelog.length?`<div class="notify-item-text" style="margin-top:5px">${r.changelog.slice(0,4).map(x=>`• ${esc(String(x))}`).join('<br>')}</div>`:'';list.innerHTML=`<div class="notify-item"><div class="notify-item-title">🔄 ${esc(r.title||updateText('بروزرسانی جدید پنل','New panel update'))}</div><div class="notify-item-text">${esc(r.message||updateText('نسخه جدید پنل منتشر شده است.','A new panel version is available.'))}</div>${changes}<div class="notify-item-meta">${updateText('نسخه فعلی','Current version')}: ${esc(r.current_version||'—')} → ${esc(r.latest_version||'—')}</div><button type="button" class="notify-update-btn" onclick="toggleNotifications(false);panelUpdate()">${updateText('مشاهده و بروزرسانی','View update')}</button></div>`}
async function checkPanelUpdateWithNotify(showToast=false){if(__updateCheckBusy)return __updateInfo;__updateCheckBusy=true;try{const r=await api('/api/update/check');if(r&&r.ok){const old=__updateInfo&&__updateInfo.latest_version;__updateInfo=r;setVersionLabels(r.current_version||'1.0.1',r.latest_version||r.current_version);renderNotifications();if(r.update_available&&showToast&&old!==r.latest_version)toast(updateText(`نسخه جدید ${r.latest_version} آماده است`,`Version ${r.latest_version} is available`));}return r}catch(e){return null}finally{__updateCheckBusy=false}}
function startUpdateNotificationPolling(){if(__updatePollTimer)clearInterval(__updatePollTimer);checkPanelUpdateWithNotify(false);__updatePollTimer=setInterval(()=>checkPanelUpdateWithNotify(false),45000)}
async function checkPanelUpdate(showToast=true){
  if(__updateCheckBusy)return __updateInfo;
  __updateCheckBusy=true;
  try{
    const r=await api('/api/update/check');
    if(r&&r.ok){
      const previousVersion=__updateInfo&&__updateInfo.latest_version;__updateInfo=r;setVersionLabels(r.current_version||'1.0.1',r.latest_version||r.current_version);renderNotifications();
      if(r.update_available&&showToast&&previousVersion!==r.latest_version){toast(updateText(`نسخه جدید ${r.latest_version} آماده است`, `Version ${r.latest_version} is available`));}
    }
    return r;
  }catch(e){return null}
  finally{__updateCheckBusy=false}
}
async function panelUpdate(){
  const m=document.getElementById('panelModal');
  const t=document.getElementById('panelModalTitle');
  const b=document.getElementById('panelModalBody');
  t.textContent=updateText('در حال بررسی نسخه جدید...','Checking for updates...');
  b.innerHTML='<div style="text-align:center;padding:20px"><div class="spin"></div></div>';
  m.classList.add('open');
  const r=await checkPanelUpdate(false);
  if(!r||!r.ok){
    t.textContent=updateText('بررسی بروزرسانی','Update check');
    b.innerHTML=`<p>${updateText('در حال حاضر امکان بررسی نسخه جدید وجود ندارد.','The update server could not be reached right now.')}</p>`;
    return;
  }
  if(!r.update_available){
    t.textContent=updateText('پنل به‌روز است','Panel is up to date');
    b.innerHTML=`<div style="text-align:center;padding:18px"><div style="font-size:34px;margin-bottom:8px">✓</div><p style="margin-bottom:6px">${updateText('نسخه فعلی پنل: ','Current panel version: ')}<strong>${esc(r.current_version)}</strong></p><p style="color:var(--t3)">${updateText('نسخه جدیدی منتشر نشده است.','No newer version has been released.')}</p></div>`;
    return;
  }
  t.textContent=updateText('بروزرسانی پنل','Panel update');
  const changes=Array.isArray(r.changelog)&&r.changelog.length?`<div style="margin:12px 0;text-align:right"><strong>${updateText('تغییرات نسخه جدید:','What’s new:')}</strong><ul style="margin:8px 0;padding-right:20px">${r.changelog.slice(0,8).map(x=>`<li>${esc(String(x))}</li>`).join('')}</ul></div>`:'';
  b.innerHTML=`<div style="padding:4px 0"><p style="margin-bottom:8px"><strong>${esc(r.title||('ONEX '+r.latest_version))}</strong></p><p style="margin-bottom:8px">${esc(r.message||updateText('نسخه جدید پنل آماده است.','A new panel version is available.'))}</p>${changes}<p style="color:var(--t3);font-size:12px">${updateText('نسخه فعلی: ','Current: ')}${esc(r.current_version)} &nbsp;→&nbsp; ${updateText('نسخه جدید: ','New: ')}${esc(r.latest_version)}</p><button type="button" class="btn btn-primary" id="panelDoUpdate" style="width:100%;margin-top:14px">${updateText('شروع بروزرسانی پنل','Update panel now')}</button></div>`;
  document.getElementById('panelDoUpdate').onclick=deployPanelUpdate;
}
async function deployPanelUpdate(){
  const btn=document.getElementById('panelDoUpdate');
  if(btn){btn.disabled=true;btn.textContent=updateText('در حال شروع بروزرسانی...','Starting update...')}
  const r=await api('/api/update/deploy',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  if(r&&r.ok&&r.update_started){
    const b=document.getElementById('panelModalBody');
    if(b)b.innerHTML=`<div style="text-align:center;padding:18px"><div class="spin" style="margin:0 auto 14px"></div><p>${updateText('بروزرسانی شروع شد. پنل پس از استقرار نسخه جدید دوباره در دسترس قرار می‌گیرد.','The update has started. The panel will become available again after the new deployment is live.')}</p><p style="color:var(--t3);font-size:12px;margin-top:8px">${esc(r.latest_version||'')}</p></div>`;
    setTimeout(()=>{location.reload()},12000);
    return;
  }
  if(btn){btn.disabled=false;btn.textContent=updateText('شروع بروزرسانی پنل','Update panel now')}
  toast((r&&r.detail)||updateText('شروع بروزرسانی ناموفق بود','Could not start the update'));
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
  try{
    const r=await api('/api/news');
    const meta=document.getElementById('newsMeta');
    if(meta && r) meta.textContent=(lang==='fa'?'آخرین بروزرسانی: ':'Last update: ')+(r.updated_at||'—');
    if(toastOk) toast(lang==='fa'?'اطلاعات تلگرام بروزرسانی شد':'Telegram info refreshed');
  }catch(e){
    if(toastOk) toast(lang==='fa'?'خطا در بروزرسانی':'Refresh failed');
  }
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
   LIGHT STATIC 3D PROTOCOL PICKER
   ============================================================ */
const PROTOCOL_PICKER_GROUPS=[
  {title:'',ids:['vless-ws','xhttp-packet-up','xhttp-stream-up','xhttp-stream-one','vmess-ws','trojan-ws','shadowsocks','socks5','http','hysteria2','tuic','wireguard','highspeed-demo','gaming-lite-demo']}
];
const PROTOCOL_PICKER_NAMES={"vless-ws":"Vortex Link","xhttp-packet-up":"XPacket Flow","xhttp-stream-up":"XStream Pulse","xhttp-stream-one":"XStream Core","vmess-ws":"VMesh Nova","trojan-ws":"Trojan Glide","shadowsocks":"Shadow Mesh","socks5":"Socket Guard","http":"Web Shield","hysteria2":"Hysteria Nova","tuic":"TUIC Blaze","wireguard":"WireGuard Orbit","highspeed-demo":"Turbo Surge","gaming-lite-demo":"Game Pulse"};
const PROTOCOL_3D_ICONS={
  "vless-ws":{c1:"#24a9ff",c2:"#1264ff",c3:"#6d3cff",mark:"V",glow:"#168cff"},
  "xhttp-packet-up":{c1:"#35c8ff",c2:"#0877d8",c3:"#3155ff",mark:"XP",glow:"#21b8ff"},
  "xhttp-stream-up":{c1:"#36e6ff",c2:"#0894c9",c3:"#16b7d1",mark:"XS",glow:"#21d9ee"},
  "xhttp-stream-one":{c1:"#b04cff",c2:"#6b1fe1",c3:"#3b25ad",mark:"XC",glow:"#a14cff"},
  "vmess-ws":{c1:"#d05cff",c2:"#7726e8",c3:"#4522a6",mark:"M",glow:"#a54cff"},
  "trojan-ws":{c1:"#ff6676",c2:"#e51c35",c3:"#a90f2b",mark:"T",glow:"#ff4058"},
  "shadowsocks":{c1:"#54e887",c2:"#11ae57",c3:"#078341",mark:"S",glow:"#22d66c"},
  "socks5":{c1:"#45dfff",c2:"#0b9fc8",c3:"#08779e",mark:"5",glow:"#20d5ff"},
  "http":{c1:"#78a7ff",c2:"#3975e8",c3:"#2448a9",mark:"H",glow:"#4d8cff"},
  "hysteria2":{c1:"#55e9ff",c2:"#08a9c5",c3:"#087b99",mark:"H2",glow:"#21dfff"},
  "tuic":{c1:"#ff9b39",c2:"#ef6518",c3:"#b93d0e",mark:"T",glow:"#ff8525"},
  "wireguard":{c1:"#a87bff",c2:"#7138df",c3:"#4120a7",mark:"W",glow:"#985cff"},
  "highspeed-demo":{c1:"#ff5b73",c2:"#e5263f",c3:"#a9142c",mark:"⚡",glow:"#ff3654"},
  "gaming-lite-demo":{c1:"#ad64ff",c2:"#6b2be0",c3:"#3c1b9c",mark:"⌁",glow:"#a447ff"}
};
let __protocolPickerTarget='' ;
let __protocolPickerOptions=[];
function protocolPickerLabel(id){const p=__protocolPickerOptions.find(x=>x.id===id);return PROTOCOL_PICKER_NAMES[id]||p?.label||id||'Vortex Link'}
function protocolPickerShort(id){return PROTOCOL_PICKER_NAMES[id]||id}
function protocolIconMarkup(id){
  const p=PROTOCOL_3D_ICONS[id]||PROTOCOL_3D_ICONS['vless-ws'];
  const safe=String(p.mark).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  const uid='pi'+String(id).replace(/[^a-z0-9]/gi,'');
  return `<span class="protocol-option-icon proto-3d" aria-hidden="true"><svg class="lego-proto-svg" viewBox="0 0 100 100" role="img">
    <defs><linearGradient id="${uid}a" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${p.c1}"/><stop offset="1" stop-color="${p.c2}"/></linearGradient><linearGradient id="${uid}b" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${p.c2}"/><stop offset="1" stop-color="${p.c3}"/></linearGradient><filter id="${uid}g"><feDropShadow dx="0" dy="5" stdDeviation="4" flood-color="${p.glow}" flood-opacity=".42"/></filter></defs>
    <g filter="url(#${uid}g)"><path d="M18 30 49 15 82 30 51 47Z" fill="url(#${uid}a)" stroke="rgba(255,255,255,.35)" stroke-width="1.2"/><path d="M18 30v40l33 18V47Z" fill="url(#${uid}b)" stroke="rgba(255,255,255,.2)" stroke-width="1.2"/><path d="M51 47 82 30v40L51 88Z" fill="${p.c3}" stroke="rgba(255,255,255,.18)" stroke-width="1.2"/><g fill="rgba(255,255,255,.35)"><ellipse cx="31" cy="29" rx="5" ry="2.6"/><ellipse cx="48" cy="22" rx="5" ry="2.6"/><ellipse cx="65" cy="30" rx="5" ry="2.6"/><ellipse cx="39" cy="36" rx="5" ry="2.6"/></g><text x="50" y="64" text-anchor="middle" font-family="Arial,sans-serif" font-size="${safe.length>1?16:25}" font-weight="900" fill="#fff" stroke="rgba(0,0,0,.12)" stroke-width="1">${safe}</text></g>
  </svg></span>`
}
function setupProtocolPickers(){['cProto','aProto'].forEach(id=>{const sel=document.getElementById(id);if(!sel)return;sel.classList.add('protocol-native');sel.style.setProperty('display','none','important');sel.setAttribute('aria-hidden','true');let trigger=sel.parentNode.querySelector(`.protocol-trigger[data-for="${id}"]`);if(!trigger){trigger=document.createElement('button');trigger.type='button';trigger.className='protocol-trigger';trigger.dataset.for=id;sel.parentNode.insertBefore(trigger,sel.nextSibling)}trigger.onclick=e=>{e.preventDefault();openProtocolPicker(id)};syncProtocolPicker(id)})}
function syncProtocolPicker(id){const sel=document.getElementById(id),trigger=document.querySelector(`.protocol-trigger[data-for="${id}"]`);if(!sel||!trigger)return;const value=sel.value||'vless-ws';trigger.innerHTML=`<span class="protocol-trigger-main"><span class="protocol-trigger-icon">${protocolIconMarkup(value)}</span><span class="protocol-trigger-text"><span class="protocol-trigger-name">${esc(protocolPickerShort(value))}</span><span class="protocol-trigger-sub">${lang==='fa'?'برای تغییر، انتخاب کنید':'Tap to choose another protocol'}</span></span></span><span class="protocol-trigger-arrow">⌄</span>`}
function ensureProtocolPicker(){let bg=document.getElementById('protocolPickerBg');if(bg)return bg;bg=document.createElement('div');bg.id='protocolPickerBg';bg.className='protocol-picker-bg';bg.innerHTML=`<div class="protocol-picker" role="dialog" aria-modal="true"><div class="protocol-picker-head"><div class="protocol-picker-head-icon"><span>✦</span></div><div class="protocol-picker-head-text"><div class="protocol-picker-title">${lang==='fa'?'انتخاب پروتکل':'Select Protocol'}</div><div class="protocol-picker-subtitle">${lang==='fa'?'پروتکل موردنظر را انتخاب کنید':'Choose the protocol you want to use'}</div></div><button type="button" class="protocol-picker-close" id="protocolPickerClose">×</button></div><div class="protocol-picker-scroll" id="protocolPickerScroll"></div><div class="protocol-picker-foot"><div class="protocol-selected-info" id="protocolSelectedInfo">—</div><button type="button" class="protocol-picker-confirm" id="protocolPickerConfirm">${lang==='fa'?'تأیید و ادامه →':'Confirm & Continue →'}</button></div></div>`;document.body.appendChild(bg);bg.addEventListener('click',e=>{if(e.target===bg)closeProtocolPicker()});bg.querySelector('#protocolPickerClose').onclick=closeProtocolPicker;bg.querySelector('#protocolPickerConfirm').onclick=confirmProtocolPicker;return bg}
function openProtocolPicker(targetId){const sel=document.getElementById(targetId);if(!sel)return;const bg=ensureProtocolPicker();__protocolPickerTarget=targetId;const current=sel.value||'vless-ws';const available=new Set([...sel.options].map(o=>o.value));const ids=PROTOCOL_PICKER_GROUPS[0].ids.filter(id=>available.has(id));const scroll=bg.querySelector('#protocolPickerScroll');scroll.innerHTML=`<div class="protocol-grid protocol-grid-all">${ids.map(id=>`<button type="button" class="protocol-option ${id===current?'selected':''}" data-proto="${id}"><span class="protocol-option-radio"></span>${protocolIconMarkup(id)}<span class="protocol-option-name">${esc(protocolPickerShort(id))}</span><span class="protocol-option-desc">${id===current?(lang==='fa'?'انتخاب‌شده':'Selected'):(lang==='fa'?'برای انتخاب کلیک کنید':'Tap to choose')}</span></button>`).join('')}</div>`;scroll.querySelectorAll('.protocol-option').forEach(btn=>btn.addEventListener('click',()=>chooseProtocol(btn.dataset.proto)));bg.querySelector('#protocolSelectedInfo').textContent=(lang==='fa'?'پروتکل انتخاب‌شده: ':'Selected: ')+protocolPickerShort(current);bg.classList.add('open');document.body.style.overflow='hidden'}
function chooseProtocol(id){const sel=document.getElementById(__protocolPickerTarget),bg=document.getElementById('protocolPickerBg');if(!sel||!bg)return;sel.value=id;bg.querySelectorAll('.protocol-option').forEach(x=>x.classList.toggle('selected',x.dataset.proto===id));bg.querySelector('#protocolSelectedInfo').textContent=(lang==='fa'?'پروتکل انتخاب‌شده: ':'Selected: ')+protocolPickerShort(id);syncProtocolPicker(__protocolPickerTarget);sel.dispatchEvent(new Event('change',{bubbles:true}))}
function confirmProtocolPicker(){if(__protocolPickerTarget){const sel=document.getElementById(__protocolPickerTarget);if(sel)sel.dispatchEvent(new Event('change',{bubbles:true}))}closeProtocolPicker()}
function closeProtocolPicker(){const bg=document.getElementById('protocolPickerBg');if(bg)bg.classList.remove('open');document.body.style.overflow=''}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeProtocolPicker()});
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',setupProtocolPickers);else setupProtocolPickers();setTimeout(setupProtocolPickers,300);setTimeout(setupProtocolPickers,1000);

applyLang();loadMe();loadProtocols();loadGroups();refreshAll();
setTimeout(()=>{startUpdateNotificationPolling()},1200);
setTimeout(()=>checkPanelUpdate(true),2500);
setInterval(()=>checkPanelUpdate(true),10*60*1000);
// Protocol picker bootstrap: keep the native select only as the data/control source.
function bootProtocolPickers(){ try{ setupProtocolPickers(); }catch(e){ console.warn('Protocol picker:',e); } }
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',bootProtocolPickers); else bootProtocolPickers();
setTimeout(bootProtocolPickers,300);
setTimeout(bootProtocolPickers,1000);
setInterval(refreshAll,1000);


</script>
</body>
</html>
"""




@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/login"
        )

    await ensure_default_categories()

    dashboard_html = DASHBOARD_HTML.replace("__ONEX_VERSION__", str(APP_VERSION))

    return HTMLResponse(
        dashboard_html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


# ============================================================
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        """
        <script>
        location.href='/dashboard'
        </script>
        """
    )


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "error":
                str(exc),

            "path":
                str(request.url),

            "method":
                request.method,

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url,
    )

    # API requests
    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path == "/stats"
    ):

        return JSONResponse(
            {
                "ok": False,
                "error":
                    str(exc)
                or "internal server error",
            },
            status_code=500,
        )

    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">
        <body style="
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">
            <h2>
            خطای داخلی PX Panel
            </h2>

            <p>
            لطفاً لاگ Railway را بررسی کنید.
            </p>
        </body>
        </html>
        """,
        status_code=500,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )
