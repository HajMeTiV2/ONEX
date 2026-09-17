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
    FileResponse,
)
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# APP
# ============================================================

APP_NAME = "ONEX"
APP_VERSION = "1.2.4"

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

# Protocol artwork shipped with the panel UI. These are local static assets
# so the protocol picker does not depend on an external image host.
PROTOCOL_ICON_DIR = Path(__file__).resolve().parent / "protocol_icons"
PROTOCOL_ICON_FILES = {
    "vless-ws": PROTOCOL_ICON_DIR / "nova-link.png",
    "xhttp-packet-up": PROTOCOL_ICON_DIR / "xpacket-nova.png",
    "xhttp-stream-up": PROTOCOL_ICON_DIR / "xstream-pulse.png",
    "xhttp-stream-one": PROTOCOL_ICON_DIR / "xstream-edge.png",
}

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


@app.get("/api/protocol-icon/{protocol_id}.png", include_in_schema=False)
async def protocol_icon(protocol_id: str):
    """Serve a bundled protocol icon for the create-config picker."""
    path = PROTOCOL_ICON_FILES.get(protocol_id)
    if not path or not path.is_file():
        raise HTTPException(status_code=404, detail="Protocol icon not found")
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "public, max-age=31536000, immutable"})

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

# Only advertise protocols for which this panel has a real server-side backend.
# VLESS is provided by relay_vless; XHTTP entries are added only after the
# optional xhttp_siz10 module is loaded successfully.  Do not put URL-only
# protocol names here: a generated URI is not enough to make a server support it.
PROTOCOLS: list[str] = []

PROTOCOL_LABELS = {
    "vless-ws": "Nova Link",
    "xhttp-packet-up": "XPacket Nova",
    "xhttp-stream-up": "XStream Pulse",
    "xhttp-stream-one": "XStream Edge",
    "trojan": "Trojan",
    "shadowsocks": "Shadowsocks",
    "socks5": "SOCKS5",
    "http": "HTTP Proxy",
    "hysteria2": "Hysteria2",
    "vless-grpc-reality": "VLESS gRPC Reality",
    "wireguard": "WireGuard",
}

PROTOCOL_ALIASES = {
    "vless": "vless-ws",
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
    "vless-grpc-reality": "h2",
}

# Advanced client-link settings exposed by the manual creator. Xray treats
# ALPN as a string list, so the UI exposes common values plus a custom field.
ALPN_VALUES = (
    # Xray-specific / commonly used values
    "h2", "h3", "http/1.1", "FromMitM",
    # IANA-registered ALPN protocol IDs
    "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3",
    "stun.turn", "stun.nat-discovery", "h2c", "webrtc", "c-webrtc",
    "ftp", "imap", "pop3", "managesieve", "coap", "co",
    "xmpp-client", "xmpp-server", "acme-tls/1", "mqtt", "dot",
    "ntske/1", "sunrpc", "smb", "irc", "nntp", "nnsp", "doq",
    "sip/2", "tds/8.0", "dicom", "postgresql", "radius/1.0", "radius/1.1",
    "netperfmeter/control", "netperfmeter/data", "n-pamp/2", "EoQ", "snifq/1",
    # Common HTTP/3 draft/version labels seen in clients
    "h3-29", "h3-30", "h3-31", "h3-32",
    # Common ready-made combinations
    "h3,h2", "h2,http/1.1", "h3,h2,http/1.1", "h3,http/1.1"
)
ALLOWED_TLS_MODES = {"tls", "reality"}
FRAGMENT_PRESETS = {
    "off": "",
    "safe": "100-200,10-20",
    "balanced": "80-300,10-20",
    "aggressive": "50-500,10-30",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    if value in PROTOCOLS:
        return value
    return PROTOCOLS[0] if PROTOCOLS else DEFAULT_PROTOCOL


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
    "dash", "configs", "create", "delete_config", "delete_all_configs",
    "subscriptions", "groups", "stats", "logs", "settings",
    "api", "users", "vps", "xray", "advanced", "support", "telegram", "news", "admins",
)
DEFAULT_PERMS = {p: True for p in ALL_PERMS}


def default_admin_record(username: str, password: str, **kwargs) -> dict:
    return {
        "id": secrets.token_hex(8),
        "username": username.strip().lower(),
        "password_hash": hash_password(password),
        "label": kwargs.get("label") or username,
        "role": kwargs.get("role") or "admin",
        "limit_bytes": int(kwargs.get("limit_bytes") or 0),
        "used_bytes": 0,
        "expires_at": kwargs.get("expires_at"),
        "active": True,
        "blocked": False,
        "permissions": {**DEFAULT_PERMS, **(kwargs.get("permissions") or {})},
        "created_at": datetime.now().isoformat(),
        "last_login_at": None,
        "last_login_ip": None,
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

# Native sing-box listener ports are shared by all accounts.  The panel
# stores credentials per UUID while the native core keeps one listener per
# protocol.  This is what makes the "all protocols" subscription a single
# account instead of creating unrelated accounts.
def protocol_public_port(link: dict | None, protocol: str, fallback: int = DEFAULT_PORT) -> int:
    if protocol in {"vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one", "trojan-ws", "vmess-ws"}:
        return safe_int((link or {}).get("port", fallback), fallback, MIN_PORT, MAX_PORT)
    try:
        ports = NATIVE_CORE.public_ports()  # type: ignore[name-defined]
        return safe_int(ports.get(protocol, fallback), fallback, MIN_PORT, MAX_PORT)
    except Exception:
        return safe_int((link or {}).get("port", fallback), fallback, MIN_PORT, MAX_PORT)

def generate_vless_link(
    uuid: str, host: str, remark: str = "ONEX",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None, link: dict | None = None,
):
    protocol = normalize_protocol(protocol)
    link = link or {}
    fp = (fingerprint or link.get("fingerprint") or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = protocol_public_port(link, protocol, safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT))
    alpn_value = (alpn or link.get("alpn") or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    if alpn_value:
        alpn_parts = [x.strip() for x in alpn_value.split(",") if x.strip()]
        alpn_value = ",".join(dict.fromkeys(alpn_parts))[:100] or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    sni = str(link.get("sni") or host).strip() or host
    allow_insecure = bool(link.get("allow_insecure", False))
    fragment = str(link.get("fragment") or "off").strip().lower()
    fragment_value = FRAGMENT_PRESETS.get(fragment, "")
    label = quote(str(remark or "ONEX"), safe="")

    def _q(extra: dict):
        if allow_insecure:
            extra["allowInsecure"] = "1"
        if fragment_value:
            extra["fragment"] = fragment_value
        return "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in extra.items())

    security = "reality" if str(link.get("tls_mode") or "tls").strip().lower() == "reality" else "tls"
    reality_extra = {}
    if security == "reality":
        if link.get("reality_public_key"):
            reality_extra["pbk"] = str(link.get("reality_public_key"))
        if link.get("reality_short_id"):
            reality_extra["sid"] = str(link.get("reality_short_id"))
        if link.get("reality_spider_x"):
            reality_extra["spx"] = str(link.get("reality_spider_x"))
        if link.get("reality_target"):
            reality_extra["target"] = str(link.get("reality_target"))
    if protocol == "vless-ws":
        q = {"encryption":"none","security":security,"type":"ws","host":host,"path":f"/ws/{uuid}","sni":sni,"fp":fp,"alpn":alpn_value,**reality_extra}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + _q(q) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        q = {"encryption":"none","security":security,"type":"xhttp","mode":mode,"host":host,"path":f"/xhttp-siz10/{mode}/{uuid}","sni":sni,"fp":fp,"alpn":alpn_value,**reality_extra}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + _q(q) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "trojan":
        insecure = "&allowInsecure=1" if getattr(NATIVE_CORE, "self_signed", False) else ""
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&sni={quote(host)}{insecure}#{label}"
    if protocol == "vless-grpc-reality":
        try:
            reality = NATIVE_CORE.reality_info()  # type: ignore[name-defined]
            pbk = quote(str(reality.get("public_key", "")), safe="")
            sid = quote(str(reality.get("short_id", "")), safe="")
        except Exception:
            pbk, sid = "", ""
        q = {"encryption":"none","security":"reality","type":"grpc","serviceName":"ONEX","sni":host,"fp":fp,"pbk":pbk,"sid":sid}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2":
        insecure = 1 if getattr(NATIVE_CORE, "self_signed", False) else 0
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure={insecure}#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "wireguard": return f"wireguard://{uuid}@{host}:{port_value}?publicKey={uuid}#{label}"
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
        port=protocol_public_port(link, link.get("protocol", DEFAULT_PROTOCOL), link.get("port", DEFAULT_PORT)),
        link=link,
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
        "sni": link.get("sni", ""),
        "allow_insecure": bool(link.get("allow_insecure", False)),
        "tls_mode": link.get("tls_mode", "tls"),
        "reality_public_key": link.get("reality_public_key", ""),
        "reality_short_id": link.get("reality_short_id", ""),
        "reality_spider_x": link.get("reality_spider_x", ""),
        "reality_target": link.get("reality_target", ""),
        "network": ("ws" if link.get("protocol") == "vless-ws" else "xhttp" if str(link.get("protocol", "")).startswith("xhttp-") else ""),
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
    sni: str = "",
    allow_insecure: bool = False,
    tls_mode: str = "tls",
    reality_public_key: str = "",
    reality_short_id: str = "",
    reality_spider_x: str = "",
    reality_target: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
    all_protocols: bool = False,
):

    if not PROTOCOLS:
        raise HTTPException(503, "No protocol backend is available")

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

        "sni":
            (sni or "").strip()[:253],

        "allow_insecure":
            bool(allow_insecure),

        "tls_mode":
            (tls_mode if tls_mode in ALLOWED_TLS_MODES else "tls"),

        "reality_public_key":
            (reality_public_key or "").strip()[:128],

        "reality_short_id":
            (reality_short_id or "").strip()[:64],

        "reality_spider_x":
            (reality_spider_x or "").strip()[:253],

        "reality_target":
            (reality_target or "").strip()[:253],

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
        "all_protocols": bool(all_protocols),
        "native_protocols": [p for p in PROTOCOLS if p not in {"vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one"}],
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
        LOGIN_HTML,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
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
        LOGIN_HTML,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
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
            admin["last_login_at"] = datetime.now().isoformat()
            admin["last_login_ip"] = ip
            await save_state()
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
async def api_logout(request: Request):
    """Destroy the current session and clear the auth cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)

    response = JSONResponse({"ok": True})
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
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

    if not PROTOCOLS:
        raise HTTPException(503, "No protocol backend is available")
    if protocol not in PROTOCOLS:
        protocol = PROTOCOLS[0]

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    raw_alpn = body.get("alpn", DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1"))
    if isinstance(raw_alpn, list):
        alpn_parts = [str(x).strip() for x in raw_alpn]
    else:
        alpn_parts = [x.strip() for x in str(raw_alpn or "").replace(";", ",").split(",")]
    alpn_parts = list(dict.fromkeys(x for x in alpn_parts if x))
    alpn = ",".join(alpn_parts)[:100] or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")

    sni = str(body.get("sni") or "").strip()[:253]
    allow_insecure = bool(body.get("allow_insecure", False))
    tls_mode = str(body.get("tls_mode") or "tls").strip().lower()
    if tls_mode not in ALLOWED_TLS_MODES:
        tls_mode = "tls"
    reality_public_key = str(body.get("reality_public_key") or "").strip()[:128]
    reality_short_id = str(body.get("reality_short_id") or "").strip()[:64]
    reality_spider_x = str(body.get("reality_spider_x") or "").strip()[:253]
    reality_target = str(body.get("reality_target") or "").strip()[:253]

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
    all_protocols = bool(body.get("all_protocols", False))
    if all_protocols:
        config_count = 1
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
        alpn=alpn,
        sni=sni,
        allow_insecure=allow_insecure,
        tls_mode=tls_mode,
        reality_public_key=reality_public_key,
        reality_short_id=reality_short_id,
        reality_spider_x=reality_spider_x,
        reality_target=reality_target,
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
        all_protocols=all_protocols,
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
    if NATIVE_CORE:
        asyncio.create_task(sync_native_core())
    if all_protocols:
        result["all_protocols"] = True
        result["protocol_count"] = len(PROTOCOLS)

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
    all_protocols = bool(body.get("all_protocols", False))
    if all_protocols:
        config_count = 1
    uid, link = await make_link(
        label=project_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by ONEX | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
        config_count=config_count,
        all_protocols=all_protocols,
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    if NATIVE_CORE:
        asyncio.create_task(sync_native_core())
    if all_protocols:
        result["all_protocols"] = True
        result["protocol_count"] = len(PROTOCOLS)
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    native_ready = bool(NATIVE_CORE and getattr(NATIVE_CORE, "is_runtime_ready", lambda: False)())
    return {
        "protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p), "backend": "native" if p in getattr(NATIVE_CORE, "SUPPORTED", ()) else "panel"} for p in PROTOCOLS],
        "default": PROTOCOLS[0] if PROTOCOLS else DEFAULT_PROTOCOL,
        "native_core": {"installed": bool(NATIVE_CORE and NATIVE_CORE.binary_exists()), "running": native_ready, "error": getattr(NATIVE_CORE, "last_error", "") if NATIVE_CORE else ""},
    }


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

            raw_alpn = body.get("alpn", "")
            if isinstance(raw_alpn, list):
                parts = [str(x).strip() for x in raw_alpn]
            else:
                parts = [x.strip() for x in str(raw_alpn or "").replace(";", ",").split(",")]
            parts = list(dict.fromkeys(x for x in parts if x))
            link["alpn"] = ",".join(parts)[:100]

        if "sni" in body:
            link["sni"] = str(body.get("sni") or "").strip()[:253]

        if "allow_insecure" in body:
            link["allow_insecure"] = bool(body.get("allow_insecure"))

        if "tls_mode" in body:
            mode = str(body.get("tls_mode") or "tls").strip().lower()
            link["tls_mode"] = mode if mode in ALLOWED_TLS_MODES else "tls"

        if "reality_public_key" in body:
            link["reality_public_key"] = str(body.get("reality_public_key") or "").strip()[:128]
        if "reality_short_id" in body:
            link["reality_short_id"] = str(body.get("reality_short_id") or "").strip()[:64]
        if "reality_spider_x" in body:
            link["reality_spider_x"] = str(body.get("reality_spider_x") or "").strip()[:253]
        if "reality_target" in body:
            link["reality_target"] = str(body.get("reality_target") or "").strip()[:253]

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
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=protocol_public_port(link, link.get("protocol", DEFAULT_PROTOCOL), link.get("port", DEFAULT_PORT)), link=link)
    lines = [stats_line]
    used_names = set()
    cfg_count = 1 if link.get("all_protocols") else max(1, min(40, int(link.get("config_count") or 1)))
    protocols = list(PROTOCOLS) if link.get("all_protocols") else [link.get("protocol", DEFAULT_PROTOCOL)]
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            for proto in protocols:
                name = project_config_name(used_names)
                used_names.add(name)
                lines.append(generate_vless_link(uuid, cip, remark=name, protocol=proto, fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=DEFAULT_ALPN_BY_PROTOCOL.get(proto, link.get("alpn")), port=protocol_public_port(link, proto, link.get("port", DEFAULT_PORT)), link=link))
    else:
        for i in range(cfg_count):
            for proto in protocols:
                name = project_config_name(used_names)
                used_names.add(name)
                lines.append(generate_vless_link(uuid, host, remark=name, protocol=proto, fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=DEFAULT_ALPN_BY_PROTOCOL.get(proto, link.get("alpn")), port=protocol_public_port(link, proto, link.get("port", DEFAULT_PORT)), link=link))
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
  .dynamic-card .text-white/40{{color:rgba(226,232,240,.58) !important;}}
  .dynamic-card .text-white/45{{color:rgba(226,232,240,.68) !important;}}
  .dynamic-card .text-white/35{{color:rgba(226,232,240,.55) !important;}}
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
# NATIVE PROTOCOL CORE (sing-box)
# ============================================================

try:
    from protocol_core import NativeCore
    NATIVE_CORE = NativeCore(DATA_DIR)
    # Native protocols are intentionally not advertised yet.
    # Keep the creation menu and the "all protocols" subscription limited
    # to the four currently exposed panel-backed protocols.
    logger.info("Native sing-box backend loaded but not advertised yet.")
except Exception as exc:
    NATIVE_CORE = None
    logger.warning("Native protocol backend unavailable: %s", exc)


async def sync_native_core():
    if not NATIVE_CORE:
        return False
    try:
        return await NATIVE_CORE.sync(LINKS, CONFIG.get("host") or os.getenv("RAILWAY_PUBLIC_DOMAIN", "localhost"))
    except Exception as exc:
        logger.warning("Native core sync failed: %s", exc)
        return False


@app.on_event("startup")
async def start_native_core():
    if NATIVE_CORE:
        asyncio.create_task(sync_native_core())


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

    if "vless-ws" not in PROTOCOLS:
        PROTOCOLS.append("vless-ws")

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

    for _protocol in (
        "xhttp-packet-up",
        "xhttp-stream-up",
        "xhttp-stream-one",
    ):
        if _protocol not in PROTOCOLS:
            PROTOCOLS.append(_protocol)

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )

# Keep the panel/backend protocol order stable: the existing Railway-safe
# transports remain first, while native listeners are appended afterwards.
_PROTOCOL_ORDER = [
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
    "trojan",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "vless-grpc-reality",
]
PROTOCOLS[:] = [p for p in _PROTOCOL_ORDER if p in PROTOCOLS]


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
            "role": a.get("role") or "admin",
            "limit_bytes": int(a.get("limit_bytes") or 0),
            "used_bytes": int(a.get("used_bytes") or 0),
            "expires_at": a.get("expires_at"),
            "active": bool(a.get("active", True)),
            "blocked": bool(a.get("blocked")),
            "permissions": a.get("permissions") or {},
            "created_at": a.get("created_at"),
            "last_login_at": a.get("last_login_at"),
            "last_login_ip": a.get("last_login_ip"),
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
    role = str(body.get("role") or "admin").lower()
    if role not in ("admin", "operator"):
        role = "admin"
    active = bool(body.get("active", True))
    rec = default_admin_record(username, password, limit_bytes=limit_bytes, expires_at=expires_at, permissions=permissions, label=body.get("label") or username, role=role)
    rec["active"] = active
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
    if "role" in body:
        role = str(body.get("role") or "admin").lower()
        a["role"] = role if role in ("admin", "operator") else "admin"
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
.sb-foot a.danger:hover .logout-ico,.sb-foot button.danger:hover .logout-ico{transform:perspective(80px) rotateY(-16deg) rotateX(8deg) scale(1.12) translateX(-2px);filter:drop-shadow(0 4px 9px rgba(239,68,68,.58))}
.sb-foot a.danger .logout-ico,.sb-foot button.danger .logout-ico{animation:logoutFloat 2.8s ease-in-out infinite}
@keyframes logoutFloat{0%,100%{translate:0 0}50%{translate:-2px -1px}}
@media (max-width:768px){
  .sidebar .nav-item .nav-ico{width:22px;height:22px;min-width:22px;min-height:22px;flex-basis:22px}
  .sidebar .nav-item.on .nav-ico{transform:perspective(80px) rotateY(-8deg) rotateX(5deg) scale(1.04)}
  .sidebar .sb-foot a.danger .logout-ico,.sidebar .sb-foot button.danger .logout-ico,.sb-foot button.danger .logout-ico{width:22px!important;height:22px!important}
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
#page-create .advanced-config{margin:14px 0 16px;border:1px solid var(--card-b);border-radius:15px;overflow:hidden;background:rgba(8,18,36,.38)}
#page-create .advanced-toggle{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:13px 14px;background:transparent;border:0;color:var(--t1);cursor:pointer;font-family:inherit;text-align:right}
#page-create .advanced-toggle-main{display:flex;align-items:center;gap:10px;min-width:0}
#page-create .advanced-toggle-icon{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:rgba(96,165,250,.10);border:1px solid rgba(96,165,250,.18);font-size:16px}
#page-create .advanced-toggle-text b{display:block;font-size:12px}
#page-create .advanced-toggle-text small{display:block;margin-top:3px;color:var(--t3);font-size:10px}
#page-create .advanced-toggle-arrow{font-size:20px;color:#60a5fa;transition:transform .18s ease}
#page-create .advanced-config.open .advanced-toggle-arrow{transform:rotate(180deg)}
#page-create .advanced-body{display:none;padding:0 14px 14px;border-top:1px solid var(--card-b)}
#page-create .advanced-config.open .advanced-body{display:block}
#page-create .advanced-section-title{font-size:10px;font-weight:800;color:var(--t3);margin:14px 0 8px;letter-spacing:.2px}
#page-create .advanced-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
#page-create .advanced-grid .field{margin:0}
#page-create .advanced-full{grid-column:1/-1}
#page-create .alpn-choices{display:flex;flex-wrap:wrap;gap:7px;max-height:240px;overflow:auto;padding:4px}
#page-create .alpn-choice{display:flex;align-items:center;gap:6px;padding:7px 9px;border:1px solid var(--card-b);border-radius:10px;background:var(--input-bg);font-size:11px;cursor:pointer;user-select:none}
#page-create .alpn-choice input{accent-color:#60a5fa}
#page-create .advanced-note{font-size:10px;line-height:1.7;color:var(--t3);padding:8px 10px;border-radius:10px;background:rgba(148,163,184,.05);border:1px solid rgba(148,163,184,.10);margin-top:9px}
#page-create .advanced-readonly{opacity:.72}
@media(max-width:640px){#page-create .advanced-grid{grid-template-columns:1fr}}
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
.protocol-art-icon{width:100%;height:100%;display:block;object-fit:contain;filter:drop-shadow(0 7px 10px rgba(0,0,0,.30));}
#page-create .protocol-trigger-icon{width:44px!important;height:44px!important}
#page-create .protocol-trigger-icon .protocol-option-icon{width:44px!important;height:44px!important}
#page-create .protocol-trigger-icon .lego-proto-svg{width:44px!important;height:44px!important}
@media(max-width:700px){.protocol-grid-all{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:10px!important}.protocol-option{min-height:124px!important}.protocol-option-icon.proto-3d{width:78px!important;height:78px!important}.lego-proto-svg{width:78px!important;height:78px!important}}
@media(max-width:380px){.protocol-grid-all{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:8px!important}.protocol-option{min-height:112px!important;padding:6px!important}.protocol-option-icon.proto-3d{width:68px!important;height:68px!important}.lego-proto-svg{width:68px!important;height:68px!important}.protocol-option-name{font-size:10px!important}}

.all-proto-toggle{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:10px 0 14px;padding:12px 14px;border:1px solid rgba(34,197,94,.22);border-radius:14px;background:rgba(34,197,94,.035);cursor:pointer;user-select:none}
.all-proto-toggle span{display:block;min-width:0}.all-proto-toggle b{display:block;font-size:12px}.all-proto-toggle small{display:block;color:var(--t3);font-size:10px;margin-top:4px;line-height:1.6}.all-proto-toggle input{position:absolute;opacity:0;pointer-events:none}.all-proto-toggle i{position:relative;flex:0 0 48px;width:48px;height:28px;border-radius:999px;background:#4b5563;transition:.2s;box-shadow:inset 0 0 0 1px rgba(255,255,255,.12)}.all-proto-toggle i:before{content:"";position:absolute;top:4px;right:24px;width:20px;height:20px;border-radius:50%;background:#fff;box-shadow:0 2px 6px rgba(0,0,0,.35);transition:.2s}.all-proto-toggle:has(input:checked) i{background:#22c55e;box-shadow:0 0 12px rgba(34,197,94,.28)}.all-proto-toggle:has(input:checked) i:before{right:4px}.all-proto-toggle:focus-within{outline:2px solid rgba(34,197,94,.35);outline-offset:2px}

/* ============================================================
   ADMIN MANAGEMENT — APPROVED COMPACT RESPONSIVE LAYOUT
   ============================================================ */
.admin-page{max-width:1080px;margin:0 auto;padding:0 0 24px}
.admin-page .page-head{margin-bottom:14px}
.admin-main-grid{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(285px,.85fr);gap:14px;align-items:start}
.admin-list-card{padding:0!important;overflow:hidden}
.admin-list-head{padding:13px 15px;border-bottom:1px solid var(--card-b)}
.admin-list-controls{display:grid;grid-template-columns:minmax(0,1fr) 125px;gap:8px;margin-top:8px}
.admin-list-controls input,.admin-list-controls select{height:38px!important;min-height:38px!important;font-size:11px!important;border-radius:10px!important}
.admin-table-wrap{overflow-x:auto}
.admin-table-head{min-width:610px;display:grid;grid-template-columns:1.55fr .78fr .8fr 1.05fr .95fr;padding:8px 12px;background:var(--bg2);border-bottom:1px solid var(--card-b);font-size:10px;color:var(--t3);font-weight:700}
.admin-create-card{padding:14px!important}
.admin-create-head{display:flex;justify-content:space-between;align-items:center;gap:8px}
.admin-create-card .field{margin-bottom:8px}
.admin-create-card .field label{font-size:10px;margin-bottom:4px}
.admin-create-card input,.admin-create-card select{height:40px!important;min-height:40px!important;font-size:12px!important;border-radius:11px!important}
.admin-create-card .form-row{gap:7px}
.admin-status-row{display:flex;align-items:center;justify-content:space-between;padding:9px 10px;margin:2px 0 8px;border:1px solid var(--card-b);background:var(--bg2);border-radius:11px;font-size:11px}
.admin-perms-card{margin-top:14px;padding:14px!important}
.admin-perm-toolbar{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
.admin-perm-actions{display:flex;gap:5px}
.admin-perm-actions .btn{height:30px!important;padding:0 8px!important;font-size:10px!important}
.admin-perm-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:12px}
.admin-perm-group{border:1px solid var(--card-b);border-radius:12px;padding:9px;background:var(--bg2)}
.admin-perm-group-title{font-size:11px;font-weight:800;margin-bottom:7px;color:var(--t1)}
.admin-perm-item{display:flex;align-items:center;justify-content:space-between;gap:7px;padding:6px 5px;border-top:1px solid var(--card-b);font-size:10px}
.admin-perm-item:first-of-type{border-top:0}
.admin-bottom-grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(280px,.65fr);gap:14px;margin-top:14px;align-items:start}
.admin-activity-card,.admin-details-card{min-height:170px}
.admin-page input,.admin-page select{box-sizing:border-box}
.admin-row{display:grid;grid-template-columns:1.55fr .78fr .8fr 1.05fr .95fr;align-items:center;min-width:610px;padding:9px 12px;border-bottom:1px solid var(--card-b);cursor:pointer;gap:7px;font-size:10px}
.admin-row:last-child{border-bottom:0}
.admin-row:hover{background:var(--bg2)}
.admin-avatar{width:32px;height:32px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;font-weight:800;flex:0 0 32px}
.admin-role{font-size:9px;padding:4px 7px;border-radius:999px;background:rgba(59,130,246,.10);color:#2563eb;width:max-content}
.admin-state{font-size:9px;border:1px solid;padding:4px 7px;border-radius:999px;width:max-content}
.admin-actions{display:flex;gap:4px}
.admin-actions .btn{min-width:28px!important;height:28px!important;padding:0 5px!important;font-size:10px!important}
.admin-detail-actions{display:flex;gap:7px;margin-top:11px}
.admin-detail-actions .btn{flex:1;height:34px!important;font-size:10px!important}
@media(max-width:900px){
  .admin-page{width:100%;max-width:none;margin:0;padding:4px 9px 20px;box-sizing:border-box}
  .admin-page .page-head{margin-bottom:9px}
  .admin-page .page-title{font-size:18px!important;line-height:1.4}
  .admin-page .page-title svg{width:19px!important;height:19px!important}
  .admin-page .page-sub{font-size:9px!important;margin-top:1px}
  .admin-page .page-head .btn{height:36px!important;padding:0 10px!important;font-size:10px!important;border-radius:10px!important}
  .admin-main-grid{grid-template-columns:1fr!important;gap:9px!important}
  .admin-list-card{order:1}.admin-create-card{order:2}
  .admin-list-head{padding:10px 11px!important}
  .admin-list-controls{grid-template-columns:minmax(0,1fr) 100px!important;gap:5px!important;margin-top:6px!important}
  .admin-list-controls input,.admin-list-controls select{height:34px!important;min-height:34px!important;font-size:9px!important}
  .admin-table-head{min-width:575px!important;padding:7px 9px!important;font-size:8px!important}
  .admin-row{min-width:575px!important;padding:8px 9px!important;font-size:9px!important}
  .admin-avatar{width:29px;height:29px;flex-basis:29px;font-size:11px}
  .admin-role,.admin-state{font-size:8px;padding:3px 6px}
  .admin-actions .btn{min-width:26px!important;height:26px!important;font-size:9px!important}
  .admin-create-card{padding:12px!important}
  .admin-create-card .card-title{font-size:13px!important}
  .admin-create-card .field{margin-bottom:6px!important}
  .admin-create-card .field label{font-size:9px!important;margin-bottom:3px!important}
  .admin-create-card input,.admin-create-card select{height:38px!important;min-height:38px!important;font-size:11px!important;border-radius:10px!important;padding:0 9px!important}
  .admin-create-card .btn{height:39px!important;font-size:11px!important;border-radius:10px!important}
  .admin-status-row{font-size:10px;padding:8px 9px;margin:1px 0 6px}
  .admin-perms-card{margin-top:9px!important;padding:11px!important}
  .admin-perm-toolbar{align-items:flex-start}
  .admin-perm-toolbar .card-title{font-size:12px!important}
  .admin-perm-toolbar>div:first-child>div:last-child{font-size:9px!important}
  .admin-perm-actions .btn{height:28px!important;font-size:9px!important}
  .admin-perm-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:9px}
  .admin-perm-group{padding:7px;border-radius:10px}
  .admin-perm-group-title{font-size:10px;margin-bottom:5px}
  .admin-perm-item{font-size:9px;padding:5px 3px}
  .admin-perm-item .switch{transform:scale(.72);transform-origin:center}
  .admin-bottom-grid{grid-template-columns:1fr!important;gap:9px!important;margin-top:9px!important}
  .admin-activity-card,.admin-details-card{min-height:0!important}
  .admin-activity-card .card-title,.admin-details-card .card-title{font-size:12px!important}
  #adminActivityBox{max-height:180px!important}
  #adminDetails{font-size:9px!important;line-height:1.8!important}
}
@media(max-width:390px){
  .admin-page{padding-left:7px;padding-right:7px}
  .admin-page .page-title{font-size:17px!important}
  .admin-list-controls{grid-template-columns:1fr 92px!important}
  .admin-perm-grid{grid-template-columns:1fr!important}
}
@media(max-width:900px){
  body:has(#page-admins.on) .sidebar{transform:translateX(105%) !important}
  body:has(#page-admins.on) .sidebar.mobile-open{transform:translateX(0) !important}
  body:has(#page-admins.on) .main,body:has(#page-admins.on) .main.expanded{width:100%!important;max-width:100%!important;margin:0!important;padding-left:10px!important;padding-right:10px!important}
  body:has(#page-admins.on) .mob-bar{display:flex!important}
}
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
    <button type="button" class="btn danger" id="panelLogoutBtn" onclick="logoutPanel()">
      <svg class="logout-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 4H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="m14 8 4 4-4 4"/><path d="M18 12H8"/><path d="M13 4v3M13 17v3" opacity=".45"/></svg>
      <span data-i18n="logout">خروج</span>
    </button>
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
        <label class="all-proto-toggle" title="یک اکانت با همه پروتکل‌ها و یک ساب"><span><b>همه پروتکل‌ها در یک ساب</b><small>یک اکانت · همه پروتکل‌های پنل · یک لینک اشتراک</small></span><input id="cAllProtocols" type="checkbox"><i aria-hidden="true"></i></label>
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

      <div class="advanced-config" id="manualAdvanced">
        <button type="button" class="advanced-toggle" onclick="toggleManualAdvanced()" aria-expanded="false">
          <span class="advanced-toggle-main"><span class="advanced-toggle-icon">⚙</span><span class="advanced-toggle-text"><b>تنظیمات پیشرفته کانفیگ</b><small>TLS، SNI، Fingerprint، ALPN، Fragment و شبکه</small></span></span>
          <span class="advanced-toggle-arrow">⌄</span>
        </button>
        <div class="advanced-body">
          <div class="advanced-section-title">امنیت و TLS</div>
          <div class="advanced-grid">
            <div class="field"><label>TLS</label><select id="cTlsMode" onchange="toggleManualRealityFields()"><option value="tls">TLS</option><option value="reality">Reality</option></select></div>
            <div class="field"><label>Port / پورت</label><input id="cPort" type="number" min="1" max="65535" placeholder="پیش‌فرض: 443"></div>
            <div class="field"><label>SNI</label><input id="cSni" type="text" dir="ltr" placeholder="پیش‌فرض: دامنه پنل"></div>
            <div class="field"><label>مجوز SSL ناامن</label><select id="cAllowInsecure"><option value="false">False</option><option value="true">True</option></select></div>
            <div class="field"><label>Fingerprint / اثرانگشت</label><select id="cFingerprint">
              <option value="chrome">Chrome</option><option value="firefox">Firefox</option><option value="safari">Safari</option><option value="ios">iOS</option><option value="android">Android</option><option value="edge">Edge</option><option value="360">360</option><option value="qq">QQ</option><option value="random">Random</option><option value="randomized">Randomized</option>
            </select></div>
          </div>
          <div id="manualRealityFields" class="advanced-grid" style="display:none;margin-top:10px">
            <div class="field advanced-full"><label>Reality Public Key</label><input id="cRealityPublicKey" type="text" dir="ltr" placeholder="Public Key"></div>
            <div class="field"><label>Reality Short ID</label><input id="cRealityShortId" type="text" dir="ltr" placeholder="Short ID"></div>
            <div class="field"><label>SpiderX</label><input id="cRealitySpiderX" type="text" dir="ltr" placeholder="/"></div>
            <div class="field advanced-full"><label>Reality Target</label><input id="cRealityTarget" type="text" dir="ltr" placeholder="example.com:443"></div>
          </div>

          <div class="advanced-section-title">ALPN</div>
          <div class="alpn-choices" id="cAlpnChoices">
            <label class="alpn-choice"><input type="checkbox" value="h2"> HTTP/2</label>
            <label class="alpn-choice"><input type="checkbox" value="h3"> HTTP/3</label>
            <label class="alpn-choice"><input type="checkbox" value="http/1.1"> HTTP/1.1</label>
            <label class="alpn-choice"><input type="checkbox" value="FromMitM"> FromMitM</label>
            <label class="alpn-choice"><input type="checkbox" value="http/0.9"> HTTP/0.9</label>
            <label class="alpn-choice"><input type="checkbox" value="http/1.0"> HTTP/1.0</label>
            <label class="alpn-choice"><input type="checkbox" value="spdy/1"> SPDY/1</label>
            <label class="alpn-choice"><input type="checkbox" value="spdy/2"> SPDY/2</label>
            <label class="alpn-choice"><input type="checkbox" value="spdy/3"> SPDY/3</label>
            <label class="alpn-choice"><input type="checkbox" value="stun.turn"> stun.turn</label>
            <label class="alpn-choice"><input type="checkbox" value="stun.nat-discovery"> stun.nat-discovery</label>
            <label class="alpn-choice"><input type="checkbox" value="h2c"> h2c</label>
            <label class="alpn-choice"><input type="checkbox" value="webrtc"> webrtc</label>
            <label class="alpn-choice"><input type="checkbox" value="c-webrtc"> c-webrtc</label>
            <label class="alpn-choice"><input type="checkbox" value="ftp"> ftp</label>
            <label class="alpn-choice"><input type="checkbox" value="imap"> imap</label>
            <label class="alpn-choice"><input type="checkbox" value="pop3"> pop3</label>
            <label class="alpn-choice"><input type="checkbox" value="managesieve"> managesieve</label>
            <label class="alpn-choice"><input type="checkbox" value="coap"> coap</label>
            <label class="alpn-choice"><input type="checkbox" value="co"> co</label>
            <label class="alpn-choice"><input type="checkbox" value="xmpp-client"> xmpp-client</label>
            <label class="alpn-choice"><input type="checkbox" value="xmpp-server"> xmpp-server</label>
            <label class="alpn-choice"><input type="checkbox" value="acme-tls/1"> acme-tls/1</label>
            <label class="alpn-choice"><input type="checkbox" value="mqtt"> mqtt</label>
            <label class="alpn-choice"><input type="checkbox" value="dot"> dot</label>
            <label class="alpn-choice"><input type="checkbox" value="ntske/1"> ntske/1</label>
            <label class="alpn-choice"><input type="checkbox" value="sunrpc"> sunrpc</label>
            <label class="alpn-choice"><input type="checkbox" value="smb"> smb</label>
            <label class="alpn-choice"><input type="checkbox" value="irc"> irc</label>
            <label class="alpn-choice"><input type="checkbox" value="nntp"> nntp</label>
            <label class="alpn-choice"><input type="checkbox" value="nnsp"> nnsp</label>
            <label class="alpn-choice"><input type="checkbox" value="doq"> doq</label>
            <label class="alpn-choice"><input type="checkbox" value="sip/2"> sip/2</label>
            <label class="alpn-choice"><input type="checkbox" value="tds/8.0"> tds/8.0</label>
            <label class="alpn-choice"><input type="checkbox" value="dicom"> dicom</label>
            <label class="alpn-choice"><input type="checkbox" value="postgresql"> postgresql</label>
            <label class="alpn-choice"><input type="checkbox" value="radius/1.0"> radius/1.0</label>
            <label class="alpn-choice"><input type="checkbox" value="radius/1.1"> radius/1.1</label>
            <label class="alpn-choice"><input type="checkbox" value="netperfmeter/control"> netperfmeter/control</label>
            <label class="alpn-choice"><input type="checkbox" value="netperfmeter/data"> netperfmeter/data</label>
            <label class="alpn-choice"><input type="checkbox" value="n-pamp/2"> n-pamp/2</label>
            <label class="alpn-choice"><input type="checkbox" value="EoQ"> EoQ</label>
            <label class="alpn-choice"><input type="checkbox" value="snifq/1"> snifq/1</label>
            <label class="alpn-choice"><input type="checkbox" value="h3-29"> h3-29</label>
            <label class="alpn-choice"><input type="checkbox" value="h3-30"> h3-30</label>
            <label class="alpn-choice"><input type="checkbox" value="h3-31"> h3-31</label>
            <label class="alpn-choice"><input type="checkbox" value="h3-32"> h3-32</label>
            <label class="alpn-choice"><input type="checkbox" value="h3,h2"> h3,h2</label>
            <label class="alpn-choice"><input type="checkbox" value="h2,http/1.1"> h2,http/1.1</label>
            <label class="alpn-choice"><input type="checkbox" value="h3,h2,http/1.1"> h3,h2,http/1.1</label>
            <label class="alpn-choice"><input type="checkbox" value="h3,http/1.1"> h3,http/1.1</label>
          </div>
          <div class="field" style="margin-top:10px">
            <label>ALPN سفارشی</label>
            <input id="cAlpnCustom" type="text" dir="ltr" placeholder="مثلاً: acme-tls/1,dot,doh">
          </div>
          <div class="advanced-note">هر تعداد ALPN را می‌توانی انتخاب کنی. علاوه بر موارد رایج، مقدار سفارشی هم قابل وارد کردن است؛ مقادیر را با کاما جدا کن. اگر چیزی انتخاب/وارد نکنی، ALPN پیش‌فرض همان پروتکل استفاده می‌شود.</div>

          <div class="advanced-section-title">شبکه و انتقال</div>
          <div class="advanced-grid">
            <div class="field"><label>Network</label><input id="cNetwork" class="advanced-readonly" type="text" value="WebSocket" readonly></div>
            <div class="field"><label>Mode</label><input id="cNetworkMode" class="advanced-readonly" type="text" value="ws" dir="ltr" readonly></div>
            <div class="field advanced-full"><label>Path</label><input id="cPath" class="advanced-readonly" type="text" value="/ws/{UUID}" dir="ltr" readonly></div>
            <div class="field advanced-full"><label>Host</label><input id="cHost" class="advanced-readonly" type="text" value="دامنه پنل (خودکار)" readonly></div>
          </div>
          <div class="advanced-note">Network و Path متناسب با چهار پروتکل فعلی خودکار تعیین می‌شوند تا با backend واقعی ONEX هماهنگ بمانند و با تغییر دستی خراب نشوند.</div>

          <div class="advanced-section-title">Fragment</div>
          <div class="advanced-grid">
            <div class="field"><label>Fragment</label><select id="cFragment"><option value="off">Off</option><option value="safe">Safe</option><option value="balanced">Balanced</option><option value="aggressive">Aggressive</option></select></div>
          </div>
          <div class="advanced-note">Fragment به‌صورت پارامتر لینک ذخیره می‌شود و روی کلاینت اعمال می‌شود؛ اگر خاموش باشد هیچ پارامتر Fragment به لینک اضافه نمی‌شود.</div>
        </div>
      </div>

      <button class="btn btn-p" style="width:100%" onclick="doManualCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M5 12h14"/></svg>
        <span data-i18n="btn_create">ساخت</span>
      </button>
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


/* ============================================================
   ONEX DARK PERFORMANCE PATCH 1.1.2
   Dark mode was using many backdrop-filter blurs + large shadows
   on scrolling surfaces. On mobile Chromium this can force repeated
   GPU compositing/repaints, making lower content appear progressively.
   Keep the dark glass appearance, but use fast opaque-ish surfaces.
   ============================================================ */

/* Only applies to the actual panel pages, not the login screen. */
html:not(.light) body:has(.page)::before{{
  animation:none !important;
}}
html:not(.light) body:has(.page) *{{
  -webkit-backdrop-filter:none !important;
  backdrop-filter:none !important;
}}

/* Replace expensive 25px glass blur with lightweight dark surfaces. */
html:not(.light) body:has(.page) .sidebar,
html:not(.light) body:has(.page) .mob-bar,
html:not(.light) body:has(.page) .onex-topbar,
html:not(.light) body:has(.page) .onex-control-dock,
html:not(.light) body:has(.page) .onex-card,
html:not(.light) body:has(.page) .onex-metric,
html:not(.light) body:has(.page) .card,
html:not(.light) body:has(.page) .metric,
html:not(.light) body:has(.page) .support-tile,
html:not(.light) body:has(.page) .quick-item,
html:not(.light) body:has(.page) .table-wrap,
html:not(.light) body:has(.page) .sub-box,
html:not(.light) body:has(.page) .link-box,
html:not(.light) body:has(.page) .modal,
html:not(.light) body:has(.page) .toast{{
  box-shadow:
    0 7px 20px rgba(0,0,0,.18),
    inset 0 1px rgba(255,255,255,.045) !important;
}}

/* Keep the panel responsive while preserving the dark blue glass tone. */
html:not(.light) body:has(.page) .onex-topbar,
html:not(.light) body:has(.page) .onex-control-dock,
html:not(.light) body:has(.page) .card,
html:not(.light) body:has(.page) .metric,
html:not(.light) body:has(.page) .onex-card,
html:not(.light) body:has(.page) .onex-metric{{
  background:linear-gradient(145deg,rgba(12,27,50,.96),rgba(4,12,25,.98)) !important;
}}

html:not(.light) body:has(.page) .quick-item,
html:not(.light) body:has(.page) .table-wrap,
html:not(.light) body:has(.page) .sub-box,
html:not(.light) body:has(.page) .link-box{{
  background:linear-gradient(145deg,rgba(10,24,45,.94),rgba(4,12,25,.97)) !important;
}}

/* Stop decorative continuous repainting in the panel. Functional
   spinners/loaders are intentionally left untouched. */
html:not(.light) body:has(.page) .onex-control-dock::before,
html:not(.light) body:has(.page) .onex-3d-control::after,
html:not(.light) body:has(.page) .nav-item.on .nav-ico,
html:not(.light) body:has(.page) .nav-item.on .nav-ico-dash,
html:not(.light) body:has(.page) .nav-item.on .nav-ico-telegram,
html:not(.light) body:has(.page) .nav-item.on .nav-ico-settings,
html:not(.light) body:has(.page) .sb-foot a.danger .logout-ico,
html:not(.light) body:has(.page) .sb-foot button.danger .logout-ico{{
  animation:none !important;
}}

html:not(.light) body:has(.page) .protocol-art-icon{{
  filter:none !important;
}}

/* Theme switching should not animate large shadow layers. */
html:not(.light) body:has(.page) .onex-topbar,
html:not(.light) body:has(.page) .onex-control-dock,
html:not(.light) body:has(.page) .onex-card,
html:not(.light) body:has(.page) .onex-metric,
html:not(.light) body:has(.page) .card,
html:not(.light) body:has(.page) .metric,
html:not(.light) body:has(.page) .support-tile,
html:not(.light) body:has(.page) .quick-item,
html:not(.light) body:has(.page) .table-wrap{{
  transition:background .12s ease,border-color .12s ease,color .12s ease !important;
}}

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

<section class="page admin-page" id="page-admins">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/></svg><span data-i18n="nav_admins">مدیریت ادمین‌ها</span></div>
      <div class="page-sub" data-i18n="admins_sub">مدیریت کاربران مدیریتی و سطح دسترسی آن‌ها</div>
    </div>
    <button class="btn btn-p btn-sm" onclick="document.getElementById('adUser')?.focus()">＋ <span data-i18n="admin_new">ادمین جدید</span></button>
  </div>

  <div class="admin-main-grid">
    <div class="card admin-list-card">
      <div class="admin-list-head">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px">
          <div><div class="card-title" style="margin:0" data-i18n="admin_list">لیست ادمین‌ها</div><div id="adminCount" style="font-size:10px;color:var(--t3);margin-top:3px">—</div></div>
          <button class="btn btn-sm" onclick="loadAdmins()">↻</button>
        </div>
        <div class="admin-list-controls">
          <input id="adminSearch" oninput="renderAdminList()" placeholder="جستجوی ادمین...">
          <select id="adminStatusFilter" onchange="renderAdminList()"><option value="all">همه وضعیت‌ها</option><option value="active">فعال</option><option value="blocked">مسدود</option><option value="invalid">منقضی/نامعتبر</option></select>
        </div>
      </div>
      <div class="admin-table-wrap">
        <div class="admin-table-head"><span>نام کاربری</span><span>نقش</span><span>وضعیت</span><span>آخرین ورود</span><span>عملیات</span></div>
        <div id="adminsList"><div style="color:var(--t3);text-align:center;padding:20px">در حال دریافت...</div></div>
      </div>
    </div>

    <div class="card admin-create-card">
      <div class="admin-create-head"><div><div class="card-title" style="margin:0">ساخت اکانت جدید</div><div style="font-size:10px;color:var(--t3);margin-top:3px">همه ادمین‌ها با همین آدرس پنل وارد می‌شوند.</div></div><span style="font-size:20px">＋</span></div>
      <div class="field" style="margin-top:10px"><label>نام کاربری</label><input id="adUser" placeholder="user1" style="direction:ltr;text-align:left" autocomplete="off"></div>
      <div class="field"><label>عنوان نمایشی</label><input id="adLabel" placeholder="اپراتور فروش"></div>
      <div class="field"><label>رمز عبور</label><input id="adPw" type="password" autocomplete="new-password"></div>
      <div class="field"><label>تکرار رمز</label><input id="adPw2" type="password" autocomplete="new-password"></div>
      <div class="field"><label>نقش</label><select id="adRole"><option value="admin">Admin</option><option value="operator">Operator</option></select></div>
      <div class="form-row"><div class="field"><label>محدودیت حجم</label><input id="adLimit" type="number" value="0" min="0"></div><div class="field"><label>واحد</label><select id="adUnit"><option>GB</option><option>MB</option></select></div></div>
      <div class="field"><label>انقضا (روز)</label><input id="adDays" type="number" value="0" min="0"></div>
      <div class="admin-status-row"><span>وضعیت ادمین</span><label class="switch"><input type="checkbox" id="adActive" checked><span class="slider"></span></label></div>
      <button class="btn btn-p" style="width:100%;margin-top:5px" onclick="createAdmin()">ساخت اکانت ادمین</button>
    </div>
  </div>

  <div class="card admin-perms-card">
    <div class="admin-perm-toolbar">
      <div><div class="card-title" style="margin:0">⚙ دسترسی‌های ادمین</div><div style="font-size:10px;color:var(--t3);margin-top:3px">یک ادمین را انتخاب کنید و دسترسی‌های او را جداگانه فعال یا غیرفعال کنید.</div></div>
      <div style="display:flex;align-items:center;gap:7px"><select id="adminPermTarget" onchange="renderSelectedAdminPerms()" style="min-width:160px;height:34px;font-size:10px"><option value="">انتخاب ادمین</option></select><div class="admin-perm-actions"><button class="btn" onclick="setSelectedAdminPerms(true)">همه</button><button class="btn" onclick="setSelectedAdminPerms(false)">هیچ‌کدام</button></div></div>
    </div>
    <div id="adminPermTargetEmpty" style="text-align:center;color:var(--t3);padding:18px">ابتدا یک ادمین را از لیست انتخاب کنید.</div>
    <div id="adminSelectedPerms" hidden>
      <div id="selectedAdminName" style="font-weight:700;font-size:11px;margin:10px 0 7px"></div>
      <div id="selectedPermGrid" class="admin-perm-grid"></div>
      <button class="btn btn-p" style="width:100%;height:36px;margin-top:10px;font-size:10px" onclick="saveSelectedAdminPerms()">ذخیره دسترسی‌ها</button>
    </div>
  </div>

  <div class="admin-bottom-grid">
    <div class="card admin-activity-card"><div class="card-title">◷ گزارش فعالیت ادمین‌ها</div><div id="adminActivityBox" style="max-height:230px;overflow:auto"><div style="text-align:center;color:var(--t3);padding:18px">در حال دریافت...</div></div></div>
    <div class="card admin-details-card"><div class="card-title">👤 جزئیات ادمین</div><div id="adminDetails" style="color:var(--t3);font-size:11px;line-height:2;text-align:center;padding:10px">برای مشاهده جزئیات، یک ادمین را انتخاب کنید.</div></div>
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
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_groups:'گروه‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',nav_donate:'حمایت مالی',nav_news:'تلگرام',nav_admins:'مدیریت ادمین‌ها',admin_new:'ادمین جدید',admin_same_url:'همه ادمین‌ها با همین آدرس پنل وارد می‌شوند و تفاوت فقط در حساب و دسترسی‌هاست.',admin_label:'عنوان نمایشی',perm_all:'همه',perm_none:'هیچ‌کدام',refresh_news:'بروزرسانی اطلاعیه',admins_sub:'ساخت اکانت ادمین با دسترسی سفارشی',admin_create:'ساخت اکانت ادمین',admin_user:'نام کاربری',admin_pw:'رمز عبور',admin_pw2:'تکرار رمز',admin_perms:'دسترسی‌ها',admin_btn:'ساخت اکانت',admin_list:'لیست ادمین‌ها',refresh:'بروزرسانی',refresh_stats:'بروزرسانی آمار',refresh_panel:'بروزرسانی پنل',panel_version:'نسخه پنل',current_version:'ورژن فعلی',nav_telegram:'ربات تلگرام',tg_sub:'توکن ربات و آیدی عددی ادمین · فعال‌سازی خودکار و وب‌هوک',tg_config:'پیکربندی ربات',tg_token:'توکن ربات (BotFather)',tg_admin:'آیدی عددی ادمین',tg_webhook:'فعال‌سازی Webhook (پیشنهادی روی Railway)',tg_activate:'ذخیره و فعال‌سازی ربات',tg_help:'راهنما',tg_h1:'از @BotFather یک ربات بساز و توکن را کپی کن',tg_h2:'آیدی عددی خودت را از @userinfobot بگیر',tg_h3:'ذخیره کن — وب‌هوک خودکار روی دامنه Railway ست می‌شود',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_proto:'پروتکل',label_count:'تعداد کانفیگ در ساب (۱–۴۰)',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_groups:'Groups',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',nav_donate:'Donate',nav_news:'Telegram',nav_admins:'Admin Management',admin_new:'New admin',admin_same_url:'All admins use the same panel address; only the account and permissions differ.',admin_label:'Display label',perm_all:'All',perm_none:'None',refresh_news:'Refresh news',admins_sub:'Create admin accounts with custom access',admin_create:'Create admin account',admin_user:'Username',admin_pw:'Password',admin_pw2:'Confirm password',admin_perms:'Permissions',admin_btn:'Create account',admin_list:'Admin list',refresh:'Refresh',refresh_stats:'Refresh stats',refresh_panel:'Update panel',panel_version:'Panel version',current_version:'Current version',nav_telegram:'Telegram bot',tg_sub:'Bot token and numeric admin ID · auto activate and webhook',tg_config:'Bot configuration',tg_token:'Bot token (BotFather)',tg_admin:'Admin numeric ID',tg_webhook:'Enable Webhook (recommended on Railway)',tg_activate:'Save and activate bot',tg_help:'Guide',tg_h1:'Create a bot with @BotFather and copy the token',tg_h2:'Get your numeric ID from @userinfobot',tg_h3:'Save — webhook is set automatically on Railway domain',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed, count and expiry',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_proto:'Protocol',label_count:'Configs in sub (1–40)',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
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

let __loggingOut=false;
async function logoutPanel(){
  if(__loggingOut)return;
  __loggingOut=true;
  const btn=document.getElementById('panelLogoutBtn');
  if(btn){btn.disabled=true;btn.setAttribute('aria-busy','true');}
  try{
    await fetch('/api/logout',{
      method:'POST',
      cache:'no-store',
      credentials:'same-origin',
      headers:{'X-Requested-With':'XMLHttpRequest'}
    });
  }catch(e){}
  window.location.replace('/login');
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

function toggleManualAdvanced(){
  const box=document.getElementById('manualAdvanced');
  if(!box)return;
  const open=!box.classList.contains('open');
  box.classList.toggle('open',open);
  const btn=box.querySelector('.advanced-toggle');
  if(btn)btn.setAttribute('aria-expanded',open?'true':'false');
}
function currentManualProtocol(){return document.getElementById('cProto')?.value||'vless-ws'}
function toggleManualRealityFields(){const mode=document.getElementById('cTlsMode')?.value||'tls';const box=document.getElementById('manualRealityFields');if(box)box.style.display=mode==='reality'?'grid':'none'}
function manualProtocolDefaults(id){
  const map={
    'vless-ws':{network:'WebSocket',mode:'ws',path:'/ws/{UUID}',alpn:['http/1.1']},
    'xhttp-packet-up':{network:'XHTTP',mode:'packet-up',path:'/xhttp-siz10/packet-up/{UUID}',alpn:['h2','http/1.1']},
    'xhttp-stream-up':{network:'XHTTP',mode:'stream-up',path:'/xhttp-siz10/stream-up/{UUID}',alpn:['h2','http/1.1']},
    'xhttp-stream-one':{network:'XHTTP',mode:'stream-one',path:'/xhttp-siz10/stream-one/{UUID}',alpn:['h2','http/1.1']}
  };
  return map[id]||map['vless-ws'];
}
function syncManualAdvancedForProtocol(){
  const id=currentManualProtocol(),d=manualProtocolDefaults(id);
  const n=document.getElementById('cNetwork'),m=document.getElementById('cNetworkMode'),p=document.getElementById('cPath');
  if(n)n.value=d.network;if(m)m.value=d.mode;if(p)p.value=d.path;
  document.querySelectorAll('#cAlpnChoices input[type="checkbox"]').forEach(x=>x.checked=d.alpn.includes(x.value));
}
function collectManualAlpn(){const picked=[...document.querySelectorAll('#cAlpnChoices input[type="checkbox"]:checked')].map(x=>x.value);const custom=document.getElementById('cAlpnCustom')?.value||'';return [...picked,...custom.split(',').map(x=>x.trim()).filter(Boolean)].filter((v,i,a)=>a.indexOf(v)===i).join(',')}
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
    fingerprint:document.getElementById('cFingerprint')?.value||'chrome',
    alpn:collectManualAlpn(),
    sni:document.getElementById('cSni')?.value.trim()||'',
    allow_insecure:(document.getElementById('cAllowInsecure')?.value||'false')==='true',
    tls_mode:document.getElementById('cTlsMode')?.value||'tls',
    reality_public_key:document.getElementById('cRealityPublicKey')?.value.trim()||'',
    reality_short_id:document.getElementById('cRealityShortId')?.value.trim()||'',
    reality_spider_x:document.getElementById('cRealitySpiderX')?.value.trim()||'',
    reality_target:document.getElementById('cRealityTarget')?.value.trim()||'',
    port:Math.max(1,Math.min(65535,Number(document.getElementById('cPort')?.value)||443)),
    fragment:document.getElementById('cFragment')?.value||'off',
    all_protocols:!!document.getElementById('cAllProtocols')?.checked
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
  fa:{dash:'داشبورد',configs:'مدیریت کانفیگ‌ها',create:'ساخت کانفیگ',delete_config:'حذف کانفیگ',delete_all_configs:'حذف همه کانفیگ‌ها',subscriptions:'مدیریت Subscription',groups:'مدیریت گروه‌ها',stats:'مشاهده آمار',logs:'مدیریت لاگ‌ها',settings:'تنظیمات پنل',api:'دسترسی به API',users:'مدیریت کاربران',vps:'مدیریت VPS',xray:'مدیریت تنظیمات Xray',advanced:'دسترسی به تنظیمات پیشرفته',support:'پشتیبانی',telegram:'ربات تلگرام',news:'اخبار',admins:'مدیریت ادمین‌ها'},
  en:{dash:'Dashboard',configs:'Config management',create:'Create config',delete_config:'Delete config',delete_all_configs:'Delete all configs',subscriptions:'Subscription management',groups:'Group management',stats:'View statistics',logs:'Activity logs',settings:'Panel settings',api:'API access',users:'User management',vps:'VPS management',xray:'Xray settings',advanced:'Advanced settings',support:'Support',telegram:'Telegram bot',news:'News',admins:'Admin management'}
};
const PERM_GROUPS={
  fa:[['مدیریت کانفیگ‌ها',['configs','create','delete_config','delete_all_configs','subscriptions']],['سیستم و سرویس',['stats','groups','vps','xray','admins']],['پنل و دسترسی',['settings','logs','api','users','advanced']]],
  en:[['Configs & subscriptions',['configs','create','delete_config','delete_all_configs','subscriptions']],['System & services',['stats','groups','vps','xray','admins']],['Panel & access',['settings','logs','api','users','advanced']]]
};
let USER_PERMS=null;
let USER_ROLE='owner';
function buildPermChecks(containerId, selected){
  const box=document.getElementById(containerId);
  if(!box)return;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  const groups=PERM_GROUPS[lang]||PERM_GROUPS.fa;
  box.innerHTML=groups.map(([title,keys])=>`<div class="admin-perm-group"><div class="admin-perm-group-title">${title}</div>${keys.map(k=>{const on=selected?!!selected[k]:(['dash','configs','create','stats','news'].includes(k));return `<div class="admin-perm-item"><span>${esc(labels[k]||k)}</span><label class="switch"><input type="checkbox" data-perm="${k}" ${on?'checked':''}><span class="slider"></span></label></div>`}).join('')}</div>`).join('');
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
let __adminsCache=[];
function adminStatusText(a){
  if(a.blocked) return lang==='fa'?'مسدود':'Blocked';
  if(!a.valid) return lang==='fa'?'نامعتبر':'Invalid';
  return lang==='fa'?'فعال':'Active';
}
function adminStatusClass(a){
  if(a.blocked) return 'background:rgba(239,68,68,.10);color:#ef4444;border-color:rgba(239,68,68,.25)';
  if(!a.valid) return 'background:rgba(245,158,11,.10);color:#d97706;border-color:rgba(245,158,11,.25)';
  return 'background:rgba(16,185,129,.10);color:#059669;border-color:rgba(16,185,129,.25)';
}
function setAllAdminPerms(value){
  document.querySelectorAll('#adPerms input[data-perm]').forEach(x=>x.checked=!!value);
}
function renderAdminList(){
  const box=document.getElementById('adminsList');
  const count=document.getElementById('adminCount');
  const search=(document.getElementById('adminSearch')?.value||'').trim().toLowerCase();
  const filter=document.getElementById('adminStatusFilter')?.value||'all';
  const all=Array.isArray(__adminsCache)?__adminsCache:[];
  const rows=all.filter(a=>{
    const hay=[a.username,a.label,a.role].map(x=>String(x||'').toLowerCase()).join(' ');
    if(search && !hay.includes(search)) return false;
    if(filter==='active' && !a.valid) return false;
    if(filter==='blocked' && !a.blocked) return false;
    if(filter==='invalid' && a.valid) return false;
    return true;
  });
  if(count) count.textContent=lang==='fa'?`${rows.length} مورد نمایش داده می‌شود · ${all.length} ادمین`:`${rows.length} shown · ${all.length} admins`;
  const sel=document.getElementById('adminPermTarget');
  if(sel){
    const current=sel.value;
    sel.innerHTML='<option value="">انتخاب ادمین</option>'+all.map(a=>`<option value="${esc(a.id)}">${esc(a.label||a.username)} (@${esc(a.username)})</option>`).join('');
    if(current && all.some(a=>a.id===current)) sel.value=current;
  }
  if(!box)return;
  if(!rows.length){box.innerHTML='<div style="color:var(--t3);text-align:center;padding:24px">ادمینی با این فیلتر پیدا نشد.</div>';return}
  box.innerHTML=rows.map(a=>{
    const status=adminStatusText(a);
    const statusStyle=adminStatusClass(a);
    const role=a.role==='operator'?'Operator':'Admin';
    return `<div class="admin-row" onclick="showAdminDetails('${esc(a.id)}')">
      <div style="display:flex;align-items:center;gap:8px;min-width:0"><span class="admin-avatar">${esc((a.username||'A')[0].toUpperCase())}</span><div style="min-width:0"><b style="display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(a.username||'—')}</b><span style="font-size:8px;color:var(--t3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block">${esc(a.label||'')}</span></div></div>
      <span class="admin-role">${role}</span>
      <span class="admin-state" style="${statusStyle}">${status}</span>
      <span style="font-size:9px;color:var(--t3)">${formatAdminDate(a.last_login_at)}</span>
      <div class="admin-actions" onclick="event.stopPropagation()">
        <button class="btn" title="ویرایش" onclick="editAdmin('${esc(a.id)}')">✎</button>
        <button class="btn btn-d" title="${a.active?'غیرفعال کردن':'فعال کردن'}" onclick="toggleActiveAdmin('${esc(a.id)}',${!a.active})">${a.active?'⊘':'✓'}</button>
        <button class="btn" title="حذف" onclick="deleteAdmin('${esc(a.id)}')">⋮</button>
      </div>
    </div>`;
  }).join('');
}
function setSelectedAdminPerms(value){
  document.querySelectorAll('#selectedPermGrid input[data-admin-perm]').forEach(x=>x.checked=!!value);
}
function showAdminDetails(id){
  const a=__adminsCache.find(x=>x.id===id); if(!a)return;
  const sel=document.getElementById('adminPermTarget'); if(sel)sel.value=id;
  renderSelectedAdminPerms();
  const perms=Object.values(a.permissions||{}).filter(Boolean).length;
  const box=document.getElementById('adminDetails'); if(!box)return;
  box.style.textAlign='right';
  box.innerHTML=`<div style="text-align:center;margin-bottom:10px"><div style="width:54px;height:54px;border-radius:50%;display:grid;place-items:center;background:linear-gradient(135deg,#2563eb,#7c3aed);color:#fff;font-size:20px;font-weight:800;margin:auto">${esc((a.username||'A')[0].toUpperCase())}</div><b style="display:block;margin-top:6px">${esc(a.label||a.username)}</b><small style="color:var(--t3);direction:ltr;display:block">@${esc(a.username)}</small></div>
  <div><b>نقش:</b> ${a.role==='operator'?'Operator':'Admin'}</div><div><b>وضعیت:</b> ${adminStatusText(a)}</div><div><b>آخرین ورود:</b> ${formatAdminDate(a.last_login_at)}</div><div dir="ltr"><b>IP:</b> ${esc(a.last_login_ip||'—')}</div><div><b>تاریخ ایجاد:</b> ${formatAdminDate(a.created_at)}</div><div><b>دسترسی:</b> ${perms}/${ALL_PERMS.length}</div>
  <div style="display:flex;gap:7px;margin-top:12px"><button class="btn" style="flex:1" onclick="editAdmin('${esc(a.id)}')">✎ ویرایش</button><button class="btn btn-d" style="flex:1" onclick="toggleActiveAdmin('${esc(a.id)}',${!a.active})">${a.active?'غیرفعال کردن':'فعال کردن'}</button></div>`;
}
function renderSelectedAdminPerms(){
  const id=document.getElementById('adminPermTarget')?.value, empty=document.getElementById('adminPermTargetEmpty'), wrap=document.getElementById('adminSelectedPerms'), name=document.getElementById('selectedAdminName'), grid=document.getElementById('selectedPermGrid');
  const a=__adminsCache.find(x=>x.id===id);
  if(!a){if(empty)empty.hidden=false;if(wrap)wrap.hidden=true;return}
  if(empty)empty.hidden=true;if(wrap)wrap.hidden=false;
  if(name)name.textContent=`${a.label||a.username}  (@${a.username})`;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  if(grid){const labels=PERM_LABELS[lang]||PERM_LABELS.fa;const groups=PERM_GROUPS[lang]||PERM_GROUPS.fa;grid.innerHTML=groups.map(([title,keys])=>`<div class="admin-perm-group"><div class="admin-perm-group-title">${title}</div>${keys.map(p=>`<div class="admin-perm-item"><span>${esc(labels[p]||p)}</span><label class="switch"><input type="checkbox" data-admin-perm="${p}" ${a.permissions&&a.permissions[p]?'checked':''}><span class="slider"></span></label></div>`).join('')}</div>`).join('')}
}
async function saveSelectedAdminPerms(){
  const id=document.getElementById('adminPermTarget')?.value;if(!id)return;
  const permissions={};document.querySelectorAll('#selectedPermGrid input[data-admin-perm]').forEach(x=>permissions[x.dataset.adminPerm]=x.checked);
  await patchAdmin(id,{permissions},lang==='fa'?'دسترسی‌ها ذخیره شد':'Permissions saved');
}
async function loadAdminActivity(){
  const box=document.getElementById('adminActivityBox');if(!box)return;
  const data=await api('/api/activity');const logs=Array.isArray(data)?data:(data&&data.logs)||[];
  if(!logs.length){box.innerHTML='<div style="text-align:center;color:var(--t3);padding:18px">لاگی ثبت نشده است.</div>';return}
  box.innerHTML=logs.slice().reverse().slice(0,12).map(l=>`<div style="display:flex;gap:10px;padding:9px 2px;border-bottom:1px solid var(--card-b);font-size:11px"><span style="color:var(--t3);white-space:nowrap">${esc((l.time||l.ts||'').toString().slice(11,19)||'—')}</span><span>${esc(l.message||l.msg||'—')}</span></div>`).join('');
}
async function loadAdmins(){
  const r=await api('/api/admins');
  if(!r||!r.admins){const box=document.getElementById('adminsList');if(box)box.innerHTML='<div style="color:var(--t3);text-align:center;padding:20px">—</div>';return}
  __adminsCache=r.admins||[];
  renderAdminList();
  loadAdminActivity();
  const current=document.getElementById('adminPermTarget')?.value;
  const target=current && __adminsCache.some(a=>a.id===current) ? current : (__adminsCache[0]?.id||'');
  const sel=document.getElementById('adminPermTarget');
  if(sel) sel.value=target;
  if(target){renderSelectedAdminPerms();showAdminDetails(target)}
}
async function createAdmin(){
  const body={
    username:document.getElementById('adUser').value.trim(),
    label:document.getElementById('adLabel')?.value.trim(),
    password:document.getElementById('adPw').value,
    repeat_password:document.getElementById('adPw2').value,
    limit_value:Number(document.getElementById('adLimit').value)||0,
    limit_unit:document.getElementById('adUnit').value,
    expires_days:Number(document.getElementById('adDays').value)||0,
    role:document.getElementById('adRole')?.value||'admin',
    active:!!document.getElementById('adActive')?.checked,
    permissions:Object.fromEntries(ALL_PERMS.map(p=>[p, ['dash','configs','create','stats','groups','news'].includes(p)]))
  };
  if(!body.username){toast(lang==='fa'?'نام کاربری را وارد کنید':'Enter a username');return}
  if(!body.password || body.password.length<6){toast(lang==='fa'?'رمز عبور حداقل ۶ کاراکتر باشد':'Password must be at least 6 characters');return}
  if(body.password!==body.repeat_password){toast(lang==='fa'?'تکرار رمز یکسان نیست':'Passwords do not match');return}
  const r=await api('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){
    toast(lang==='fa'?'اکانت ساخته شد':'Created');
    ['adUser','adLabel','adPw','adPw2'].forEach(id=>{const e=document.getElementById(id);if(e)e.value=''});
    await loadAdmins();
    const sel=document.getElementById('adminPermTarget');
    if(sel && r.id){sel.value=r.id;renderSelectedAdminPerms();showAdminDetails(r.id);document.getElementById('adminSelectedPerms')?.scrollIntoView({behavior:'smooth',block:'center'})}
  }
}
async function patchAdmin(id,payload,okText){
  const r=await api('/api/admins/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  if(r){toast(okText||'OK');loadAdmins()}
}
async function toggleActiveAdmin(id,active){
  if(!active && !confirm(lang==='fa'?'این ادمین غیرفعال شود؟':'Disable this admin?'))return;
  await patchAdmin(id,{active},active?(lang==='fa'?'فعال شد':'Enabled'):(lang==='fa'?'غیرفعال شد':'Disabled'));
}
async function toggleBlockAdmin(id,blocked){
  await patchAdmin(id,{blocked},blocked?(lang==='fa'?'مسدود شد':'Blocked'):(lang==='fa'?'رفع مسدودی شد':'Unblocked'));
}
async function editAdmin(id){
  const a=__adminsCache.find(x=>x.id===id);if(!a)return;
  const labels=PERM_LABELS[lang]||PERM_LABELS.fa;
  const body=document.getElementById('panelModalBody');
  const title=document.getElementById('panelModalTitle');
  if(!body||!title)return;
  title.textContent=lang==='fa'?'ویرایش ادمین':'Edit admin';
  body.innerHTML=`<div class="field"><label>${lang==='fa'?'عنوان نمایشی':'Display label'}</label><input id="edLabel" value="${esc(a.label||'')}"></div>
    <div class="field"><label>${lang==='fa'?'رمز جدید (اختیاری)':'New password (optional)'}</label><input id="edPw" type="password" autocomplete="new-password"></div>
    <div class="form-row"><div class="field"><label>${lang==='fa'?'محدودیت حجم':'Traffic limit'}</label><input id="edLimit" type="number" min="0" value="${a.limit_bytes?Math.round(a.limit_bytes/1073741824*100)/100:0}"></div><div class="field"><label>${lang==='fa'?'واحد':'Unit'}</label><select id="edUnit"><option>GB</option><option>MB</option></select></div></div>
    <div class="field"><label>${lang==='fa'?'انقضا (روز از امروز)':'Expiry (days from today)'}</label><input id="edDays" type="number" min="0" value="0"></div>
    <div class="card-title" style="margin-top:10px">${lang==='fa'?'دسترسی‌ها':'Permissions'}</div><div id="edPerms" style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:12px"></div>`;
  document.getElementById('panelModal').classList.add('open');
  buildPermChecks('edPerms');
  Object.entries(a.permissions||{}).forEach(([k,v])=>{const el=document.querySelector(`#edPerms input[data-perm="${k}"]`);if(el)el.checked=!!v});
  document.getElementById('panelModal').dataset.adminId=id;
  document.getElementById('panelModal').dataset.adminOriginalLimit=a.limit_bytes||0;
  const actions=document.querySelector('#panelModal .modal-actions');
  if(actions)actions.innerHTML=`<button class="btn" onclick="document.getElementById('panelModal').classList.remove('open')">${lang==='fa'?'انصراف':'Cancel'}</button><button class="btn btn-p" onclick="saveAdminEdit()">${lang==='fa'?'ذخیره تغییرات':'Save changes'}</button>`;
}
async function saveAdminEdit(){
  const id=document.getElementById('panelModal')?.dataset.adminId;if(!id)return;
  const body={label:document.getElementById('edLabel')?.value.trim(),permissions:readPermChecks('edPerms')};
  const pw=document.getElementById('edPw')?.value||'';if(pw)body.password=pw;
  const lv=Number(document.getElementById('edLimit')?.value)||0;const lu=document.getElementById('edUnit')?.value||'GB';
  body.limit_value=lv;body.limit_unit=lu;
  const days=Number(document.getElementById('edDays')?.value)||0;body.expires_days=days;
  const r=await api('/api/admins/'+id,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){document.getElementById('panelModal').classList.remove('open');toast(lang==='fa'?'تغییرات ذخیره شد':'Changes saved');loadAdmins()}
}
async function deleteAdmin(id){
  const a=__adminsCache.find(x=>x.id===id);
  if(!confirm(lang==='fa'?`اکانت «${a?.username||''}» حذف شود؟ این عمل قابل بازگشت نیست.`:`Delete “${a?.username||''}”? This cannot be undone.`))return;
  const r=await api('/api/admins/'+id,{method:'DELETE'});
  if(r){toast(lang==='fa'?'اکانت حذف شد':'Deleted');loadAdmins()}
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
  {title:'',ids:['vless-ws','xhttp-packet-up','xhttp-stream-up','xhttp-stream-one']}
];
const PROTOCOL_PICKER_NAMES={"vless-ws":"Nova Link","xhttp-packet-up":"XPacket Nova","xhttp-stream-up":"XStream Pulse","xhttp-stream-one":"XStream Edge","trojan":"Trojan","shadowsocks":"Shadowsocks","socks5":"SOCKS5","http":"HTTP Proxy","hysteria2":"Hysteria2","vless-grpc-reality":"VLESS gRPC Reality"};
const PROTOCOL_3D_ICONS={
  "vless-ws":{c1:"#24a9ff",c2:"#1264ff",c3:"#6d3cff",mark:"V",glow:"#168cff"},
  "xhttp-packet-up":{c1:"#35c8ff",c2:"#0877d8",c3:"#3155ff",mark:"XP",glow:"#21b8ff"},
  "xhttp-stream-up":{c1:"#36e6ff",c2:"#0894c9",c3:"#16b7d1",mark:"XS",glow:"#21d9ee"},
  "xhttp-stream-one":{c1:"#b04cff",c2:"#6b1fe1",c3:"#3b25ad",mark:"XC",glow:"#a14cff"},
  "vmess-ws":{c1:"#d05cff",c2:"#7726e8",c3:"#4522a6",mark:"M",glow:"#a54cff"},
  "trojan":{c1:"#ff6676",c2:"#e51c35",c3:"#a90f2b",mark:"T",glow:"#ff4058"},
  "shadowsocks":{c1:"#54e887",c2:"#11ae57",c3:"#078341",mark:"S",glow:"#22d66c"},
  "socks5":{c1:"#45dfff",c2:"#0b9fc8",c3:"#08779e",mark:"5",glow:"#20d5ff"},
  "http":{c1:"#78a7ff",c2:"#3975e8",c3:"#2448a9",mark:"H",glow:"#4d8cff"},
  "hysteria2":{c1:"#55e9ff",c2:"#08a9c5",c3:"#087b99",mark:"H2",glow:"#21dfff"},
  "vless-grpc-reality":{c1:"#b04cff",c2:"#6b1fe1",c3:"#3b25ad",mark:"GR",glow:"#a14cff"},
};
let __protocolPickerTarget='' ;
let __protocolPickerOptions=[];
function protocolPickerLabel(id){const p=__protocolPickerOptions.find(x=>x.id===id);return PROTOCOL_PICKER_NAMES[id]||p?.label||id||'Vortex Link'}
function protocolPickerShort(id){return PROTOCOL_PICKER_NAMES[id]||id}
const PROTOCOL_ICON_DATA={"vless-ws":"data:image/png;base64,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","xhttp-packet-up":"data:image/png;base64,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","xhttp-stream-up":"data:image/png;base64,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","xhttp-stream-one":"data:image/png;base64,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"};
function protocolIconMarkup(id){
  // Icons are embedded in the dashboard so Railway does not depend on
  // serving separate PNG files from the deployment filesystem.
  const srcMap=PROTOCOL_ICON_DATA;
  const src=srcMap[id]||srcMap["vless-ws"];
  return `<span class="protocol-option-icon proto-3d" aria-hidden="true"><img class="protocol-art-icon" src="${src}" alt="" loading="eager" decoding="async"></span>`
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

syncManualAdvancedForProtocol();
document.getElementById('cProto')?.addEventListener('change',syncManualAdvancedForProtocol);
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
