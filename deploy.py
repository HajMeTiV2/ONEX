"""Small deployment helpers shared by supported hosting platforms."""
from __future__ import annotations

import os
from urllib.parse import urlsplit


PUBLIC_ENV_VARS = (
    "ONEX_PUBLIC_URL", "PUBLIC_URL", "PUBLIC_DOMAIN", "PUBLIC_HOST",
    "APP_URL", "APP_DOMAIN", "EXTERNAL_URL", "EXTERNAL_DOMAIN",
    "SERVICE_URL", "SERVICE_DOMAIN", "RENDER_EXTERNAL_URL",
    "RENDER_EXTERNAL_HOSTNAME", "KOYEB_PUBLIC_DOMAIN", "RAILWAY_PUBLIC_DOMAIN",
    "RAILWAY_STATIC_URL", "FLY_APP_NAME", "FLY_ALLOC_ID", "VERCEL_URL",
    "VERCEL_BRANCH_URL", "NETLIFY_URL", "DEPLOY_PRIME_URL",
    "REPLIT_DEV_DOMAIN", "REPLIT_DOMAINS",
)


def normalize_public_host(value: str) -> str:
    raw = str(value or "").strip().strip("'\"")
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else "//" + raw)
    host = (parsed.hostname or "").strip("[]").lower()
    if host in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}:
        return ""
    return host


def public_endpoint_candidates() -> list[str]:
    values: list[str] = []
    for name in PUBLIC_ENV_VARS:
        value = normalize_public_host(os.environ.get(name, ""))
        if value and value not in values:
            values.append(value)
    return values
