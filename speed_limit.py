"""Small per-link bandwidth throttle used by ONEX relay backends."""
from __future__ import annotations

import asyncio
import time


def _rate(uid: str) -> int:
    try:
        from main import LINKS
        link = LINKS.get(uid) or {}
        return max(0, int(link.get("speed_limit_bytes", 0) or 0))
    except Exception:
        return 0


async def throttle(uid: str, amount: int) -> None:
    """Apply a simple non-blocking per-link byte-rate limit.

    A zero/negative rate means unlimited. The relay calls this once per chunk,
    so the sleep remains cooperative and does not block other connections.
    """
    if amount <= 0:
        return
    rate = _rate(uid)
    if rate <= 0:
        return
    await asyncio.sleep(min(10.0, max(0.0, amount / float(rate))))
