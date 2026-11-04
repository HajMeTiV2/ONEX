"""ONEX Sell Bot: plans, orders, card-to-card receipts and automatic delivery.

Flow
  1. Customer opens the bot and taps "🛒 خرید اشتراک" and picks a plan.
  2. The bot shows the payment details (card number / payment link) and waits
     for a receipt (photo or text).
  3. Every bot admin receives the receipt with ✅ approve / ❌ reject buttons.
     Orders can also be approved from the panel (Sell page).
  4. On approval a real ONEX link is created with the plan's volume, days,
     IP limit and protocol, owned by the customer (telegram_owner_id), and the
     subscription URL is delivered to the customer.
  5. A background loop warns customers before their service expires or runs
     out of traffic.

State lives in DATA_DIR/sell_settings.json and DATA_DIR/sell_orders.json.
The module never imports ``main`` at import time; it resolves the running
application module lazily so it works under ``uvicorn main:app`` and
``python main.py`` alike.
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import secrets
import sys
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response


CF_PROTOCOLS = ["vmess-ws", "vless-ws", "trojan-ws"]


def _m():
    mod = sys.modules.get("main")
    if mod is not None and hasattr(mod, "LINKS"):
        return mod
    mod = sys.modules.get("__main__")
    if mod is not None and hasattr(mod, "LINKS"):
        return mod
    import main as mod  # noqa: WPS433 (last resort)
    return mod


def _bot():
    from onex.integrations import telegram_bot
    return telegram_bot


GB = 1024 ** 3
_LOCK = asyncio.Lock()
_expiry_task: asyncio.Task | None = None

DEFAULT_SETTINGS = {
    "enabled": False,
    "hide_free_create": True,
    "card_number": "",
    "card_holder": "",
    "bank_name": "",
    "payment_url": "",
    "payment_note": "بعد از واریز، عکس رسید یا کد پیگیری را همین‌جا بفرستید.",
    "support_username": "",
    "welcome_text": "🛒 به فروشگاه ONEX خوش آمدید.\nیکی از پلن‌های زیر را انتخاب کنید:",
    "expiry_warn_days": 2,
    "usage_warn_percent": 85,
    "plans": [],
}


def _data_dir() -> Path:
    return Path(_m().DATA_DIR)


def _settings_file() -> Path:
    return _data_dir() / "sell_settings.json"


def _orders_file() -> Path:
    return _data_dir() / "sell_orders.json"


def _read_json(path: Path, default):
    try:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, type(default)):
                return data
    except Exception:
        pass
    return default


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_settings() -> dict:
    data = _read_json(_settings_file(), {})
    out = {**DEFAULT_SETTINGS, **data}
    if not isinstance(out.get("plans"), list):
        out["plans"] = []
    return out


def save_settings(data: dict) -> None:
    _write_json(_settings_file(), data)


def load_orders() -> dict:
    return _read_json(_orders_file(), {})


def save_orders(data: dict) -> None:
    # Keep the file bounded: newest 2000 orders.
    if len(data) > 2000:
        keep = sorted(data.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)[:2000]
        data = dict(keep)
    _write_json(_orders_file(), data)


def is_enabled() -> bool:
    return bool(load_settings().get("enabled"))


def hide_free_create() -> bool:
    s = load_settings()
    return bool(s.get("enabled") and s.get("hide_free_create", True))


# ---------------------------------------------------------------- plans

def normalize_plan(raw: dict, old: dict | None = None) -> dict:
    old = old or {}
    m = _m()
    name = str(raw.get("name", old.get("name", ""))).strip()[:60]
    if not name:
        raise ValueError("نام پلن الزامی است")
    try:
        price = int(str(raw.get("price", old.get("price", 0))).replace(",", "").strip() or 0)
    except ValueError:
        raise ValueError("قیمت باید عدد باشد (تومان)")
    if price < 0:
        raise ValueError("قیمت نامعتبر است")
    traffic_gb = float(raw.get("traffic_gb", old.get("traffic_gb", 0)) or 0)
    days = int(raw.get("days", old.get("days", 30)) or 0)
    ip_limit = int(raw.get("ip_limit", old.get("ip_limit", 0)) or 0)
    if not (0 <= traffic_gb <= 100000) or not (0 <= days <= 3650) or not (0 <= ip_limit <= 1000):
        raise ValueError("حجم/روز/محدودیت IP نامعتبر است")
    protocol = str(raw.get("protocol", old.get("protocol", m.DEFAULT_PROTOCOL)) or m.DEFAULT_PROTOCOL)
    all_protocols = bool(raw.get("all_protocols", old.get("all_protocols", False)))
    raw_bundle = raw.get("protocols", old.get("bundle_protocols"))
    allowed = set(m.PROTOCOLS) if protocol != "cloudflare" else set(CF_PROTOCOLS)
    bundle = []
    if isinstance(raw_bundle, list):
        for x in raw_bundle:
            x = str(x)
            if x in allowed and x not in bundle:
                bundle.append(x)
    if protocol in ("onex_vip", "cloudflare"):
        if not bundle:
            bundle = list(CF_PROTOCOLS) if protocol == "cloudflare" else []
        all_protocols = False
        protocol = bundle[0] if bundle else m.DEFAULT_PROTOCOL
    elif not all_protocols and protocol not in m.PROTOCOLS:
        protocol = m.DEFAULT_PROTOCOL
        bundle = []
    return {
        "id": old.get("id") or "pln_" + secrets.token_hex(4),
        "name": name,
        "price": price,
        "traffic_gb": round(traffic_gb, 2),
        "days": days,
        "ip_limit": ip_limit,
        "protocol": protocol,
        "all_protocols": all_protocols,
        "bundle_protocols": bundle,
        "enabled": bool(raw.get("enabled", old.get("enabled", True))),
        "created_at": old.get("created_at") or datetime.now().isoformat(),
    }


def active_plans() -> list[dict]:
    return [p for p in load_settings()["plans"] if p.get("enabled", True)]


def find_plan(pid: str) -> dict | None:
    for p in load_settings()["plans"]:
        if p.get("id") == pid:
            return p
    return None


def _price(n) -> str:
    try:
        n = int(n)
    except Exception:
        return str(n)
    return "رایگان" if n == 0 else f"{n:,} تومان"


def _plan_line(p: dict) -> str:
    vol = "نامحدود" if not p.get("traffic_gb") else f"{p['traffic_gb']:g} گیگ"
    days = "بدون انقضا" if not p.get("days") else f"{p['days']} روز"
    ip = f" · {p['ip_limit']} کاربره" if p.get("ip_limit") else ""
    return f"{p['name']} | {vol} | {days}{ip} | {_price(p.get('price'))}"


# ---------------------------------------------------------------- orders

def _new_order_id() -> str:
    return "ord_" + secrets.token_hex(4)


def _esc(s) -> str:
    return _m().escape_html(str(s or ""))


async def create_order(chat_id: int, user: dict, plan: dict) -> dict:
    async with _LOCK:
        orders = load_orders()
        # One open order per customer: reuse/replace an unpaid one.
        for oid, o in list(orders.items()):
            if str(o.get("chat_id")) == str(chat_id) and o.get("status") == "awaiting_receipt":
                o["status"] = "cancelled"
                o["updated_at"] = datetime.now().isoformat()
        oid = _new_order_id()
        orders[oid] = {
            "id": oid,
            "chat_id": chat_id,
            "username": user.get("username") or "",
            "name": " ".join(x for x in (user.get("first_name"), user.get("last_name")) if x).strip(),
            "plan": dict(plan),
            "status": "awaiting_receipt",
            "receipt_file_id": "",
            "receipt_text": "",
            "link_uid": "",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
        }
        save_orders(orders)
        return orders[oid]


def _open_order_for(chat_id: int) -> dict | None:
    for o in sorted(load_orders().values(), key=lambda x: x.get("created_at", ""), reverse=True):
        if str(o.get("chat_id")) == str(chat_id) and o.get("status") == "awaiting_receipt":
            return o
    return None


async def approve_order(oid: str, by: str = "panel") -> dict:
    m = _m()
    async with _LOCK:
        orders = load_orders()
        o = orders.get(oid)
        if not o:
            raise ValueError("سفارش پیدا نشد")
        if o.get("status") == "approved":
            return o
        if o.get("status") not in ("pending_review", "awaiting_receipt"):
            raise ValueError("این سفارش قابل تأیید نیست")
        plan = o["plan"]
        days = int(plan.get("days") or 0)
        expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
        uname = (o.get("username") or str(o.get("chat_id")))[:16]
        bundle = list(plan.get("bundle_protocols") or []) or None
        uid, link = await m.make_link(
            label=f"{uname}-{secrets.token_hex(2)}",
            limit_bytes=int(float(plan.get("traffic_gb") or 0) * GB),
            expires_at=expires_at,
            note=f"Sell order {oid} · {plan.get('name')}",
            protocol=(bundle[0] if bundle else (plan.get("protocol") or m.DEFAULT_PROTOCOL)),
            ip_limit=int(plan.get("ip_limit") or 0),
            all_protocols=bool(plan.get("all_protocols")),
            bundle_protocols=bundle,
        )
        link["telegram_owner_id"] = str(o["chat_id"])
        link["sell_order_id"] = oid
        await m.save_state()
        o.update(status="approved", link_uid=uid, approved_by=by, updated_at=datetime.now().isoformat())
        save_orders(orders)
    await _deliver(o, uid, link)
    try:
        m.log_activity("sell", f"سفارش {oid} تأیید شد ({plan.get('name')})")
    except Exception:
        pass
    return o


async def reject_order(oid: str, reason: str = "", by: str = "panel") -> dict:
    async with _LOCK:
        orders = load_orders()
        o = orders.get(oid)
        if not o:
            raise ValueError("سفارش پیدا نشد")
        if o.get("status") == "approved":
            raise ValueError("سفارش تأییدشده قابل رد نیست")
        o.update(status="rejected", reject_reason=reason[:300], rejected_by=by, updated_at=datetime.now().isoformat())
        save_orders(orders)
    text = "❌ <b>سفارش شما رد شد</b>\n" + (f"دلیل: {_esc(reason)}\n" if reason else "")
    sup = load_settings().get("support_username")
    if sup:
        text += f"پشتیبانی: @{_esc(sup.lstrip('@'))}"
    await _bot()._send(o["chat_id"], text, _customer_menu_kb())
    return o


async def _deliver(o: dict, uid: str, link: dict) -> None:
    m = _m()
    host = m.get_host()
    sub = f"https://{host}/sub/{uid}"
    info = f"https://{host}/api/public/sub/{uid}"
    plan = o["plan"]
    text = (
        "✅ <b>پرداخت تأیید شد، سرویس شما آماده است!</b>\n"
        f"{'─' * 18}\n"
        f"📦 پلن: <b>{_esc(plan.get('name'))}</b>\n"
        f"🔗 لینک اشتراک (در اپ کپی کنید):\n<code>{sub}</code>\n\n"
        "📱 این لینک را در v2rayNG / Hiddify / Streisand به‌عنوان Subscription اضافه کنید."
    )
    kb = {"inline_keyboard": [
        [{"text": "📦 سرویس‌های من", "callback_data": "list:0"}],
        [{"text": "🛒 خرید دوباره", "callback_data": "shop"}],
    ]}
    await _bot()._send(o["chat_id"], text, kb)


# ---------------------------------------------------------------- bot UI

def _customer_menu_kb():
    return {"inline_keyboard": [
        [{"text": "🛒 خرید اشتراک", "callback_data": "shop"}],
        [{"text": "📦 سرویس‌های من", "callback_data": "list:0"}, {"text": "🧾 سفارش‌های من", "callback_data": "myorders"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu"}],
    ]}


def _shop_text() -> str:
    s = load_settings()
    return _esc(s.get("welcome_text") or DEFAULT_SETTINGS["welcome_text"])


def _shop_kb():
    rows = [[{"text": _plan_line(p), "callback_data": f"buy:{p['id']}"}] for p in active_plans()[:20]]
    rows.append([{"text": "🧾 سفارش‌های من", "callback_data": "myorders"}])
    rows.append([{"text": "🏠 منوی اصلی", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


def _payment_text(o: dict) -> str:
    s = load_settings()
    p = o["plan"]
    lines = [
        "🧾 <b>فاکتور سفارش</b>",
        "─" * 18,
        f"📦 {_esc(_plan_line(p))}",
        f"🆔 کد سفارش: <code>{o['id']}</code>",
        "",
        f"💳 مبلغ قابل پرداخت: <b>{_price(p.get('price'))}</b>",
    ]
    cards = [c.strip() for c in re.split(r"[,\n،]+", str(s.get("card_number") or "")) if c.strip()]
    if cards:
        lines.append(f"شماره کارت: <code>{_esc(random.choice(cards))}</code>")
    if s.get("card_holder"):
        lines.append(f"به نام: {_esc(s['card_holder'])}" + (f" ({_esc(s['bank_name'])})" if s.get("bank_name") else ""))
    if s.get("payment_url"):
        lines.append(f"لینک پرداخت: {_esc(s['payment_url'])}")
    lines += ["", f"📸 {_esc(s.get('payment_note'))}"]
    return "\n".join(lines)


_STATUS_FA = {
    "awaiting_receipt": "⏳ منتظر رسید",
    "pending_review": "🔎 در حال بررسی",
    "approved": "✅ تأیید شده",
    "rejected": "❌ رد شده",
    "cancelled": "🚫 لغو شده",
}


def _my_orders_text(chat_id: int) -> str:
    mine = [o for o in load_orders().values() if str(o.get("chat_id")) == str(chat_id)]
    mine.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    if not mine:
        return "🧾 هنوز سفارشی ثبت نکرده‌اید."
    out = ["🧾 <b>سفارش‌های من</b>", "─" * 18]
    for o in mine[:10]:
        out.append(f"<code>{o['id']}</code> · {_esc(o['plan'].get('name'))} · {_STATUS_FA.get(o['status'], o['status'])}")
    return "\n".join(out)


def _admin_review_kb(oid: str):
    return {"inline_keyboard": [[
        {"text": "✅ تأیید و ارسال", "callback_data": f"ord:ok:{oid}"},
        {"text": "❌ رد", "callback_data": f"ord:no:{oid}"},
    ]]}


def _admin_caption(o: dict) -> str:
    who = f"@{o['username']}" if o.get("username") else (o.get("name") or "—")
    cap = (
        "🧾 <b>رسید جدید</b>\n"
        f"👤 {_esc(who)} · <code>{o['chat_id']}</code>\n"
        f"📦 {_esc(_plan_line(o['plan']))}\n"
        f"🆔 <code>{o['id']}</code>"
    )
    if o.get("receipt_text"):
        cap += f"\n📝 {_esc(o['receipt_text'][:500])}"
    return cap


async def _notify_admins(o: dict) -> None:
    bot = _bot()
    for aid in list(bot.ADMIN_IDS):
        try:
            if o.get("receipt_file_id"):
                await bot._call("sendPhoto", chat_id=aid, photo=o["receipt_file_id"], caption=_admin_caption(o),
                                parse_mode="HTML", reply_markup=_admin_review_kb(o["id"]))
            else:
                await bot._send(aid, _admin_caption(o), _admin_review_kb(o["id"]))
        except Exception as exc:  # pragma: no cover - network
            bot.logger.warning("sell notify admin %s: %s", aid, exc)


async def handle_message(msg: dict) -> bool:
    """Return True if the message was consumed by the shop (receipt upload)."""
    if not is_enabled():
        return False
    chat_id = (msg.get("chat") or {}).get("id")
    if chat_id is None:
        return False
    photos = msg.get("photo") or []
    doc = msg.get("document") or {}
    text = (msg.get("text") or msg.get("caption") or "").strip()
    if text.startswith("/shop"):
        await _bot()._send(chat_id, _shop_text(), _shop_kb())
        return True
    o = _open_order_for(chat_id)
    if not o:
        return False
    if text.startswith("/"):
        return False
    file_id = ""
    if photos:
        file_id = photos[-1].get("file_id", "")
    elif str(doc.get("mime_type", "")).startswith("image/"):
        file_id = doc.get("file_id", "")
    if not file_id and len(text) < 4:
        await _bot()._send(chat_id, "📸 لطفاً عکس رسید یا کد پیگیری واریز را بفرستید.")
        return True
    async with _LOCK:
        orders = load_orders()
        cur = orders.get(o["id"])
        if not cur:
            return False
        cur.update(status="pending_review", receipt_file_id=file_id, receipt_text=text[:500],
                   updated_at=datetime.now().isoformat())
        save_orders(orders)
    await _bot()._send(chat_id, f"✅ رسید شما ثبت شد.\nکد سفارش: <code>{cur['id']}</code>\nبعد از بررسی، سرویس خودکار برایتان ارسال می‌شود.", _customer_menu_kb())
    await _notify_admins(cur)
    return True


SHOP_CALLBACKS = ("shop", "myorders", "buy:", "ord:", "cancelord:")


def owns_callback(data: str) -> bool:
    return any(data == c or (c.endswith(":") and data.startswith(c)) for c in SHOP_CALLBACKS)


async def handle_callback(cb: dict) -> None:
    bot = _bot()
    cb_id = cb.get("id")
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    mid = msg.get("message_id")
    user = cb.get("from") or {}

    if data.startswith("ord:"):
        if not bot._is_admin(chat_id):
            await bot._answer_cb(cb_id, "⛔️ مخصوص ادمین", alert=True)
            return
        _, action, oid = (data.split(":", 2) + ["", ""])[:3]
        try:
            if action == "ok":
                o = await approve_order(oid, by=f"tg:{chat_id}")
                await bot._answer_cb(cb_id, "✅ تأیید و ارسال شد")
                note = f"\n\n✅ تأیید شد · لینک: <code>{o.get('link_uid', '')[:8]}…</code>"
            else:
                await reject_order(oid, by=f"tg:{chat_id}")
                await bot._answer_cb(cb_id, "❌ رد شد")
                note = "\n\n❌ رد شد"
            o = load_orders().get(oid) or {}
            if msg.get("photo"):
                await bot._call("editMessageCaption", chat_id=chat_id, message_id=mid,
                                caption=_admin_caption(o) + note, parse_mode="HTML")
            else:
                await bot._edit(chat_id, mid, _admin_caption(o) + note)
        except Exception as exc:
            await bot._answer_cb(cb_id, f"خطا: {exc}", alert=True)
        return

    if not is_enabled():
        await bot._answer_cb(cb_id, "فروشگاه فعلاً غیرفعال است", alert=True)
        return
    await bot._answer_cb(cb_id)

    if data == "shop":
        if not active_plans():
            await bot._edit(chat_id, mid, "فعلاً پلنی برای فروش تعریف نشده است.", _customer_menu_kb())
            return
        await bot._edit(chat_id, mid, _shop_text(), _shop_kb())
        return
    if data == "myorders":
        await bot._edit(chat_id, mid, _my_orders_text(chat_id), _customer_menu_kb())
        return
    if data.startswith("buy:"):
        plan = find_plan(data[4:])
        if not plan or not plan.get("enabled", True):
            await bot._edit(chat_id, mid, "این پلن دیگر موجود نیست.", _shop_kb())
            return
        o = await create_order(chat_id, user, plan)
        if int(plan.get("price") or 0) == 0:
            # Free/trial plan: deliver immediately, one per customer.
            already = [x for x in load_orders().values() if str(x.get("chat_id")) == str(chat_id)
                       and x.get("status") == "approved" and x["plan"].get("id") == plan["id"]]
            if already:
                await reject_order(o["id"], reason="هر کاربر فقط یک‌بار می‌تواند پلن رایگان بگیرد", by="auto")
                return
            await approve_order(o["id"], by="auto-free")
            return
        await bot._edit(chat_id, mid, _payment_text(o), {"inline_keyboard": [
            [{"text": "🚫 لغو سفارش", "callback_data": f"cancelord:{o['id']}"}],
            [{"text": "🛒 بازگشت به پلن‌ها", "callback_data": "shop"}],
        ]})
        return
    if data.startswith("cancelord:"):
        oid = data.split(":", 1)[1]
        async with _LOCK:
            orders = load_orders()
            o = orders.get(oid)
            if o and str(o.get("chat_id")) == str(chat_id) and o.get("status") == "awaiting_receipt":
                o.update(status="cancelled", updated_at=datetime.now().isoformat())
                save_orders(orders)
        await bot._edit(chat_id, mid, "🚫 سفارش لغو شد.", _customer_menu_kb())


# ---------------------------------------------------------------- expiry / usage warnings

async def _expiry_loop():
    while True:
        try:
            await asyncio.sleep(1800)
            if not is_enabled():
                continue
            m = _m()
            s = load_settings()
            warn_days = max(0, int(s.get("expiry_warn_days") or 0))
            warn_pct = max(0, min(100, int(s.get("usage_warn_percent") or 0)))
            changed = False
            for uid, link in list(m.LINKS.items()):
                owner = link.get("telegram_owner_id")
                if not owner or not link.get("sell_order_id"):
                    continue
                msgs = []
                exp = link.get("expires_at")
                if warn_days and exp and not link.get("_sell_warned_exp"):
                    try:
                        left = datetime.fromisoformat(str(exp)) - datetime.now()
                        if timedelta(0) < left <= timedelta(days=warn_days):
                            msgs.append(f"⏰ سرویس <b>{_esc(link.get('label'))}</b> کمتر از {warn_days} روز دیگر منقضی می‌شود.")
                            link["_sell_warned_exp"] = True
                    except Exception:
                        pass
                lim = int(link.get("limit_bytes") or 0)
                if warn_pct and lim and not link.get("_sell_warned_use"):
                    if int(link.get("used_bytes") or 0) * 100 >= lim * warn_pct:
                        msgs.append(f"📊 بیش از {warn_pct}٪ حجم سرویس <b>{_esc(link.get('label'))}</b> مصرف شده است.")
                        link["_sell_warned_use"] = True
                if msgs:
                    changed = True
                    await _bot()._send(int(owner), "\n".join(msgs) + "\nبرای تمدید از دکمه زیر استفاده کنید.",
                                       {"inline_keyboard": [[{"text": "🛒 تمدید / خرید", "callback_data": "shop"}]]})
            if changed:
                await m.save_state()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover
            try:
                _m().logger.warning("sell expiry loop: %s", exc)
            except Exception:
                pass


def start_background() -> None:
    global _expiry_task
    if _expiry_task is None or _expiry_task.done():
        try:
            _expiry_task = asyncio.get_running_loop().create_task(_expiry_loop())
        except RuntimeError:
            pass


# ---------------------------------------------------------------- panel API

def build_router(require_perm) -> APIRouter:
    r = APIRouter(prefix="/api/sell", tags=["sell"])
    dep = Depends(require_perm("telegram"))

    @r.get("/settings")
    async def get_settings(_=dep):
        s = load_settings()
        bot = _bot()
        return {**s, "bot_ready": bool(bot.API_BASE), "admin_count": len(bot.ADMIN_IDS)}

    @r.post("/settings")
    async def set_settings(request: Request, _=dep):
        body = await request.json()
        s = load_settings()
        for k in ("card_number", "card_holder", "bank_name", "payment_url", "payment_note",
                  "support_username", "welcome_text"):
            if k in body:
                s[k] = str(body.get(k) or "").strip()[:1000]
        for k in ("enabled", "hide_free_create"):
            if k in body:
                s[k] = bool(body.get(k))
        for k, hi in (("expiry_warn_days", 30), ("usage_warn_percent", 100)):
            if k in body:
                try:
                    s[k] = max(0, min(hi, int(body.get(k) or 0)))
                except ValueError:
                    pass
        save_settings(s)
        if s["enabled"]:
            start_background()
        return {"ok": True, "settings": s}

    @r.get("/plans")
    async def list_plans(_=dep):
        return {"plans": load_settings()["plans"]}

    @r.post("/plans")
    async def add_plan(request: Request, _=dep):
        try:
            plan = normalize_plan(await request.json())
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        s = load_settings()
        if len(s["plans"]) >= 50:
            raise HTTPException(400, "حداکثر ۵۰ پلن")
        s["plans"].append(plan)
        save_settings(s)
        return {"ok": True, "plan": plan}

    @r.put("/plans/{pid}")
    async def edit_plan(pid: str, request: Request, _=dep):
        s = load_settings()
        for i, p in enumerate(s["plans"]):
            if p.get("id") == pid:
                try:
                    s["plans"][i] = normalize_plan(await request.json(), p)
                except ValueError as exc:
                    raise HTTPException(400, str(exc))
                save_settings(s)
                return {"ok": True, "plan": s["plans"][i]}
        raise HTTPException(404, "پلن پیدا نشد")

    @r.delete("/plans/{pid}")
    async def del_plan(pid: str, _=dep):
        s = load_settings()
        before = len(s["plans"])
        s["plans"] = [p for p in s["plans"] if p.get("id") != pid]
        if len(s["plans"]) == before:
            raise HTTPException(404, "پلن پیدا نشد")
        save_settings(s)
        return {"ok": True}

    @r.get("/orders")
    async def list_orders(status: str = "", _=dep):
        items = sorted(load_orders().values(), key=lambda x: x.get("created_at", ""), reverse=True)
        if status:
            items = [o for o in items if o.get("status") == status]
        approved = [o for o in load_orders().values() if o.get("status") == "approved"]
        revenue = sum(int(o["plan"].get("price") or 0) for o in approved)
        return {
            "orders": items[:300],
            "summary": {
                "pending": sum(1 for o in load_orders().values() if o.get("status") == "pending_review"),
                "approved": len(approved),
                "revenue": revenue,
            },
        }

    @r.post("/orders/{oid}/approve")
    async def approve(oid: str, _=dep):
        try:
            return {"ok": True, "order": await approve_order(oid)}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @r.post("/orders/{oid}/reject")
    async def reject(oid: str, request: Request, _=dep):
        try:
            body = await request.json()
        except Exception:
            body = {}
        try:
            return {"ok": True, "order": await reject_order(oid, str(body.get("reason") or ""))}
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @r.get("/orders/{oid}/receipt")
    async def receipt(oid: str, _=dep):
        o = load_orders().get(oid)
        if not o or not o.get("receipt_file_id"):
            raise HTTPException(404, "رسید تصویری ندارد")
        bot = _bot()
        info = await bot._call("getFile", file_id=o["receipt_file_id"])
        path = ((info or {}).get("result") or {}).get("file_path")
        if not path or not bot.BOT_TOKEN:
            raise HTTPException(502, "دریافت رسید از تلگرام ناموفق بود")
        import httpx
        async with httpx.AsyncClient(timeout=30) as c:
            resp = await c.get(f"https://api.telegram.org/file/bot{bot.BOT_TOKEN}/{path}")
        if resp.status_code != 200:
            raise HTTPException(502, "دریافت رسید از تلگرام ناموفق بود")
        return Response(resp.content, media_type=resp.headers.get("content-type", "image/jpeg"),
                        headers={"Cache-Control": "private, max-age=300"})

    return r
