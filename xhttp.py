# xhttp_siz10.py

import asyncio
import secrets
import socket
import time
import uuid as uuidlib
from datetime import datetime

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import StreamingResponse
from starlette.requests import ClientDisconnect

from main import (
    LINKS,
    LINKS_LOCK,
    stats,
    hourly_traffic,
    connections,
    error_logs,
    logger,
    is_link_allowed,
    is_ip_allowed,
    save_state,
)
from onex.core.vless_relay import parse_vless_header, check_and_use
from onex.core.traffic_limiter import throttle

router = APIRouter()

XHTTP_BUF = 512 * 1024
DOWNLINK_QUEUE_MAX = 32
SESSION_IDLE_TIMEOUT = 30
REAPER_INTERVAL = 10
TCP_CONNECT_TIMEOUT = 10.0
SOCK_BUF_SIZE = 2 * 1024 * 1024
TCP_USER_TIMEOUT_MS = 20_000
FLOW_MIN_HW = 256 * 1024
FLOW_MAX_HW = 8 * 1024 * 1024
FLOW_START_HW = 2 * 1024 * 1024
FLOW_FAST_DRAIN_MS = 2.0
FLOW_SLOW_DRAIN_MS = 25.0  
QUOTA_MIN_BATCH = 32 * 1024
QUOTA_MAX_BATCH = 1 * 1024 * 1024
QUOTA_START_BATCH = 64 * 1024
QUOTA_CHECK_INTERVAL = 0.2 

PACKET_UP_HIGH_WATER = 2 * 1024 * 1024  

xhttp_sessions: dict = {}
XHTTP_LOCK = asyncio.Lock()

FINGERPRINTS = {
    "chrome": {
        "content-type": "application/grpc",
        "cache-control": "no-cache, no-store",
        "x-accel-buffering": "no",
        "server": "cloudflare",
    },
    "plain": {
        "content-type": "application/octet-stream",
        "cache-control": "no-store",
        "x-accel-buffering": "no",
    },
}
DEFAULT_FINGERPRINT = "chrome"


def _resp_headers(fp: str, *, stream_one: bool = False) -> dict:
    headers = dict(FINGERPRINTS.get(fp, FINGERPRINTS[DEFAULT_FINGERPRINT]))
    # Xray stream-one keeps the HTTP response open as the downstream tunnel.
    # Its native XHTTP server uses an SSE-compatible response content type so
    # HTTP/1.1 intermediaries flush the body instead of buffering it.
    if stream_one:
        headers["content-type"] = "text/event-stream"
    return headers


def _tune_socket(writer: asyncio.StreamWriter):
    sock = writer.transport.get_extra_info("socket")
    if not sock:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUF_SIZE)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUF_SIZE)
        # Linux latency/cleanup knobs.  Keep them optional for non-Linux hosts.
        quickack = getattr(socket, "TCP_QUICKACK", None)
        if quickack is not None:
            sock.setsockopt(socket.IPPROTO_TCP, quickack, 1)
        user_timeout = getattr(socket, "TCP_USER_TIMEOUT", None)
        if user_timeout is not None:
            sock.setsockopt(socket.IPPROTO_TCP, user_timeout, TCP_USER_TIMEOUT_MS)
    except OSError:
        pass


class _QuotaGate:
    __slots__ = ("uuid", "pending", "last_check", "ok", "batch_bytes", "rate_ewma")

    def __init__(self, uuid: str):
        self.uuid = uuid
        self.pending = 0
        self.last_check = time.monotonic()
        self.ok = True
        self.batch_bytes = QUOTA_START_BATCH
        self.rate_ewma = 0.0

    async def add(self, nbytes: int) -> bool:
        if not self.ok:
            return False
        self.pending += nbytes
        now = time.monotonic()
        elapsed = now - self.last_check
        if self.pending >= self.batch_bytes or elapsed >= QUOTA_CHECK_INTERVAL:
            flush, self.pending = self.pending, 0
            if elapsed > 0:
                inst_rate = flush / elapsed
                self.rate_ewma = inst_rate if self.rate_ewma == 0 else (0.7 * self.rate_ewma + 0.3 * inst_rate)
                target = int(self.rate_ewma * QUOTA_CHECK_INTERVAL)
                self.batch_bytes = max(QUOTA_MIN_BATCH, min(QUOTA_MAX_BATCH, target or QUOTA_MIN_BATCH))
            self.last_check = now
            self.ok = await check_and_use(self.uuid, flush)
            return self.ok
        return True

    async def flush(self) -> bool:
        if self.pending:
            flush, self.pending = self.pending, 0
            self.ok = self.ok and await check_and_use(self.uuid, flush)
        return self.ok


class _AdaptiveFlow:
    __slots__ = ("high_water", "last_drain_ms")

    def __init__(self):
        self.high_water = FLOW_START_HW
        self.last_drain_ms = 0.0

    def should_drain(self, buf_size: int) -> bool:
        return buf_size > self.high_water

    async def drain(self, writer: asyncio.StreamWriter):
        t0 = time.monotonic()
        await writer.drain()
        elapsed_ms = (time.monotonic() - t0) * 1000
        self.last_drain_ms = elapsed_ms
        if elapsed_ms < FLOW_FAST_DRAIN_MS:
            self.high_water = min(FLOW_MAX_HW, int(self.high_water * 1.5) + 65536)
        elif elapsed_ms > FLOW_SLOW_DRAIN_MS:
            self.high_water = max(FLOW_MIN_HW, self.high_water // 2)


def _req_client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


def _vless_header_complete(buf: bytes) -> bool:
    """Return True only when the complete VLESS request header is buffered."""
    if len(buf) < 19:  # version + UUID + addons length + command
        return False
    addon_len = buf[17]
    pos = 18 + addon_len
    if len(buf) < pos + 4:  # command + port + address type
        return False
    addr_type = buf[pos + 3]
    if addr_type == 1:
        need = pos + 3 + 1 + 4
    elif addr_type == 2:
        if len(buf) < pos + 5:
            return False
        need = pos + 3 + 1 + 1 + buf[pos + 4]
    elif addr_type == 3:
        need = pos + 3 + 1 + 16
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return len(buf) >= need


async def _open_tcp_from_header(first_chunk: bytes):
    command, address, port, payload = await parse_vless_header(first_chunk)
    # ONEX XHTTP currently exposes a TCP VLESS relay.  Reject UDP/Mux instead
    # of treating their bytes as a TCP destination, which otherwise produces
    # confusing client-side latency failures.
    if command != 1:
        raise ValueError(f"unsupported VLESS command: {command}")
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port), timeout=TCP_CONNECT_TIMEOUT
    )
    _tune_socket(writer)
    if payload:
        writer.write(payload)
        await writer.drain()
    return reader, writer, address, port


async def _check_link(uuid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        raise HTTPException(status_code=403, detail="not authorized")


async def _get_or_create_session(uuid: str, mode: str, session_id: str, ip: str = "نامشخص") -> dict:
    async with XHTTP_LOCK:
        sess = xhttp_sessions.get(session_id)
        if sess is not None:
            sess["last_seen"] = time.time()
            return sess

        async with LINKS_LOCK:
            link = LINKS.get(uuid)
        if not is_ip_allowed(link, uuid, ip):
            logger.warning(f"🚫 XHTTP[{mode}] rejected uuid={uuid[:8]} ip={ip} (ip limit reached)")
            raise HTTPException(status_code=403, detail="ip limit reached")

        conn_id = secrets.token_urlsafe(6)
        connections[conn_id] = {
            "uuid": uuid,
            "ip": ip,
            "connected_at": datetime.now().isoformat(),
            "bytes": 0,
            "transport": f"xhttp-{mode}",
        }
        sess = {
            "uuid": uuid, "mode": mode, "writer": None,
            "downlink_task": None, "uplink_task": None,
            "down_q": asyncio.Queue(maxsize=DOWNLINK_QUEUE_MAX),
            "last_seen": time.time(),
            "conn_id": conn_id, "tcp_open": False, "closed": False,
            "seq_buf": {}, "next_seq": 0, "downlink_header_sent": False,
            "gate": None,  # لازی ساخته می‌شه: _QuotaGate تطبیقی مخصوص stream-up
            "flow": None,  # لازی ساخته می‌شه: _AdaptiveFlow مخصوص stream-up
        }
        xhttp_sessions[session_id] = sess
        logger.info(f"new XHTTP[{mode}] session [{session_id[:8]}] uuid={uuid[:8]} ip={ip}")
        return sess


async def _teardown(session_id: str):
    async with XHTTP_LOCK:
        sess = xhttp_sessions.pop(session_id, None)
    if not sess:
        return
    sess["closed"] = True
    current_task = asyncio.current_task()
    for t in ("uplink_task", "downlink_task"):
        task = sess.get(t)
        if task and task is not current_task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    writer = sess.get("writer")
    if writer:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    connections.pop(sess.get("conn_id"), None)
    dq = sess.get("down_q")
    if dq:
        try:
            dq.put_nowait(None)
        except Exception:
            pass
    logger.info(f"closed XHTTP[{sess.get('mode')}] [{session_id[:8]}] total={len(xhttp_sessions)}")


async def _reaper():
    while True:
        await asyncio.sleep(REAPER_INTERVAL)
        now = time.time()
        async with XHTTP_LOCK:
            stale = [sid for sid, s in xhttp_sessions.items()
                     if now - s["last_seen"] > SESSION_IDLE_TIMEOUT and not s.get("tcp_open")]
        for sid in stale:
            await _teardown(sid)


_reaper_started = False


def ensure_reaper():
    global _reaper_started
    if not _reaper_started:
        asyncio.create_task(_reaper())
        _reaper_started = True


async def _pump_tcp_to_queue(session_id: str, uuid: str, reader: asyncio.StreamReader, down_q: asyncio.Queue):
    gate = _QuotaGate(uuid)
    stream_one = False
    async with XHTTP_LOCK:
        sess0 = xhttp_sessions.get(session_id)
        stream_one = bool(sess0 and sess0.get("mode") == "stream-one")
    try:
        while True:
            data = await reader.read(XHTTP_BUF)
            if not data:
                break
            if not await gate.add(len(data)):
                break
            await throttle(uuid, len(data))
            async with XHTTP_LOCK:
                sess = xhttp_sessions.get(session_id)
            if sess:
                c = connections.get(sess["conn_id"])
                if c:
                    c["bytes"] += len(data)
            # VLESS response header is emitted immediately by the Stream-One
            # HTTP response generator.  Do not prepend it again to target data.
            # Packet/stream-up still use the legacy first-chunk prefix here.
            if stream_one:
                payload = data
            else:
                async with XHTTP_LOCK:
                    sess2 = xhttp_sessions.get(session_id)
                    first_sent = bool(sess2 and sess2.get("downlink_header_sent"))
                    if sess2 and not first_sent:
                        sess2["downlink_header_sent"] = True
                payload = data if first_sent else b"\x00\x00" + data
            await down_q.put(payload)
    except (asyncio.CancelledError, Exception):
        pass
    finally:
        await gate.flush()
        await _teardown(session_id)


async def _open_tcp_for_session(session_id: str, uuid: str, sess: dict, first_chunk: bytes):
    reader, writer, address, port = await _open_tcp_from_header(first_chunk)
    logger.info(f"connect XHTTP[{sess['mode']}] [{session_id[:8]}] -> {address}:{port}")
    sess["writer"] = writer
    sess["tcp_open"] = True
    sess["downlink_task"] = asyncio.create_task(
        _pump_tcp_to_queue(session_id, uuid, reader, sess["down_q"])
    )
    asyncio.create_task(save_state())


def _downstream_gen(sess: dict, *, stream_one: bool = False):
    async def gen():
        try:
            if stream_one:
                # Xray VLESS clients decode the response header before they can
                # report the connection as established.  The official XHTTP
                # server flushes HTTP 200 and the VLESS response header before
                # dispatching the destination, so do the same.
                yield VLESS_RESPONSE_HEADER
            while True:
                chunk = await sess["down_q"].get()
                if chunk is None:
                    break
                sess["last_seen"] = time.time()
                yield chunk
        finally:
            pass
    return gen()


@router.get("/xhttp-siz10/{mode}/{uuid}/{session_id}")
async def xhttp_downlink(mode: str, uuid: str, session_id: str, request: Request):
    ensure_reaper()
    if mode not in ("packet-up", "stream-up", "stream-one"):
        raise HTTPException(status_code=404, detail="unknown mode")
    await _check_link(uuid)
    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    sess = await _get_or_create_session(uuid, mode, session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    headers = _resp_headers(fp)
    return StreamingResponse(_downstream_gen(sess), headers=headers, media_type=headers["content-type"])


@router.post("/xhttp-siz10/packet-up/{uuid}/{session_id}/{seq}")
async def packet_up_upload(uuid: str, session_id: str, seq: int, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "packet-up", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    sess["last_seen"] = time.time()
    body = await request.body()
    if not body:
        return {"ok": True}

    if not await check_and_use(uuid, len(body)):
        await _teardown(session_id)
        raise HTTPException(status_code=403, detail="quota/disabled/unknown")
    await throttle(uuid, len(body))

    stats["total_requests"] += 1
    connections[sess["conn_id"]]["bytes"] += len(body)

    try:
        if sess["writer"] is None:
            if seq != 0:
                sess["seq_buf"][seq] = body
                return {"ok": True, "buffered": True}
            await _open_tcp_for_session(session_id, uuid, sess, body)
            # هر پکت بافرشده‌ای که حالا نوبتش رسیده رو هم بفرست
            nxt = 1
            while nxt in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(nxt)
                sess["writer"].write(pending)
                nxt += 1
            sess["next_seq"] = nxt
            return {"ok": True, "connected": True}

        if seq == sess["next_seq"]:
            sess["writer"].write(body)
            sess["next_seq"] += 1
            while sess["next_seq"] in sess["seq_buf"]:
                pending = sess["seq_buf"].pop(sess["next_seq"])
                sess["writer"].write(pending)
                sess["next_seq"] += 1
        else:
            sess["seq_buf"][seq] = body

        if sess["writer"].transport.get_write_buffer_size() > PACKET_UP_HIGH_WATER:
            await sess["writer"].drain()
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="write failed")

    return {"ok": True}


# ══════════════════════════════ STREAM-UP (یک POST پیوسته) ══════════════════════════════
# موتور تطبیقی: _QuotaGate (batch کوتا بر اساس نرخ واقعی) + _AdaptiveFlow (AIMD روی
# high-water درین) + کش رفرنس‌ها داخل لوپ. هیچ داده‌ای بافر/coalesce نمی‌شه —
# هر بایت فوری write() می‌شه، فقط «کِی صبر کنیم برای drain» تطبیقیه.
@router.post("/xhttp-siz10/stream-up/{uuid}/{session_id}")
async def stream_up_upload(uuid: str, session_id: str, request: Request):
    ensure_reaper()
    sess = await _get_or_create_session(uuid, "stream-up", session_id, _req_client_ip(request))
    if sess.get("closed"):
        raise HTTPException(status_code=404, detail="session closed")

    gate = sess.get("gate")
    if gate is None:
        gate = _QuotaGate(uuid)
        sess["gate"] = gate

    flow = sess.get("flow")
    if flow is None:
        flow = _AdaptiveFlow()
        sess["flow"] = flow

    conn = connections[sess["conn_id"]]   # یک بار لوک‌آپ، نه هر چانک
    writer = sess["writer"]               # ممکنه هنوز None باشه

    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            sess["last_seen"] = time.time()

            if not await gate.add(len(chunk)):
                raise HTTPException(status_code=403, detail="quota/disabled/unknown")
            await throttle(uuid, len(chunk))

            stats["total_requests"] += 1
            conn["bytes"] += len(chunk)

            if writer is None:
                await _open_tcp_for_session(session_id, uuid, sess, chunk)
                writer = sess["writer"]
                continue

            writer.write(chunk)
            if flow.should_drain(writer.transport.get_write_buffer_size()):
                await flow.drain(writer)
    except HTTPException:
        await gate.flush()
        await _teardown(session_id)
        raise
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await gate.flush()
        await _teardown(session_id)
        raise HTTPException(status_code=502, detail="stream error")

    await gate.flush()
    return {"ok": True}

# ══════════════════════════════ STREAM-ONE ══════════════════════════════
# Xray stream-one is ONE long-lived HTTP request/response pair. There is no
# session id and no UUID in the URL; the VLESS UUID is inside bytes 1..16 of
# the first request body. The response body is the downlink of the same HTTP
# stream.
STREAM_ONE_MAX_HEADER = 64 * 1024
VLESS_RESPONSE_HEADER = b"\x00\x00"


def _stream_one_extract_uuid(buf: bytes) -> str:
    if len(buf) < 17:
        raise ValueError("VLESS header too small")
    if buf[0] != 0:
        raise ValueError("unsupported VLESS version")
    try:
        return str(uuidlib.UUID(bytes=bytes(buf[1:17])))
    except (ValueError, AttributeError) as exc:
        raise ValueError("invalid VLESS UUID") from exc


async def _stream_one_read_first(iterator):
    """Read only enough of the first HTTP DATA chunk to authenticate UUID.

    The response must not wait for the complete VLESS destination header.  Xray
    opens/flushed the HTTP response first; the rest of the VLESS request can
    continue arriving concurrently.
    """
    while True:
        try:
            chunk = await iterator.__anext__()
        except StopAsyncIteration:
            raise ValueError("empty stream-one request")
        if chunk:
            if len(chunk) < 17:
                # Keep collecting only until UUID is available. This is still
                # much smaller/earlier than waiting for the complete address.
                buf = bytearray(chunk)
                while len(buf) < 17:
                    try:
                        nxt = await iterator.__anext__()
                    except StopAsyncIteration:
                        raise ValueError("incomplete VLESS UUID")
                    if nxt:
                        buf.extend(nxt)
                return iterator, bytes(buf)
            return iterator, bytes(chunk)


async def _stream_one_uplink_iter(session_id: str, uuid: str, sess: dict, iterator, first_chunk: bytes):
    gate = sess.get("gate") or _QuotaGate(uuid)
    sess["gate"] = gate
    flow = sess.get("flow") or _AdaptiveFlow()
    sess["flow"] = flow
    conn = connections.get(sess["conn_id"])
    writer = None
    header_buf = bytearray()
    header_done = False

    async def write_payload(payload: bytes):
        nonlocal writer
        if not payload:
            return
        sess["last_seen"] = time.time()
        if not await gate.add(len(payload)):
            raise HTTPException(status_code=403, detail="quota/disabled/unknown")
        await throttle(uuid, len(payload))
        stats["total_requests"] += 1
        if conn:
            conn["bytes"] += len(payload)
        if writer is None:
            raise RuntimeError("VLESS destination is not open")
        if writer.is_closing():
            raise ConnectionError("transport closing")
        writer.write(payload)
        if flow.should_drain(writer.transport.get_write_buffer_size()):
            await flow.drain(writer)

    try:
        # Parse the VLESS request header incrementally. Do not block HTTP
        # response creation on destination/address bytes.
        chunks = [first_chunk]
        while not header_done:
            chunk = chunks.pop(0) if chunks else await iterator.__anext__()
            if not chunk:
                continue
            header_buf.extend(chunk)
            if len(header_buf) > STREAM_ONE_MAX_HEADER:
                raise ValueError("VLESS header is too large")
            if not _vless_header_complete(header_buf):
                continue
            command, address, port, payload = await parse_vless_header(bytes(header_buf))
            if command != 1:
                raise ValueError(f"unsupported VLESS command: {command}")
            reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=TCP_CONNECT_TIMEOUT)
            _tune_socket(writer)
            sess["writer"] = writer
            sess["tcp_open"] = True
            logger.info(f"connect XHTTP[stream-one] [{session_id[:8]}] -> {address}:{port}")
            sess["downlink_task"] = asyncio.create_task(_pump_tcp_to_queue(session_id, uuid, reader, sess["down_q"]))
            header_done = True
            if payload:
                await write_payload(payload)

        while True:
            try:
                chunk = await iterator.__anext__()
            except StopAsyncIteration:
                break
            await write_payload(chunk)
        await gate.flush()
    except ClientDisconnect:
        await gate.flush()
    except HTTPException:
        await gate.flush()
        raise
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        await gate.flush()
    finally:
        await _teardown(session_id)


def _stream_one_response(request: Request):
    """Build the Stream-One response as one full-duplex HTTP tunnel.

    Xray sends the HTTP response headers before it waits for the request body.
    This ordering is important because the client may wait for the response
    before continuing to upload the VLESS stream.
    """
    async def gen():
        session_id = None
        try:
            # Flush the VLESS response header immediately. Do not wait for the
            # request body before producing the HTTP response.
            yield VLESS_RESPONSE_HEADER

            iterator = request.stream().__aiter__()
            iterator, first_chunk = await _stream_one_read_first(iterator)
            uuid = _stream_one_extract_uuid(first_chunk)
            await _check_link(uuid)
            session_id = "one-" + secrets.token_urlsafe(18)
            sess = await _get_or_create_session(
                uuid, "stream-one", session_id, _req_client_ip(request)
            )
            if sess.get("closed"):
                return

            sess["uplink_task"] = asyncio.create_task(
                _stream_one_uplink_iter(session_id, uuid, sess, iterator, first_chunk)
            )

            while True:
                chunk = await sess["down_q"].get()
                if chunk is None:
                    break
                sess["last_seen"] = time.time()
                yield chunk
        except (ClientDisconnect, asyncio.CancelledError):
            return
        except Exception as exc:
            error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
            return
        finally:
            if session_id:
                await _teardown(session_id)

    fp = request.query_params.get("fp", DEFAULT_FINGERPRINT)
    headers = _resp_headers(fp, stream_one=True)
    headers["cache-control"] = "no-store"
    headers["x-accel-buffering"] = "no"
    headers["content-type"] = "text/event-stream"
    return StreamingResponse(gen(), headers=headers, media_type="text/event-stream")


@router.post("/xhttp-siz10/stream-one")
@router.post("/xhttp-siz10/stream-one/")
async def stream_one(request: Request):
    ensure_reaper()
    return _stream_one_response(request)


@router.post("/xhttp-siz10/stream-one/{tail:path}")
async def stream_one_custom_path(tail: str, request: Request):
    ensure_reaper()
    return _stream_one_response(request)
