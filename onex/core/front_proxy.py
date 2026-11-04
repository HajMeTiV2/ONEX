"""Transparent TCP front proxy for ONEX (SideRail-style edge).

Owns the public port and dispatches raw connections:
  * /siderail/*        -> uvicorn (siderail_bridge -> local Xray)
  * /httpup/<uuid>     -> pure-python VLESS HTTPUpgrade relay (101 + raw stream)
  * everything else    -> uvicorn (panel, WS relay, XHTTP)

Byte-transparent for anything it does not recognize, so panel behaviour is
identical to running uvicorn directly on the public port.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

MAX_HEAD = 64 * 1024
HEAD_TIMEOUT = 15.0
FIRST_CHUNK_TIMEOUT = 20.0
CONNECT_TIMEOUT = 10.0
BUF = 256 * 1024
QUOTA_BATCH = 64 * 1024


def parse_vless_header(chunk: bytes):
    """Minimal pure-python VLESS request header parser."""
    if len(chunk) < 24:
        raise ValueError("chunk too small")
    pos = 1 + 16
    addon_len = chunk[pos]
    pos += 1 + addon_len
    command = chunk[pos]
    pos += 1
    port = int.from_bytes(chunk[pos:pos + 2], "big")
    pos += 2
    addr_type = chunk[pos]
    pos += 1
    if addr_type == 1:
        address = ".".join(str(b) for b in chunk[pos:pos + 4])
        pos += 4
    elif addr_type == 2:
        dlen = chunk[pos]
        pos += 1
        address = chunk[pos:pos + dlen].decode("utf-8", errors="ignore")
        pos += dlen
    elif addr_type == 3:
        ab = chunk[pos:pos + 16]
        pos += 16
        address = ":".join(f"{ab[i]:02x}{ab[i + 1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown addr type: {addr_type}")
    return command, address, port, chunk[pos:]


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(reader.read(4096), timeout=HEAD_TIMEOUT)
        if not chunk:
            raise ConnectionError("client closed before headers")
        buf.extend(chunk)
        if len(buf) > MAX_HEAD:
            raise ValueError("header too large")
    return bytes(buf)


def _parse_head(head: bytes):
    try:
        text = head.decode("latin-1", errors="replace")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        target = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return target, headers
    except Exception:
        return "/", {}


async def _pipe(a: asyncio.StreamReader, b: asyncio.StreamWriter, counter=None):
    try:
        while True:
            data = await a.read(BUF)
            if not data:
                break
            b.write(data)
            await b.drain()
            if counter:
                await counter(len(data))
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            b.close()
        except Exception:
            pass


async def _relay_to(host: str, port: int, head: bytes, client_r, client_w, counter=None):
    try:
        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except Exception:
        client_w.close()
        return
    up_w.write(head)
    await up_w.drain()
    t1 = asyncio.create_task(_pipe(client_r, up_w))
    t2 = asyncio.create_task(_pipe(up_r, client_w, counter=counter))
    await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    for t in (t1, t2):
        t.cancel()


async def _httpupgrade_relay(path: str, upgrade_value: str, head: bytes, client_r, client_w, ctx):
    """Serve a real xray-style HTTPUpgrade: 101 then raw VLESS stream."""
    parts = path.split("/")
    uuid = parts[2] if len(parts) > 2 else ""
    link = await ctx["get_link"](uuid)
    if not ctx["is_link_allowed"](link):
        client_w.close()
        return
    ip = ctx.get("client_ip", "unknown")
    if not ctx["is_ip_allowed"](link, uuid, ip):
        client_w.close()
        return
    conn_id = ctx["register_connection"](uuid, ip, "vless-httpupgrade")
    up_w = None
    pending = 0
    ok = True

    async def quota(n: int) -> bool:
        nonlocal pending, ok
        if not ok:
            return False
        pending += n
        if pending >= QUOTA_BATCH:
            flush, pending = pending, 0
            ok = await ctx["check_and_use"](uuid, flush)
        ctx["add_conn_bytes"](conn_id, n)
        return ok

    try:
        upgrade = (upgrade_value or "httpupgrade").encode("latin-1", errors="replace")[:64]
        client_w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + upgrade + b"\r\nConnection: Upgrade\r\n\r\n")
        await client_w.drain()

        sep = head.find(b"\r\n\r\n")
        leftover = head[sep + 4:] if sep >= 0 else b""
        if len(leftover) >= 24:
            first = leftover
        else:
            more = await asyncio.wait_for(client_r.read(65536), timeout=FIRST_CHUNK_TIMEOUT)
            first = leftover + more
        if not first:
            raise ConnectionError("empty first chunk")
        command, address, port, payload = parse_vless_header(first)
        if command != 1:
            raise ValueError("unsupported command")
        if ctx["is_blocked"](address, link):
            raise PermissionError("blocked destination")
        if not await quota(len(first)):
            raise PermissionError("quota")
        await ctx["throttle"](uuid, len(first))

        up_r, up_w = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=CONNECT_TIMEOUT)
        if payload:
            up_w.write(payload)
            await up_w.drain()

        async def down(n):
            return await quota(n)

        t1 = asyncio.create_task(_pipe(client_r, up_w, counter=lambda n: quota(n)))
        first_reply = True

        async def downstream():
            nonlocal first_reply
            try:
                while True:
                    data = await up_r.read(BUF)
                    if not data:
                        break
                    if not await quota(len(data)):
                        break
                    await ctx["throttle"](uuid, len(data))
                    if first_reply:
                        data = b"\x00\x00" + data
                        first_reply = False
                    client_w.write(data)
                    await client_w.drain()
            except (ConnectionError, asyncio.CancelledError, OSError):
                pass
            finally:
                try:
                    client_w.close()
                except Exception:
                    pass

        t2 = asyncio.create_task(downstream())
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in (t1, t2):
            t.cancel()
    except (ConnectionError, asyncio.TimeoutError, ValueError, PermissionError):
        try:
            client_w.close()
        except Exception:
            pass
    finally:
        if pending:
            try:
                await ctx["check_and_use"](uuid, pending)
            except Exception:
                pass
        if up_w is not None:
            try:
                up_w.close()
            except Exception:
                pass
        ctx["drop_connection"](conn_id)


def make_handler(ctx):
    internal_host = ctx.get("internal_host", "127.0.0.1")
    internal_port = int(ctx.get("internal_port"))
    vmess_port = int(ctx.get("siderail_vmess_port", 18501))
    xhttp_port = int(ctx.get("siderail_xhttp_port", 18503))
    log = ctx.get("log") or (lambda *a, **k: None)

    async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter):
        try:
            head = await _read_head(client_r)
        except Exception:
            client_w.close()
            return
        target, headers = _parse_head(head)
        path = target.split("?", 1)[0]
        upgrade = (headers.get("upgrade") or "").lower()
        has_ws_key = "sec-websocket-key" in headers
        peer = client_w.get_extra_info("peername")
        ctx["client_ip"] = headers.get("x-forwarded-for", "").split(",")[0].strip() or (peer[0] if peer else "unknown")

        try:
            # /siderail/* is now served per-request by uvicorn (siderail_bridge),
            # so no raw connection is ever pinned to Xray.
            if path.startswith("/httpup/") and upgrade and not has_ws_key:
                await _httpupgrade_relay(path, upgrade, head, client_r, client_w, ctx)
            else:
                await _relay_to(internal_host, internal_port, head, client_r, client_w)
        except Exception as exc:
            log(f"front proxy error: {exc}")
            try:
                client_w.close()
            except Exception:
                pass

    return handle
