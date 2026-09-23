"""Local end-to-end smoke test for ONEX XHTTP Stream-One.

It starts a local TCP echo target, sends a real VLESS TCP request through the
FastAPI XHTTP endpoint, and verifies that the response begins with the VLESS
response header (00 00) followed by the echoed payload.
"""

import asyncio
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx

import main


async def _echo_once(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        data = await reader.read(1024 * 1024)
        writer.write(data)
        await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def main_test() -> None:
    server = await asyncio.start_server(_echo_once, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    uid = str(uuid.uuid4())

    async with main.LINKS_LOCK:
        main.LINKS[uid] = {
            "uuid": uid,
            "active": True,
            "limit_bytes": 0,
            "used_bytes": 0,
            "ip_limit": 0,
            "label": "stream-one-smoke-test",
        }

    # VLESS TCP request header + payload.
    request_body = (
        b"\x00"
        + uuid.UUID(uid).bytes
        + b"\x00"          # addons length
        + b"\x01"          # TCP command
        + port.to_bytes(2, "big")
        + b"\x01\x7f\x00\x00\x01"  # IPv4 127.0.0.1
        + b"ping"
    )

    try:
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://onex-test",
            timeout=5.0,
        ) as client:
            response = await client.post(
                "/xhttp-siz10/stream-one/",
                content=request_body,
                headers={"content-type": "application/grpc"},
            )

        assert response.status_code == 200, response.text
        assert response.headers.get("content-type", "").startswith("text/event-stream")
        assert response.content.startswith(b"\x00\x00"), response.content[:8]
        assert response.content[2:] == b"ping", response.content
        print("PASS: stream-one HTTP/VLESS/TCP round-trip")
    finally:
        async with main.LINKS_LOCK:
            main.LINKS.pop(uid, None)
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main_test())
