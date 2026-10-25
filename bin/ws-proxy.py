#!/usr/bin/env python3
"""SSH-over-WebSocket proxy for HTTP Injector / HTTP Custom style payloads.

Usage: ws-proxy.py [listen_port] [target_port]

Any HTTP-looking request (one or several chained header blocks) is answered
with "101 Switching Protocols" and the connection is then piped raw to the
local SSH server. Clients that start with "SSH-" are piped directly.
Works with Python 3.8+ (Debian 11 ... Ubuntu 26.04).
"""
import asyncio
import sys

LISTEN_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8880
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 109
RESPONSE = (b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
BUF = 65536


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(BUF)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle(c_reader, c_writer):
    try:
        first = await asyncio.wait_for(c_reader.read(BUF), timeout=20)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        c_writer.close()
        return
    if not first:
        c_writer.close()
        return

    leftover = b""
    if first.startswith(b"SSH-"):
        leftover = first
    else:
        # Keep whatever follows the last header block if it is already SSH data
        tail = first.rsplit(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in first else b""
        if tail.startswith(b"SSH-"):
            leftover = tail
        c_writer.write(RESPONSE)
        await c_writer.drain()

    try:
        s_reader, s_writer = await asyncio.open_connection("127.0.0.1", TARGET_PORT)
    except OSError:
        c_writer.close()
        return
    if leftover:
        s_writer.write(leftover)
        await s_writer.drain()

    await asyncio.gather(pipe(c_reader, s_writer), pipe(s_reader, c_writer))


async def main():
    server = await asyncio.start_server(handle, host=None, port=LISTEN_PORT, backlog=1024)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
