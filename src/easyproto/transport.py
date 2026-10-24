"""Bounded asynchronous intermediate TCP transport."""
from __future__ import annotations

import asyncio
import struct

from .errors import ProtocolError

MAX_FRAME = 16 * 1024 * 1024


class IntermediateTransport:
    def __init__(self, host: str, port: int = 443, timeout: float = 20) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None
        self._write_lock = asyncio.Lock()
        self._close_task: asyncio.Task | None = None

    async def connect(self) -> None:
        self._close_task = None
        self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(self.host, self.port), self.timeout)
        self.writer.write(b"\xee\xee\xee\xee")
        await self.writer.drain()

    async def send(self, data: bytes) -> None:
        if not data or len(data) % 4 or len(data) > MAX_FRAME:
            raise ValueError("Invalid intermediate frame size")
        async with self._write_lock:
            writer = self.writer
            if not writer or writer.is_closing():
                raise ConnectionError("Transport is disconnected")
            writer.write(struct.pack("<I", len(data)) + data)
            await writer.drain()

    async def receive(self) -> bytes:
        reader = self.reader
        if not reader:
            raise ConnectionError("Transport is disconnected")
        length = struct.unpack("<i", await reader.readexactly(4))[0]
        if length <= 0 or length % 4 or length > MAX_FRAME:
            raise ProtocolError(f"Invalid intermediate frame length: {length}")
        data = await reader.readexactly(length)
        if length == 4:
            raise ProtocolError(f"Telegram transport error: {struct.unpack('<i', data)[0]}")
        return data

    async def close(self) -> None:
        writer, self.writer = self.writer, None
        self.reader = None
        if writer:
            writer.close()
            async def wait_closed():
                try:
                    await writer.wait_closed()
                except (OSError, ConnectionError):
                    pass
            self._close_task = asyncio.create_task(wait_closed(), name="easyproto-transport-close")
        if self._close_task:
            # Multiple owners may close after EOF/failure. Cancelling one owner
            # must not cancel StreamWriter's shared close waiter for the others.
            await asyncio.shield(self._close_task)
