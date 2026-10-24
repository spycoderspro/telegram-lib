"""Encrypted RPC multiplexing, server acknowledgements and keepalives."""
from __future__ import annotations

import asyncio
import contextlib
import gzip
import io
import secrets
import struct
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from .auth import create_auth_key
from .crypto import decrypt_message, encrypt_message
from .errors import ProtocolError, rpc_error
from .session import Session
from .tl import GZIP, MAX_BYTES, Reader, Schema, TLObject, default_schema
from .transport import IntermediateTransport

RPC_RESULT, CONTAINER = 0xF35C6D01, 0x73F1F8DC


@dataclass
class Pending:
    request: TLObject
    future: asyncio.Future
    content: bool
    attempts: int = 0


class Connection:
    def __init__(self, session: Session, *, timeout: float = 30, transport: IntermediateTransport | None = None) -> None:
        self.session, self.timeout = session, timeout
        self.schema: Schema = default_schema()
        self.transport = transport or IntermediateTransport(session.host, timeout=timeout)
        self.session_id = secrets.token_bytes(8)
        self.pending: dict[int, Pending] = {}
        self.updates: asyncio.Queue[TLObject] = asyncio.Queue(maxsize=1000)
        self.closed = asyncio.Event()
        self.failure: BaseException | None = None
        self._last_id = self._sequence = 0
        self._seen: set[int] = set()
        self._recent: deque[int] = deque()
        self._id_floor = 0
        self._salts: dict[int, tuple[int, int]] = {}
        self._send_lock = asyncio.Lock()
        self._reader_task: asyncio.Task | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._closing = False

    async def connect(self) -> None:
        if self._reader_task:
            raise RuntimeError("Connection has already been started")
        try:
            await self.transport.connect()
            if not self.session.auth_key:
                await create_auth_key(self.transport, self.session, self.schema)
            self._reader_task = asyncio.create_task(self._receive_loop(), name="easyproto-reader")
            self._heartbeat_task = asyncio.create_task(self._heartbeat(), name="easyproto-heartbeat")
        except BaseException:
            await self.transport.close()
            raise

    def _message_id(self) -> int:
        self._last_id = max(int((time.time() + self.session.time_offset) * (1 << 32)) & ~3, self._last_id + 4)
        return self._last_id

    async def _send(self, obj: TLObject, content: bool, pending: Pending | None = None) -> int:
        body = self.schema.encode(obj)
        async with self._send_lock:
            if self.closed.is_set():
                raise ConnectionError("MTProto connection is closed") from self.failure
            now = time.time() + self.session.time_offset
            for salt, (since, until) in self._salts.items():
                if since <= now < until:
                    self.session.salt = salt
                    break
            msg_id = self._message_id()
            seq_no = self._sequence * 2 + int(content)
            if content:
                self._sequence += 1
            plain = struct.pack("<q8sqii", self.session.salt, self.session_id, msg_id, seq_no, len(body)) + body
            if pending:
                self.pending[msg_id] = pending
            try:
                await self.transport.send(encrypt_message(self.session.auth_key, plain))
            except BaseException:
                if pending:
                    self.pending.pop(msg_id, None)
                raise
            return msg_id

    async def invoke(self, request: TLObject, *, content: bool = True) -> Any:
        if not self._reader_task or self.closed.is_set():
            raise ConnectionError("Connect before making requests") from self.failure
        future = asyncio.get_running_loop().create_future()
        pending = Pending(request, future, content)
        try:
            await self._send(request, content, pending)
            return await asyncio.wait_for(asyncio.shield(future), self.timeout)
        finally:
            for msg_id, item in list(self.pending.items()):
                if item is pending:
                    del self.pending[msg_id]
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()  # Retrieve a concurrent close/error even after cancellation.

    def _check_server_id(self, msg_id: int) -> bool:
        if msg_id <= 0 or msg_id % 4 not in (1, 3):
            raise ProtocolError("Invalid server message ID")
        now = time.time() + self.session.time_offset
        stamp = msg_id / (1 << 32)
        if not now - 300 <= stamp <= now + 30:
            raise ProtocolError("Server message is outside the accepted time window")
        if msg_id <= self._id_floor or msg_id in self._seen:
            return False
        self._seen.add(msg_id)
        self._recent.append(msg_id)
        if len(self._recent) > 1024:
            removed = self._recent.popleft()
            self._seen.remove(removed)
            self._id_floor = max(self._id_floor, removed)
        return True

    def _unzip(self, body: bytes) -> bytes:
        for _ in range(4):
            if len(body) < 4 or struct.unpack("<I", body[:4])[0] != GZIP:
                return body
            reader = Reader(body[4:])
            packed = reader.bytes()
            if reader.remaining():
                raise ProtocolError("Trailing gzip envelope bytes")
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(packed)) as stream:
                    body = stream.read(MAX_BYTES + 1)
            except (OSError, EOFError) as exc:
                raise ProtocolError("Invalid compressed message") from exc
            if len(body) > MAX_BYTES:
                raise ProtocolError("Expanded message exceeds size limit")
        raise ProtocolError("Excessively nested gzip")

    async def _handle(self, msg_id: int, seq_no: int, body: bytes, depth: int = 0) -> None:
        if depth > 8 or seq_no < 0:
            raise ProtocolError("Invalid message container nesting or sequence")
        body = self._unzip(body)
        # Authenticated clock-rejection notices can repair a stale local clock.
        if len(body) >= 20 and struct.unpack("<I", body[:4])[0] == 0xA7EFF811:
            notice = self.schema.decode(body)
            if notice.error_code in (16, 17) and notice.bad_msg_id in self.pending:
                self.session.time_offset = msg_id / (1 << 32) - time.time()
                self._last_id = 0
        fresh = self._check_server_id(msg_id)
        if seq_no & 1:
            await self._send(TLObject("msgs_ack", msg_ids=[msg_id]), False)
        if not fresh:
            return
        reader = Reader(body)
        constructor = reader.unpack("<I")
        if constructor == CONTAINER:
            count = reader.unpack("<i")
            if not 0 <= count <= 1024:
                raise ProtocolError("Invalid message container size")
            for _ in range(count):
                inner_id, inner_seq, length = struct.unpack("<qii", reader.read(16))
                if length < 4 or length % 4:
                    raise ProtocolError("Invalid container message size")
                if inner_id >= msg_id:
                    raise ProtocolError("Container child ID must precede its envelope ID")
                await self._handle(inner_id, inner_seq, reader.read(length), depth + 1)
            if reader.remaining():
                raise ProtocolError("Trailing container bytes")
            return
        if constructor == RPC_RESULT:
            request_id = reader.unpack("<q")
            pending = self.pending.pop(request_id, None)
            if not pending or pending.future.done():
                return
            data = self._unzip(reader.read(reader.remaining()))
            kind = "Object" if data[:4] == struct.pack("<I", 0x2144CA19) else self.schema.result_type(pending.request)
            try:
                result = self.schema.decode(data, kind)
                if isinstance(result, TLObject) and result.name == "rpc_error":
                    pending.future.set_exception(rpc_error(result.error_code, result.error_message))
                else:
                    pending.future.set_result(result)
            except Exception as exc:
                pending.future.set_exception(exc)
                raise
            return
        obj = self.schema.decode(body)
        if obj.name == "pong":
            pending = self.pending.pop(obj.msg_id, None)
            if pending and not pending.future.done():
                pending.future.set_result(obj)
        elif obj.name == "future_salts":
            if len(obj.salts) > 64:
                raise ProtocolError("Excessive future salts")
            pending = self.pending.pop(obj.req_msg_id, None)
            if pending and not pending.future.done():
                self._salts = {s.salt: (s.valid_since, s.valid_until) for s in obj.salts
                               if s.valid_since < s.valid_until}
                pending.future.set_result(obj)
        elif obj.name in ("bad_server_salt", "bad_msg_notification"):
            if obj.name == "bad_server_salt":
                self.session.salt = obj.new_server_salt
                self.session.save()
            pending = self.pending.pop(obj.bad_msg_id, None)
            if pending and not pending.future.done():
                if obj.error_code not in (16, 17, 48) or pending.attempts >= 2:
                    pending.future.set_exception(ProtocolError(f"Server rejected message: {obj.error_code}"))
                else:
                    pending.attempts += 1
                    try:
                        await self._send(pending.request, pending.content, pending)
                    except Exception as exc:
                        pending.future.set_exception(exc)
                        raise
        elif obj.name == "new_session_created":
            self.session.salt = obj.server_salt
            self.session.save()
        elif obj.name not in {"msgs_ack", "msgs_state_info", "msgs_all_info", "msg_detailed_info", "msg_new_detailed_info"}:
            try:
                self.updates.put_nowait(obj)
            except asyncio.QueueFull as exc:
                raise ProtocolError("Update queue overflow; reconnect and recover update state") from exc

    def _announces_salt(self, body: bytes, salt: int, depth: int = 0) -> bool:
        if depth > 8:
            raise ProtocolError("Excessive salt notification nesting")
        body = self._unzip(body)
        reader = Reader(body)
        code = reader.unpack("<I")
        if code == CONTAINER:
            count = reader.unpack("<i")
            if not 0 <= count <= 1024:
                raise ProtocolError("Invalid message container size")
            announced = False
            for _ in range(count):
                _, _, length = struct.unpack("<qii", reader.read(16))
                announced |= self._announces_salt(reader.read(length), salt, depth + 1)
            if reader.remaining():
                raise ProtocolError("Trailing container bytes")
            return announced
        if code in (0xEDAB447B, 0x9EC20908):
            obj = self.schema.decode(body)
            return obj.get("new_server_salt", obj.get("server_salt")) == salt
        return False

    async def _receive_loop(self) -> None:
        try:
            while True:
                packet = await self.transport.receive()
                salt, session_id, msg_id, seq_no, body = decrypt_message(self.session.auth_key, packet)
                if session_id != self.session_id:
                    raise ProtocolError("Response belongs to a different MTProto session")
                now = time.time() + self.session.time_offset
                known_salt = salt in self._salts and self._salts[salt][0] <= now < self._salts[salt][1]
                if salt != self.session.salt and not known_salt and not self._announces_salt(body, salt):
                    raise ProtocolError("Unrecognized server salt")
                await self._handle(msg_id, seq_no, body)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failure = exc
        finally:
            self.closed.set()
            if self._heartbeat_task and not self._closing:
                self._heartbeat_task.cancel()
            for item in self.pending.values():
                if not item.future.done():
                    item.future.set_exception(ConnectionError("MTProto connection closed"))
            self.pending.clear()
            await self.transport.close()

    async def _heartbeat(self) -> None:
        try:
            counter = 0
            while not self.closed.is_set():
                await asyncio.sleep(30)
                if counter % 20 == 0:
                    await self.invoke(TLObject("get_future_salts", num=32))
                await self.invoke(TLObject("ping_delay_disconnect", ping_id=secrets.randbits(63), disconnect_delay=75), content=False)
                counter += 1
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.failure = exc
            await self.close()

    async def close(self) -> None:
        current = asyncio.current_task()
        self._closing = True
        self.closed.set()
        for task in (self._heartbeat_task, self._reader_task):
            if task and task is not current:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
        await self.transport.close()
