"""Simple user-account actions over EasyProto's independent MTProto engine."""
from __future__ import annotations

import asyncio
import getpass
import inspect
import logging
import os
import re
import secrets
import sys
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .connection import Connection
from .crypto import password_proof
from .errors import AuthorizationRequired, FloodWaitError, MigrationRequired, RPCError, UnsupportedFeature
from .session import Session
from .tl import TLObject, default_schema, functions, types

log = logging.getLogger(__name__)
Peer = str | int | TLObject


def random_id() -> int:
    return secrets.randbits(63)


def peer_id(peer: TLObject) -> int:
    if peer.name in ("peerUser", "inputPeerUser", "user", "userEmpty"):
        return peer.get("user_id", peer.get("id"))
    if peer.name in ("peerChat", "inputPeerChat", "chat", "chatForbidden"):
        return -peer.get("chat_id", peer.get("id"))
    if peer.name in ("peerChannel", "inputPeerChannel", "channel", "channelForbidden"):
        return -1_000_000_000_000 - peer.get("channel_id", peer.get("id"))
    raise ValueError(f"Cannot obtain a peer ID from {peer.name}")


def schedule_date(value: datetime | None) -> int | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Use a timezone-aware schedule datetime")
    return int(value.timestamp())


@dataclass
class Message:
    client: Client
    raw: TLObject
    target: Peer

    @property
    def id(self) -> int:
        return self.raw.id

    @property
    def text(self) -> str:
        return self.raw.get("message", "")

    raw_text = text

    @property
    def sender_id(self) -> int | None:
        sender = self.raw.get("from_id")
        return peer_id(sender) if sender else (self.client.session.user_id if self.raw.get("out") else None)

    async def reply(self, text: str, **options: Any) -> Message:
        return await self.client.reply(self.target, self.id, text, **options)

    async def edit(self, text: str, **options: Any) -> Message:
        return await self.client.edit(self.target, self.id, text, **options)

    async def download(self, destination: str | Path = ".", *, workers: int | None = None) -> Path:
        return await self.client.download(self, destination, workers=workers)


class RawNamespace:
    def __init__(self, client: Client, prefix: str = "") -> None:
        self.client, self.prefix = client, prefix

    def __getattr__(self, name: str) -> RawNamespace:
        return RawNamespace(self.client, f"{self.prefix}.{name}" if self.prefix else name)

    async def __call__(self, request: TLObject | None = None, /, **fields: Any) -> Any:
        if request is not None and (self.prefix or fields):
            raise TypeError("Pass a request object or namespace fields")
        return await self.client.invoke(request if request is not None else TLObject(self.prefix, **fields))


class Client:
    def __init__(self, api_id: int, api_hash: str, session: str | Path = "easyproto", *,
                 test_mode: bool = False, dc_id: int = 2, timeout: float = 30,
                 flood_sleep_threshold: int = 0, transfer_workers: int = 4) -> None:
        if isinstance(api_id, bool) or not isinstance(api_id, int) or api_id <= 0:
            raise ValueError("api_id must be a positive integer")
        if not isinstance(api_hash, str) or not api_hash.strip():
            raise ValueError("api_hash is required")
        if timeout <= 0 or flood_sleep_threshold < 0:
            raise ValueError("Invalid timeout or flood sleep threshold")
        from .media import worker_count
        self.transfer_workers = worker_count(self, transfer_workers)
        self.api_id, self._api_hash = api_id, api_hash
        self.session = Session.load(session, dc_id=dc_id, test_mode=test_mode)
        self.session.host  # Validate the selected DC before attempting a connection.
        self.timeout, self.flood_sleep_threshold = timeout, flood_sleep_threshold
        self.raw = RawNamespace(self)
        self._connection: Connection | None = None
        self._entities: dict[str | int, TLObject] = {}
        self._peers: dict[str | int, TLObject] = {}
        self._handlers: list[tuple[Callable, Any, Any, bool]] = []
        self._listening = False

    @classmethod
    def from_env(cls, **options: Any) -> Client:
        try:
            api_id, api_hash = int(os.environ["TG_API_ID"]), os.environ["TG_API_HASH"]
        except (KeyError, ValueError) as exc:
            raise ValueError("Set TG_API_ID (integer) and TG_API_HASH") from exc
        options.setdefault("session", os.getenv("TG_SESSION", "easyproto"))
        return cls(api_id, api_hash, **options)

    async def _initialize(self, connection: Connection) -> None:
        await connection.connect()
        await connection.invoke(functions.invokeWithLayer(layer=default_schema().layer,
            query=functions.initConnection(api_id=self.api_id, device_model="EasyProto Python",
                system_version=sys.platform, app_version="0.2.0a2", system_lang_code="en",
                lang_pack="", lang_code="en", query=functions.help.getConfig())))

    async def _open(self) -> None:
        if self._connection and not self._connection.closed.is_set():
            return
        self.session.acquire()
        self._connection = Connection(self.session, timeout=self.timeout)
        try:
            await self._initialize(self._connection)
        except BaseException:
            await self.close()
            raise

    async def connect(self) -> Client:
        """Connect an authorized session; never prompt for login."""
        try:
            await self._open()
            await self.me()
            return self
        except RPCError as exc:
            await self.close()
            if exc.code == 401:
                raise AuthorizationRequired("Session needs login; call start() explicitly") from exc
            raise
        except BaseException:
            await self.close()
            raise

    async def _migrate(self, dc_id: int) -> None:
        old = self._connection
        if not old:
            raise ConnectionError("Not connected")
        exported = await old.invoke(functions.auth.exportAuthorization(dc_id=dc_id)) if self.session.user_id else None
        temporary = Session(None, dc_id=dc_id, test_mode=self.session.test_mode)
        replacement = Connection(temporary, timeout=self.timeout)
        try:
            await self._initialize(replacement)
            if exported:
                await replacement.invoke(functions.auth.importAuthorization(id=exported.id, bytes=exported.bytes))
                temporary.user_id = self.session.user_id
        except BaseException:
            await replacement.close()
            raise
        temporary.path = self.session.path
        try:
            temporary.save()
        except BaseException:
            await replacement.close()
            raise
        temporary._lock_file, self.session._lock_file = self.session._lock_file, None
        self.session, self._connection = temporary, replacement
        await old.close()

    async def invoke(self, request: TLObject) -> Any:
        if not self._connection:
            raise ConnectionError("Call start() or connect() first")
        default_schema().encode(request)
        for attempt in range(2):
            try:
                result = await self._connection.invoke(request)
                self._cache_result(result)
                return result
            except FloodWaitError as exc:
                if attempt or exc.seconds > self.flood_sleep_threshold:
                    raise
                await asyncio.sleep(exc.seconds)
            except MigrationRequired as exc:
                if attempt or exc.message.startswith("FILE_"):
                    raise
                await self._migrate(exc.dc_id)
        raise RuntimeError("Unreachable retry state")

    async def send_code(self, phone: str) -> TLObject:
        return await self.invoke(functions.auth.sendCode(phone_number=phone, api_id=self.api_id,
                                 api_hash=self._api_hash, settings=types.codeSettings()))

    async def sign_in(self, phone: str, code: str, phone_code_hash: str) -> TLObject:
        result = await self.invoke(functions.auth.signIn(phone_number=phone,
                                  phone_code_hash=phone_code_hash, phone_code=code))
        return self._authorized(result)

    def _authorized(self, result: TLObject) -> TLObject:
        if result.name != "auth.authorization":
            raise UnsupportedFeature("Account signup or additional verification is required; use an existing account")
        self._cache_result(result.user)
        self.session.user_id = result.user.id
        self.session.save()
        return result.user

    async def check_password(self, password: str) -> TLObject:
        settings = await self.invoke(functions.account.getPassword())
        proof = await asyncio.to_thread(password_proof, password, settings)
        return self._authorized(await self.invoke(functions.auth.checkPassword(password=proof)))

    async def start(self, *, phone: str | None = None, code_callback: Callable | None = None,
                    password: str | Callable | None = None) -> Client:
        """Explicit existing-account login. Callbacks may be async."""
        try:
            await self._open()
            try:
                await self.me()
                return self
            except RPCError as exc:
                if exc.code != 401:
                    raise
            async def value(callback: Callable) -> str:
                result = callback()
                return await result if inspect.isawaitable(result) else result
            if phone is None:
                if not sys.stdin.isatty():
                    raise AuthorizationRequired("First login requires phone and code_callback, or an interactive terminal")
                phone = await asyncio.to_thread(input, "Telegram phone number: ")
            sent = await self.send_code(phone)
            if sent.name == "auth.sentCodeSuccess":
                self._authorized(sent.authorization)
                return self
            if sent.name != "auth.sentCode":
                raise UnsupportedFeature(f"Login requires extra steps: {sent.name}")
            if code_callback is None:
                if not sys.stdin.isatty():
                    raise AuthorizationRequired("Supply code_callback to complete login")
                code = await asyncio.to_thread(input, "Telegram login code: ")
            else:
                code = await value(code_callback)
            try:
                await self.sign_in(phone, code, sent.phone_code_hash)
            except RPCError as exc:
                if exc.message != "SESSION_PASSWORD_NEEDED":
                    raise
                if callable(password):
                    secret = await value(password)
                elif password is not None:
                    secret = password
                elif sys.stdin.isatty():
                    secret = await asyncio.to_thread(getpass.getpass, "Telegram 2FA password: ")
                else:
                    raise AuthorizationRequired("Supply a password callback for 2FA") from exc
                await self.check_password(secret)
            return self
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        try:
            if self._connection:
                await self._connection.close()
                self._connection = None
        finally:
            self.session.release()

    async def __aenter__(self) -> Client:
        return await self.start()

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    def _cache_result(self, result: Any) -> None:
        if isinstance(result, list):
            for item in result:
                self._cache_result(item)
            return
        if not isinstance(result, TLObject):
            return
        if result.name in ("user", "chat", "chatForbidden", "channel", "channelForbidden"):
            key = peer_id(result)
            if result.name == "user" and (result.get("self") or result.id == self.session.user_id):
                peer = types.inputPeerSelf()
            elif result.name == "user" and result.get("access_hash") is not None and not result.get("min"):
                peer = types.inputPeerUser(user_id=result.id, access_hash=result.access_hash)
            elif result.name in ("channel", "channelForbidden") and result.get("access_hash") is not None and not result.get("min"):
                peer = types.inputPeerChannel(channel_id=result.id, access_hash=result.access_hash)
            elif result.name in ("chat", "chatForbidden"):
                peer = types.inputPeerChat(chat_id=result.id)
            else:
                self._entities.setdefault(key, result)
                return
            self._entities[key], self._peers[key] = result, peer
            names = [result.get("username")]
            names += [u.username for u in result.get("usernames", []) or [] if u.get("active")]
            for name in names:
                if name:
                    self._entities[name.lower()], self._peers[name.lower()] = result, peer
        for field in ("users", "chats", "user"):
            if child := result.get(field):
                self._cache_result(child)

    async def resolve(self, target: Peer) -> TLObject:
        if isinstance(target, TLObject):
            if target.name.startswith("inputPeer"):
                return target
            self._cache_result(target)
            key = peer_id(target)
        elif isinstance(target, str):
            if target.lower() in ("me", "self"):
                return types.inputPeerSelf()
            value = target.strip()
            if value.startswith(("https://", "http://")):
                parsed = urlparse(value)
                if parsed.hostname not in ("t.me", "telegram.me", "www.t.me"):
                    raise ValueError("Expected a Telegram username link")
                value = parsed.path.strip("/")
            key = value.lstrip("@").lower()
            if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,31}", key):
                raise ValueError("Expected a username; numeric IDs must be integers")
            if key not in self._peers:
                await self.invoke(functions.contacts.resolveUsername(username=key))
        elif isinstance(target, int) and not isinstance(target, bool):
            if target == self.session.user_id:
                return types.inputPeerSelf()
            key = target
        else:
            raise TypeError("Expected a username, cached numeric peer ID, or TL peer")
        try:
            return self._peers[key]
        except KeyError as exc:
            raise ValueError("Unknown peer/access hash; resolve a username or load chats first") from exc

    @staticmethod
    def _channel(peer: TLObject) -> TLObject:
        if peer.name != "inputPeerChannel":
            raise ValueError("Expected a channel or supergroup")
        return types.inputChannel(channel_id=peer.channel_id, access_hash=peer.access_hash)

    async def me(self) -> TLObject:
        result = await self.invoke(functions.users.getUsers(id=[types.inputUserSelf()]))
        if len(result) != 1 or result[0].name != "user":
            raise AuthorizationRequired("Account is not authorized")
        self.session.user_id = result[0].id
        self.session.save()
        return result[0]

    async def user(self, target: Peer) -> TLObject:
        peer = await self.resolve(target)
        if peer.name == "inputPeerSelf":
            return await self.me()
        key = peer_id(peer)
        if key in self._entities:
            return self._entities[key]
        if peer.name == "inputPeerUser":
            result = await self.invoke(functions.users.getUsers(id=[types.inputUser(user_id=peer.user_id, access_hash=peer.access_hash)]))
            return result[0]
        if peer.name == "inputPeerChannel":
            result = await self.invoke(functions.channels.getChannels(id=[self._channel(peer)]))
        else:
            result = await self.invoke(functions.messages.getChats(id=[peer.chat_id]))
        return result.chats[0]

    @staticmethod
    def _plain(parse_mode: str | None) -> None:
        if parse_mode is not None:
            raise UnsupportedFeature("Use plain text or explicit TL entities; HTML/Markdown parsing is not implemented")

    def _message(self, result: TLObject, target: Peer, text: str = "", wanted_id: int | None = None) -> Message:
        if result.name == "updateShortSentMessage":
            return Message(self, TLObject("message", id=result.id, message=text, out=True,
                                          date=result.date, media=result.get("media")), target)
        updates = [result.update] if result.name == "updateShort" else result.get("updates", [])
        for update in updates:
            message = update.get("message")
            if isinstance(message, TLObject) and message.name in ("message", "messageService"):
                if wanted_id is None or message.id == wanted_id:
                    return Message(self, message, target)
        raise UnsupportedFeature("Telegram returned no matching message; inspect the raw RPC response")

    async def send(self, target: Peer, text: str, *, reply_to: int | None = None,
                   silent: bool = False, schedule: datetime | None = None,
                   parse_mode: str | None = None, **options: Any) -> Message:
        self._plain(parse_mode)
        request = functions.messages.sendMessage(peer=await self.resolve(target), message=text,
            random_id=random_id(), silent=silent,
            reply_to=types.inputReplyToMessage(reply_to_msg_id=reply_to) if reply_to is not None else None,
            schedule_date=schedule_date(schedule), **options)
        return self._message(await self.invoke(request), target, text)

    async def reply(self, target: Peer, message_id: int, text: str, **options: Any) -> Message:
        return await self.send(target, text, reply_to=message_id, **options)

    async def edit(self, target: Peer, message_id: int, text: str, *, parse_mode: str | None = None,
                   **options: Any) -> Message:
        self._plain(parse_mode)
        result = await self.invoke(functions.messages.editMessage(peer=await self.resolve(target),
                                   id=message_id, message=text, **options))
        return self._message(result, target, text, message_id)

    async def delete(self, target: Peer, message_ids: int | Sequence[int], *, revoke: bool = False) -> Any:
        peer = await self.resolve(target)
        ids = [message_ids] if isinstance(message_ids, int) else list(message_ids)
        if peer.name == "inputPeerChannel":
            return await self.invoke(functions.channels.deleteMessages(channel=self._channel(peer), id=ids))
        return await self.invoke(functions.messages.deleteMessages(id=ids, revoke=revoke))

    async def forward(self, source: Peer, target: Peer, message_ids: int | Sequence[int],
                      *, schedule: datetime | None = None, **options: Any) -> TLObject:
        ids = [message_ids] if isinstance(message_ids, int) else list(message_ids)
        return await self.invoke(functions.messages.forwardMessages(from_peer=await self.resolve(source),
            to_peer=await self.resolve(target), id=ids, random_id=[random_id() for _ in ids],
            schedule_date=schedule_date(schedule), **options))

    async def history(self, target: Peer, *, limit: int = 100, search: str | None = None,
                      **options: Any) -> AsyncIterator[Message]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        peer, offset, yielded = await self.resolve(target), options.pop("offset_id", 0), 0
        while yielded < limit:
            fields = dict(peer=peer, offset_id=offset, offset_date=0, add_offset=0,
                          limit=min(100, limit - yielded), max_id=0, min_id=0, hash=0)
            if search is not None:
                fields.update(q=search, filter=types.inputMessagesFilterEmpty(), min_date=0, max_date=0)
            fields.update(options)
            result = await self.invoke(TLObject("messages.search" if search is not None else "messages.getHistory", **fields))
            messages = result.get("messages", [])
            if not messages:
                return
            for message in messages:
                if message.name != "messageEmpty":
                    yield Message(self, message, target)
                    yielded += 1
                    if yielded >= limit:
                        return
            next_offset = messages[-1].id
            if offset and next_offset >= offset:
                return
            offset = next_offset

    async def chats(self, *, limit: int = 100) -> AsyncIterator[TLObject]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        offset_id, offset_date, offset_peer, yielded = 0, 0, types.inputPeerEmpty(), 0
        while yielded < limit:
            result = await self.invoke(functions.messages.getDialogs(offset_id=offset_id,
                offset_date=offset_date, offset_peer=offset_peer, limit=min(100, limit - yielded), hash=0,
                exclude_pinned=bool(offset_id)))
            dialogs = result.get("dialogs", [])
            if not dialogs:
                return
            for dialog in dialogs:
                entity = self._entities.get(peer_id(dialog.peer))
                if entity:
                    yield entity
                    yielded += 1
                    if yielded >= limit:
                        return
            last = dialogs[-1]
            resolved = await self.resolve(last.peer)
            if last.top_message == offset_id and resolved == offset_peer:
                return
            offset_id, offset_peer = last.top_message, resolved
            matching = next((m for m in result.messages if m.id == offset_id and m.get("peer_id") == last.peer), None)
            if matching is None:
                return
            offset_date = matching.date

    async def read(self, target: Peer, *, through: int = 0) -> Any:
        peer = await self.resolve(target)
        if peer.name == "inputPeerChannel":
            return await self.invoke(functions.channels.readHistory(channel=self._channel(peer), max_id=through))
        return await self.invoke(functions.messages.readHistory(peer=peer, max_id=through))

    async def react(self, target: Peer, message_id: int, emoji: str | None = "👍") -> TLObject:
        reaction = [types.reactionEmoji(emoticon=emoji)] if emoji is not None else []
        return await self.invoke(functions.messages.sendReaction(peer=await self.resolve(target),
                                 msg_id=message_id, reaction=reaction))

    async def join(self, target: str) -> TLObject:
        value = target.strip()
        if value.startswith(("https://", "http://")):
            parsed = urlparse(value)
            if parsed.hostname not in ("t.me", "telegram.me", "www.t.me"):
                raise ValueError("Expected a Telegram link")
            value = parsed.path.strip("/")
        invite = value[1:] if value.startswith("+") else value[len("joinchat/"):] if value.startswith("joinchat/") else None
        if invite is not None:
            if not re.fullmatch(r"[\w-]+", invite):
                raise ValueError("Invalid invite hash")
            return await self.invoke(functions.messages.importChatInvite(hash=invite))
        return await self.invoke(functions.channels.joinChannel(channel=self._channel(await self.resolve(value))))

    async def leave(self, target: Peer) -> TLObject:
        return await self.invoke(functions.channels.leaveChannel(channel=self._channel(await self.resolve(target))))

    async def profile(self, *, first_name: str | None = None, last_name: str | None = None,
                      bio: str | None = None) -> TLObject:
        return await self.invoke(functions.account.updateProfile(first_name=first_name, last_name=last_name, about=bio))

    async def upload(self, path: str | Path, *, workers: int | None = None) -> TLObject:
        from .media import upload
        return await upload(self, path, workers=workers)

    async def media(self, target: Peer, path: str | Path | Sequence[str | Path], *, caption: str = "",
                    as_photo: bool = False, schedule: datetime | None = None,
                    reply_to: int | None = None, workers: int | None = None,
                    **options: Any) -> Message | TLObject:
        from .media import send_media
        return await send_media(self, target, path, caption=caption, as_photo=as_photo, workers=workers,
            schedule_date=schedule_date(schedule),
            reply_to=types.inputReplyToMessage(reply_to_msg_id=reply_to) if reply_to is not None else None,
            **options)

    async def download(self, message: Message | TLObject, destination: str | Path = ".", *,
                       workers: int | None = None) -> Path:
        from .media import download
        return await download(self, message, destination, workers=workers)

    @asynccontextmanager
    async def _at_dc(self, dc_id: int):
        if dc_id == self.session.dc_id:
            if not self._connection:
                raise ConnectionError("Not connected")
            yield self._connection
            return
        exported = await self.invoke(functions.auth.exportAuthorization(dc_id=dc_id))
        connection = Connection(Session(None, dc_id=dc_id, test_mode=self.session.test_mode), timeout=self.timeout)
        try:
            await self._initialize(connection)
            await connection.invoke(functions.auth.importAuthorization(id=exported.id, bytes=exported.bytes))
            yield connection
        finally:
            await connection.close()

    def on_message(self, *, chats: Peer | Sequence[Peer] | None = None, pattern: str | None = None,
                   incoming: bool = True) -> Callable:
        compiled = re.compile(pattern) if pattern else None
        def register(callback: Callable) -> Callable:
            if not inspect.iscoroutinefunction(callback):
                raise TypeError("Message callback must be async")
            self._handlers.append((callback, chats, compiled, incoming))
            return callback
        return register

    def off_message(self, callback: Callable) -> int:
        count = sum(item[0] is callback for item in self._handlers)
        self._handlers = [item for item in self._handlers if item[0] is not callback]
        return count

    async def _dispatch(self, message: TLObject) -> None:
        target = message.get("peer_id")
        if target is None:
            return
        event = Message(self, message, target)
        for callback, chats, pattern, incoming in list(self._handlers):
            if bool(message.get("out", False)) == incoming:
                continue
            if pattern and not pattern.search(event.text):
                continue
            if chats is not None:
                choices = [chats] if isinstance(chats, (str, int, TLObject)) else chats
                allowed = []
                for choice in choices:
                    resolved = await self.resolve(choice)
                    allowed.append(self.session.user_id if resolved.name == "inputPeerSelf" else peer_id(resolved))
                if peer_id(target) not in allowed:
                    continue
            try:
                await callback(event)
            except Exception:
                log.exception("EasyProto message callback failed")

    async def listen(self) -> None:
        """Dispatch live new-message events; reconnects and history replay are explicit."""
        if self._listening:
            raise RuntimeError("Only one listen() call may run per client")
        if not self._connection:
            raise ConnectionError("Connect before listening")
        self._listening = True
        connection = self._connection
        closed = asyncio.create_task(connection.closed.wait())
        next_update: asyncio.Task | None = None
        try:
            while True:
                next_update = asyncio.create_task(connection.updates.get())
                done, _ = await asyncio.wait((next_update, closed), return_when=asyncio.FIRST_COMPLETED)
                if closed in done:
                    if connection.failure:
                        raise ConnectionError("MTProto listener disconnected; reconnect explicitly") from connection.failure
                    return
                result = next_update.result()
                self._cache_result(result)
                if result.name in ("updatesTooLong", "updateChannelTooLong"):
                    raise UnsupportedFeature("Update gap recovery is not implemented; fetch history explicitly")
                if result.name in ("updateShortMessage", "updateShortChatMessage"):
                    out = result.get("out", False)
                    if result.name == "updateShortChatMessage":
                        target, sender = types.peerChat(chat_id=result.chat_id), types.peerUser(user_id=result.from_id)
                    else:
                        target = types.peerUser(user_id=result.user_id)
                        sender = types.peerUser(user_id=self.session.user_id if out else result.user_id)
                    await self._dispatch(TLObject("message", id=result.id, message=result.message, out=out,
                        peer_id=target, from_id=sender, date=result.date))
                    continue
                updates = [result.update] if result.name == "updateShort" else result.get("updates", [result])
                for update in updates:
                    if update.name == "updateChannelTooLong":
                        raise UnsupportedFeature("Channel update gap recovery is not implemented; fetch history explicitly")
                    if update.name in ("updateNewMessage", "updateNewChannelMessage"):
                        await self._dispatch(update.message)
        finally:
            for task in (next_update, closed):
                if task and not task.done():
                    task.cancel()
                if task:
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            self._listening = False
