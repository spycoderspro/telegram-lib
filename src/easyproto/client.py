"""Async action facade. Native Telethon results and exceptions are preserved."""
from __future__ import annotations

import os
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from telethon import TelegramClient, events, functions, types

Peer = str | int | types.TypeInputPeer


class Client:
    """Own one client per session file and event loop.

    Context entry performs interactive phone/code/2FA login if needed. For
    services, use connect() with an already-authorized session instead.
    """

    def __init__(
        self,
        api_id: int,
        api_hash: str,
        session: str | Path = "easyproto",
        *,
        flood_sleep_threshold: int = 30,
        **transport_options: Any,
    ) -> None:
        if isinstance(api_id, bool) or not isinstance(api_id, int) or api_id <= 0:
            raise ValueError("api_id must be a positive integer")
        if not api_hash or not api_hash.strip():
            raise ValueError("api_hash is required")
        if flood_sleep_threshold < 0:
            raise ValueError("flood_sleep_threshold must be nonnegative")
        self.raw = TelegramClient(
            str(session), api_id, api_hash,
            flood_sleep_threshold=flood_sleep_threshold,
            **transport_options,
        )
        # Plain text is predictable; callers can opt into markdown or HTML.
        self.raw.parse_mode = None

    @classmethod
    def from_env(cls, **options: Any) -> Client:
        """Read TG_API_ID, TG_API_HASH and optional TG_SESSION."""
        try:
            api_id = int(os.environ["TG_API_ID"])
            api_hash = os.environ["TG_API_HASH"]
        except (KeyError, ValueError) as exc:
            raise ValueError("Set TG_API_ID (integer) and TG_API_HASH") from exc
        options.setdefault("session", os.getenv("TG_SESSION", "easyproto"))
        return cls(api_id, api_hash, **options)

    async def start(self, **login_options: Any) -> Client:
        """Interactive login; accepts Telethon phone/code/password callbacks."""
        try:
            await self.raw.start(**login_options)
        except BaseException:
            await self.raw.disconnect()
            raise
        return self

    async def connect(self) -> Client:
        """Noninteractive connection; fail if the session needs login."""
        try:
            await self.raw.connect()
            if not await self.raw.is_user_authorized():
                raise RuntimeError("Session needs login; run start() locally first")
        except BaseException:
            await self.raw.disconnect()
            raise
        return self

    async def close(self) -> None:
        await self.raw.disconnect()

    async def __aenter__(self) -> Client:
        return await self.start()

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    async def me(self) -> Any:
        return await self.raw.get_me()

    async def user(self, target: Peer) -> Any:
        return await self.raw.get_entity(target)

    async def send(
        self, target: Peer, text: str, *, reply_to: int | None = None,
        silent: bool = False, schedule: datetime | None = None,
        parse_mode: str | None = None, **options: Any,
    ) -> Any:
        """Send text; use 'me' for Saved Messages."""
        return await self.raw.send_message(
            target, text, reply_to=reply_to, silent=silent,
            schedule=schedule, parse_mode=parse_mode, **options,
        )

    async def reply(self, target: Peer, message_id: int, text: str, **options: Any) -> Any:
        return await self.send(target, text, reply_to=message_id, **options)

    async def edit(self, target: Peer, message_id: int, text: str, **options: Any) -> Any:
        return await self.raw.edit_message(target, message_id, text, **options)

    async def delete(
        self, target: Peer, message_ids: int | Sequence[int], *, revoke: bool = False,
    ) -> Any:
        """Request local deletion by default. Channels may always delete globally."""
        return await self.raw.delete_messages(target, message_ids, revoke=revoke)

    async def forward(
        self, source: Peer, target: Peer, message_ids: int | Sequence[int],
        **options: Any,
    ) -> Any:
        return await self.raw.forward_messages(
            target, message_ids, from_peer=source, **options,
        )

    async def media(
        self, target: Peer, file: Any, *, caption: str = "", **options: Any,
    ) -> Any:
        """Upload one file or a list (album); options pass through to send_file."""
        return await self.raw.send_file(target, file, caption=caption, **options)

    async def download(self, message: Any, destination: str | Path = ".", **options: Any) -> Any:
        return await self.raw.download_media(message, file=str(destination), **options)

    async def history(
        self, target: Peer, *, limit: int = 100, search: str | None = None,
        **options: Any,
    ) -> AsyncIterator[Any]:
        if limit < 1:
            raise ValueError("limit must be positive")
        async for message in self.raw.iter_messages(target, limit=limit, search=search, **options):
            yield message

    async def chats(self, *, limit: int = 100) -> AsyncIterator[Any]:
        if limit < 1:
            raise ValueError("limit must be positive")
        async for dialog in self.raw.iter_dialogs(limit=limit):
            yield dialog

    async def read(self, target: Peer, *, through: int) -> Any:
        """Mark messages up to this ID read."""
        return await self.raw.send_read_acknowledge(target, max_id=through)

    async def react(self, target: Peer, message_id: int, emoji: str | None) -> Any:
        """One standard emoji reaction; None clears the reaction."""
        peer = await self.raw.get_input_entity(target)
        reaction = [] if emoji is None else [types.ReactionEmoji(emoticon=emoji)]
        return await self.raw(functions.messages.SendReactionRequest(
            peer=peer, msg_id=message_id, reaction=reaction,
        ))

    async def join(self, target: str) -> Any:
        """Join a public channel/group or a t.me/+ / joinchat invite URL."""
        from urllib.parse import urlparse
        value = target.strip()
        if value.startswith(("https://", "http://")):
            parsed = urlparse(value)
            if parsed.hostname not in {"t.me", "telegram.me", "www.t.me"}:
                raise ValueError("Expected a Telegram link")
            value = parsed.path.strip("/")
        if value.startswith("+"):
            invite = value[1:]
        elif value.startswith("joinchat/"):
            invite = value[len("joinchat/"):]
        else:
            if not value or "/" in value:
                raise ValueError("Expected a username or invite link")
            return await self.raw(functions.channels.JoinChannelRequest(value))
        if not invite or "/" in invite:
            raise ValueError("Invalid invite link")
        return await self.raw(functions.messages.ImportChatInviteRequest(invite))

    async def leave(self, target: Peer) -> Any:
        """Leave a channel or supergroup (not a legacy basic group)."""
        entity = await self.raw.get_input_entity(target)
        return await self.raw(functions.channels.LeaveChannelRequest(entity))

    async def profile(
        self, *, first_name: str | None = None, last_name: str | None = None,
        bio: str | None = None,
    ) -> Any:
        return await self.raw(functions.account.UpdateProfileRequest(
            first_name=first_name, last_name=last_name, about=bio,
        ))

    def on_message(
        self, *, chats: Any = None, pattern: str | None = None,
        incoming: bool = True,
    ) -> Callable:
        """Register an async callback receiving a native NewMessage event."""
        builder = events.NewMessage(chats=chats, pattern=pattern, incoming=incoming)

        def register(callback: Callable[..., Awaitable[Any]]) -> Callable:
            self.raw.add_event_handler(callback, builder)
            return callback
        return register

    def off_message(self, callback: Callable) -> int:
        return self.raw.remove_event_handler(callback, events.NewMessage)

    async def listen(self) -> None:
        await self.raw.run_until_disconnected()
