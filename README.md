# EasyProto Actions 0.1.0

A small Python 3.10+ library for everyday Telegram user-account actions. Built on
Telethon 1.45.0, the published release verified on 2026-10-23. Kurigram-inspired
simplicity, with native Telethon messages, events and errors. This is an action
facade, not an independent MTProto implementation or a Kurigram-compatible backend.
The package is delivered locally; it has not been published to PyPI.

## Install and run

Unzip, open a terminal inside `easyproto`, then:

```sh
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install .
```

Get your own API ID/hash from https://my.telegram.org under API development tools.
Set environment variables (PowerShell uses `$env:TG_API_ID = "12345"`):

```sh
export TG_API_ID=12345
export TG_API_HASH=your_api_hash
export TG_SESSION=personal
python examples/saved_messages.py
```

First run prompts for phone number, Telegram login code, and 2FA password if enabled.
Subsequent runs reuse the session. Never commit or share `.session` files or credentials;
a session grants access to your account. Keep one running process per session file.

```python
import asyncio
from easyproto import Client

async def main():
    async with Client.from_env() as tg:
        await tg.send("me", "A note to myself")
        # Explicitly choose a recipient for other actions:
        # await tg.send("@username", "Hello")
        # await tg.media("me", "photo.jpg", caption="My photo")

asyncio.run(main())
```

In notebooks, use `await main()` instead of `asyncio.run(main())`.

## Action reference

| Goal | Method |
|---|---|
| Account / resolve user or chat | `await tg.me()` / `await tg.user(target)` |
| Send / reply | `await tg.send(target, text)` / `await tg.reply(target, id, text)` |
| Edit / delete | `await tg.edit(target, id, text)` / `await tg.delete(target, ids)` |
| Forward | `await tg.forward(source, target, ids)` |
| Upload / album | `await tg.media(target, path_or_list, caption="...")` |
| Download | `await tg.download(message, "downloads/")` |
| Search history | `async for m in tg.history(target, limit=50, search="invoice")` |
| List chats | `async for chat in tg.chats(limit=50)` |
| Mark read through an ID | `await tg.read(target, through=123)` |
| React / clear reaction | `await tg.react(target, id, "👍")` / `await tg.react(target, id, None)` |
| Join | `await tg.join("@public_channel")` or a Telegram invite URL |
| Leave channel / supergroup | `await tg.leave(target)` |
| Edit profile | `await tg.profile(first_name="Alex", bio="Hello")` |
| Event handler | `@tg.on_message(chats=target, pattern=r"^hello")` |
| Remove handler / keep listening | `tg.off_message(handler)` / `await tg.listen()` |
| Advanced API | `tg.raw` is the native Telethon client |

Use usernames, `'me'`, cached numeric peer IDs or native input peers. Unknown numeric
IDs alone may not resolve because Telegram also requires access hashes. Scheduling
uses `schedule=datetime(...)`; prefer timezone-aware dates. Extra options on send,
edit, media, forward and history follow Telethon's corresponding method signatures.
Plain text is the default; explicitly pass `parse_mode="html"` or `"md"` when wanted.

`delete` defaults to `revoke=False`; Telegram channels/supergroups may delete for
everyone regardless. Profile fields set to None are unchanged; an empty string
requests clearing a field. Telegram enforces permissions, valid reactions, profile
limits, join approvals, and which messages can be edited/deleted. Errors propagate.

## Events

```python
async def main():
    tg = Client.from_env()
    @tg.on_message(chats="@chosen_chat", pattern=r"^hello$")
    async def greet(event):
        print(event.sender_id, event.raw_text)
    async with tg:
        await tg.listen()
```

Incoming events are the default, avoiding most self-reply loops. Use
`incoming=False` for outgoing-only events. Callbacks must be async. Telethon owns
handler scheduling; use its logging facilities to observe callback failures.

## Runtime behavior

- Async lifecycle and streaming history keep memory use bounded.
- Telethon handles reconnects and transport behavior; constructor options such as
  `proxy`, `connection_retries`, and `device_model` pass through unchanged.
- Short flood waits (30 seconds by default) are handled by Telethon. Longer waits
  surface as `telethon.errors.FloodWaitError`, including `.seconds`. Set
  `flood_sleep_threshold=0` to surface waits. Telegram limits cannot be bypassed.
- No extra wrapper retry loop replays failed actions. Telethon retains its own
  native RPC retry behavior; exactly-once delivery is not promised.
- For a noninteractive service, run `start()` locally once, then use
  `await tg.connect()` and `try/finally: await tg.close()` in the service.
- Raw methods expose features not wrapped here, including stories, topics and
  other layer-specific requests. Support is limited to the pinned engine's schema.
- Optional acceleration: `python -m pip install '.[fast]'` (cryptg).

## Verify and build

```sh
python -m pip install '.[dev]'
python -m pytest -q
python -m build
```

Tests exercise wrapper routing, cleanup, authorization failures, flood-wait
propagation, streaming, reactions and actual Telethon construction. They do not
contact Telegram. Live login and Telegram RPCs require your account and have not
been exercised as part of this delivery. This is an initial tested package, not a
claim of full Telethon/Kurigram feature parity.

Dependencies are deliberately pinned for reproducibility. To update, check the
upstream changelog, change the pin, run the suite, then perform account-based smoke
tests (Saved Messages send/edit/media/history). Do not silently auto-upgrade in production.

## Upstream references checked 2026-10-23

- https://pypi.org/project/Telethon/ (1.45.0)
- https://docs.telethon.dev/en/stable/modules/client.html
- https://docs.telethon.dev/en/stable/misc/changelog.html
- https://pypi.org/project/Kurigram/ (2.2.26, comparison only)
- https://docs.kurigram.icu/
