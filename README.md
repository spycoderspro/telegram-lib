# EasyProto Actions 0.2.0a2

An **experimental, independently implemented Python MTProto 2.0 client** with a
small asynchronous API for Telegram user actions. There is no Telethon, Kurigram,
Pyrogram or TDLib runtime dependency. PyCryptodome supplies the AES/RSA primitives;
EasyProto implements the protocol constructions, transport, TL codec, sessions,
key exchange, SRP password proof, RPC handling and action methods. Optional
`cryptg` accelerates AES-IGE without adding a Telegram client dependency.

This is an initial independent implementation, **not a production-ready replacement
or a feature-compatible implementation of Telethon/Kurigram**. Local protocol tests
pass, but real Telegram login, account RPCs and media transfers have not been
verified. The cloud environment refused a direct TCP connection to Telegram's test
DC. See [VALIDATION.md](VALIDATION.md) for what was actually tested.

## Protocol version and provenance

The bundled Telegram API schema is **layer 232**, fetched from the official
Telegram Desktop `dev` source at commit
`a7f453612f4896ac04d0007a36ab0d377e5bcbcf`. This is a pinned development-source
snapshot, not a claim about the latest stable Telegram release. The schemas and
production/test RSA public keys come from official Telegram sources. Their URLs,
commit and SHA-256 digests are recorded in
[`provenance.json`](src/easyproto/schemas/provenance.json). No schema download or
code generation is required at runtime. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Install

Python 3.10+ is required. The cloud setup was tested on Python 3.12.14.

```sh
uv sync --frozen --extra dev --extra fast
uv run python -m pytest -q
```

Or install the package with pip into your own virtual environment:

```sh
python -m pip install '.[fast]'
```

`uv.lock` pins the dependency resolution; cryptography dependencies are explicitly
pinned in `pyproject.toml`. The `fast` extra installs cryptg 0.6.0 on Python 3.11+.
On Python 3.10 the independent Python AES-IGE fallback remains available; use
Python 3.11+ for native acceleration. Existing 0.1.0 artifacts in `dist/` are
the old Telethon-based version. Use the **0.2.0a2** artifacts for this rewrite.

## User login and simplest actions

Obtain your own API ID/hash at https://my.telegram.org. Set them in your local
environment; do not put credentials into source files or chat.

```sh
export TG_API_ID=12345
export TG_API_HASH=your_own_api_hash
export TG_SESSION="$HOME/.local/share/easyproto/personal"
uv run python examples/saved_messages.py
```

First login in a terminal prompts for your phone, Telegram code and 2FA password
when required. Existing-account phone/code login and the SRP 2FA proof are
implemented. Email verification, paid login flows and account signup are not.
Those flows raise an explicit error. Telegram determines which login flow applies.

```python
import asyncio
from easyproto import Client

async def main():
    async with Client.from_env() as tg:
        message = await tg.send("me", "Hello from my independent client")
        await message.edit("Edited")
        await message.reply("A reply")

asyncio.run(main())
```

For callback-based login:

```python
await tg.start(phone=your_phone, code_callback=your_async_code_callback,
               password=your_async_password_callback)
```

For an already-authorized noninteractive process:

```python
await tg.connect()  # Raises AuthorizationRequired rather than prompting.
try:
    account = await tg.me()
finally:
    await tg.close()
```

Sessions use a new private JSON format ending in `.easyproto.json`, saved atomically
with mode 0600 on POSIX and locked against concurrent clients. Windows inherits
the parent directory's access controls. Sessions contain account authorization
keys: keep the directory private and never share/commit them. `session=":memory:"`
keeps session data only in memory and creates no file. **Telethon/Kurigram session
files are incompatible**; log in separately. The committed legacy `.session` file
is not loaded by the new implementation.

## User actions

| Action | Easy method |
|---|---|
| My account / resolve user or chat | `await tg.me()` / `await tg.user(target)` |
| Send / reply | `await tg.send(target, text)` / `await tg.reply(target, id, text)` |
| Edit / delete | `await tg.edit(target, id, text)` / `await tg.delete(target, ids)` |
| Forward | `await tg.forward(source, target, ids)` |
| Upload and send document | `await tg.media(target, "file.pdf", caption="...")` |
| Send photo | `await tg.media(target, "photo.jpg", as_photo=True)` |
| Send album (2–10 items) | `await tg.media(target, paths, as_photo=True)` |
| Upload only | `await tg.upload(path)` |
| Download document/photo | `await tg.download(message, "downloads/")` |
| History / search | `async for m in tg.history(target, limit=50, search="invoice")` |
| List chats | `async for chat in tg.chats(limit=50)` |
| Mark messages read | `await tg.read(target, through=id)` |
| React / clear reaction | `await tg.react(target, id, "👍")` / `await tg.react(target, id, None)` |
| Join / leave channel or supergroup | `await tg.join("@channel")` / `await tg.leave(target)` |
| Join invitation | `await tg.join("https://t.me/+invite_hash")` |
| Profile | `await tg.profile(first_name="Alex", bio="Hello")` |
| Live handlers | `@tg.on_message(chats=target, pattern=r"^hello")` |
| Remove handler / listen | `tg.off_message(handler)` / `await tg.listen()` |

Targets accept usernames, Telegram username URLs, `"me"`, native TL peers, or
numeric IDs whose access hashes have been cached. Resolve a username or call
`chats()` before using an unknown numeric ID. Channel/supergroup numeric IDs use
`-1000000000000 - channel_id`; basic group IDs are negative. Entity caches are
in memory and are rebuilt after reconnecting.

Text is plain by default. Pass explicit TL `entities` for formatting; convenience
HTML/Markdown parsing is not implemented. Additional request options use the
**current Telegram TL field names**, not Telethon/Kurigram keyword conventions.
Unknown or incorrectly typed TL fields are rejected by the codec.

`send`, `forward` and `media` accept `schedule=` with a timezone-aware `datetime`.
`media` also accepts `reply_to=`. `send`/`reply`/`edit` and single-media sends return
a `Message` with `.id`, `.text`, `.raw`, `.reply()`, `.edit()` and `.download()`.
Forward and album methods return the raw Telegram updates object. Some server
responses may require direct handling via the raw API.

`delete` defaults to local deletion (`revoke=False`). Channel/supergroup deletion
uses the channel-specific API and may delete for everyone. Telegram enforces
permissions, flood limits, edit restrictions and all other account restrictions.

## Faster uploads and downloads

Install the `fast` extra above to enable native AES-IGE automatically. Transfers
now keep **four chunk requests in flight** on the existing multiplexed MTProto
connection. Set a client default or override a single operation:

```python
tg = Client.from_env(transfer_workers=4)
# Inside an authorized client lifecycle:
await tg.media("me", "large.zip", workers=4)
await tg.download(message, "large.zip", workers=4)
# Upload without sending:
file = await tg.upload("large.zip", workers=4)
```

`workers` accepts integers 1–16. Use 1 for sequential operation, start with 4,
and tune from actual measurements. More workers can increase Telegram flood
waits and do not raise your connection/account/server limits. This implementation
pipelines requests on one connection; it does not create a multi-connection pool.

Uploads use a bounded producer queue and preserve part IDs/checksums even when
RPCs complete out of order. Big uploads skip the unused small-file MD5 pass.
Downloads write chunks at their requested offsets into a temporary file and
replace the destination only after every part is validated. Failure/cancellation
drains all workers and disk operations before removing temporary files. Transfers
do not load the whole file into memory. Approximate upload chunk buffers are
bounded by `(2 * workers + 1) * 512 KiB`, excluding framing/crypto allocations;
downloads keep at most one chunk per worker. These bounds are per transfer.

[Local benchmark results](BENCHMARKS.md) demonstrate reduced simulated-latency
waiting and native AES-IGE overhead. **Real Telegram transfer speed remains
unmeasured**, and no speed advantage over Telethon/Kurigram has been established.
Reproduce the offline benchmark with:

```sh
uv run --extra fast python examples/benchmark_transfers.py --workers 1 4
```

## Events

```python
async def main():
    tg = Client.from_env()

    @tg.on_message(chats="me", pattern=r"^hello", incoming=False)
    async def handler(message):
        print(message.id, message.raw_text)

    async with tg:
        await tg.listen()
```

Callbacks must be async. Incoming messages are selected by default;
`incoming=False` selects outgoing live updates. Callbacks run in order, with
exceptions logged. Only one `listen()` may run per client. Network disconnection,
queue overflow and explicit gap notifications are surfaced. The listener does
not promise durable delivery, replay across disconnections, automatic recovery of
`pts`/`qts`/channel state, or events for the client's own RPC results. Fetch history
explicitly to reconcile messages after a gap.

## Advanced raw API

The schema-driven API exposes the bundled declarations without a generated
Telethon/Pyrogram types dependency:

```python
from easyproto import functions, types

users = await tg.raw.users.getUsers(id=[types.inputUserSelf()])
# Equivalent explicit request:
users = await tg.raw(functions.users.getUsers(id=[types.inputUserSelf()]))
```

Raw results are `TLObject` instances with `.name` (constructor name), `.fields`
(the field mapping), field attributes and `.get()`. A TL field named `name` is
available through `.fields["name"]`. Raw schema availability does not implement
all feature workflows, such as calls, secret chats, payments or stories.

## Runtime and limitations

- Native asynchronous intermediate TCP to Telegram DCs, currently IPv4 on port
  443. This is **MTProto TCP, not HTTPS**; an HTTPS proxy alone cannot carry it.
  MTProxy, SOCKS, HTTP/WebSocket transports and transport obfuscation are absent.
- MTProto 2.0 SHA-256 message-key derivation and authenticated AES-IGE envelopes;
  pinned RSA keys with modern RSA_PAD for permanent auth-key negotiation;
  validated 2048-bit safe-prime DH groups and SRP 2FA password proofs.
- Bounded frame/TL/gzip sizes and nesting, session/message ID checks, replay
  rejection, acknowledgements, containers, bad-salt/clock corrections, future
  salts and keepalives. This code has **not had an independent security audit**.
- Known DC migration errors can move the account connection; downloads can
  establish a separately authorized connection to the file's DC. These paths
  have local request tests, not live account validation.
- File transfers pipeline 512 KiB parts through four concurrent RPC workers by
  default, with bounded queues and disk buffers. CDN redirects and automatic
  expired file-reference refresh are not implemented. Telegram size limits apply.
- No automatic reconnect/replay of requests after a lost response. A timeout can
  leave the result of a mutating action unknown; reconnect and inspect account
  state before retrying. Exactly-once delivery is not promised.
- Flood waits are raised as `easyproto.FloodWaitError` with `.seconds` by default.
  Opt into one bounded retry for a known rejection by setting
  `flood_sleep_threshold=N`. Salt corrections retain the original random IDs.
- No compatibility guarantee with Telethon/Kurigram types, sessions or options.
  Raw Telegram objects replace Telethon-native objects from version 0.1.0.

## Verify and build

```sh
uv sync --frozen --extra dev --extra fast
uv run python -m pytest -q
uv run python -m build --installer uv --outdir dist
```

Tests use generated keys, local protocol peers, loopback TCP and mocked account
RPC responses. They do not contact Telegram or send account messages. The codec
suite also exercises all 2,628 registered declarations from the pinned schemas
using synthetic minimal values; that is not a live compatibility guarantee.
See [VALIDATION.md](VALIDATION.md) before considering production use.

## Save Restricted Content Bot client-layer validation (2026-10-24)

The baseline passed **105 offline tests**. On the local feature branch
`validation/save-restricted-workflow`, focused RPC/session fixes and regression
coverage plus the separate harness pass **127 offline tests**, with **2 live
integration tests skipped**. Run both suites explicitly:

```sh
uv sync --frozen --extra dev --extra fast
.venv/bin/python -m pytest -q tests integration -rs
```

See [integration/README.md](integration/README.md) for staged account checks and
an authorized, one-message download/hash/upload/hash relay using `easyproto.Client`
directly. It refuses protected/expiring content and requires a known source hash.
It is a client-layer harness, not a validated deployed bot. Runtime dependencies,
public method signatures and bundled protocol schemas are unchanged.

The production and test DC 2 TCP connections were both refused in this cloud.
**No real Telegram login, account RPC, transfer, or bot workflow has passed here;
real upload/download speeds remain unmeasured.** Offline readiness is sufficient
to develop and test the library, but production readiness is not established.
Read [VALIDATION.md](VALIDATION.md) for exact scope, fixes and remaining risks.
