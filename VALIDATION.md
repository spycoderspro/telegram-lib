# Validation of the independent 0.2.0a2 rewrite

Validated in the current cloud machine on Python 3.12.14, PyCryptodome 4.1.0,
cryptg 0.6.0 (fast extra), pytest 9.1.1 and pytest-asyncio 1.4.0. This supersedes the old Telethon-based
0.1.0 validation report.

## Passed

- 105 offline tests passed against the source installation with the fast extra.
- The same 105 tests passed against the built wheel with the fast extra in a
  separate virtual environment, using tests extracted from the source archive.
- Without the fast extra, the installed wheel passed 102 tests; three optional
  native-backend equivalence tests were skipped. The Python AES-IGE known-answer
  test and all protocol/transfer tests still executed and passed.
- Telethon and Pyrogram/Kurigram are absent from both new virtual environments.
  Base runtime metadata requires only PyCryptodome; the optional fast extra adds
  cryptg for native AES-IGE.
- All 2,628 registered TL declarations in the pinned official layer-232 schema
  encoded/decoded using synthetic minimal values. Real Telegram payload coverage
  is narrower; this is a codec check, not proof of live API compatibility.
- An AES-256-IGE known-answer vector matched OpenSSL libcrypto independently.
- A local server with a generated RSA private key completed the permanent auth-key
  handshake and derived the same shared key. Nonce, fingerprint, checksum and key
  confirmation tampering were rejected without retaining an authorization key.
- A separately computed SRP server proof matched the client's 2FA proof.
- An actual loopback TCP server exercised encrypted request/response framing,
  gzip-packed vector results inside a message container, RPC correlation and
  acknowledgements.
- Unit tests exercised message IDs, replay rejection, message authentication,
  bounds, server-salt corrections, future salts, session privacy/locking, login
  routing, cleanup, flood errors and no automatic mutation replay after a lost
  response.
- User-action request tests covered send/reply/scheduling, forwarding, deletion,
  invites, reactions, profile updates, entity caching, paginated history, media
  upload/send/download, raw calls and live-event filtering/cancellation.
- Wheel and source distribution built successfully. The wheel includes the native
  engine, vendored schemas, keys and upstream notices. The source archive includes
  the lockfile, complete offline tests/fixtures and examples. Neither archive
  contains account sessions.

## Parallel transfer validation

- Upload tests verify overlapping RPCs, unchanged part numbering, a single file ID,
  correct small-file MD5, big-file part totals, and bounded producer read-ahead.
- Download tests verify exact reconstruction despite out-of-order responses,
  offset-aligned requests, and no replacement of an existing destination on error.
- Failure/cancellation tests verify that all workers and disk threads finish before
  temporary files are removed or handles are closed, including repeated cancellation.
- A loopback encrypted TCP peer received four requests before replying in reverse
  order; the client correlated every result correctly. Closing after peer EOF is
  safe across concurrent owners.
- Both independent Python and native AES-IGE match the OpenSSL known-answer vector;
  equivalence tests also cover a full 512 KiB block. Integrity verification remains
  enabled in both paths.
- The offline 8 MiB/40 ms RPC-latency model completed upload in 0.6903 seconds with
  one worker versus 0.1863 with four; download took 0.6918 versus 0.1787 seconds.
  This simulation excludes real network transport and MTProto encryption. It is
  not a Telegram speed measurement. The separate encryption microbenchmark is
  recorded in BENCHMARKS.md with a reproducible command.

## Blocked or unverified

An anonymous direct TCP connection to Telegram test DC 2 at
`149.154.167.40:443` was refused by the cloud machine (`ConnectionRefusedError`,
errno 111). The failure occurred before MTProto negotiation. No live protocol
success can be inferred from the local tests. HTTPS access to core.telegram.org
was also denied by the environment proxy; the official GitHub sources were
accessible.

No real Telegram login, account RPC, account event stream, DC migration, media
transfer or cross-DC authorization was validated. TG_API_ID, TG_API_HASH and
TG_SESSION were absent during setup; no account credentials were requested or
used, and no Telegram account messages were sent.

## Deliberate limitations

This is an experimental alpha, not full Telethon/Kurigram parity. It lacks an
independent security audit, automatic reconnect and update-state gap recovery,
HTML/Markdown parsing, CDN downloads, file-reference refresh, alternate/proxied
transports, signup and extra email/paid verification flows. Read README.md for
supported APIs and compatibility changes.

Before treating it as production-ready, validate real test-account login and 2FA,
Saved Messages actions, scheduled messages, upload/download and albums, entity
resolution, event handling, migration and failure recovery on a machine that can
reach Telegram MTProto. An independent cryptographic/protocol review is still
needed. Publishing a cloud snapshot or building the wheel does not perform these
checks.
