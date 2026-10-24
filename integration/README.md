# Staged validation of the EasyProto client layer

This harness imports `easyproto.Client` from the existing implementation. It
contains no Telethon/Pyrogram dependency and no alternative Telegram client.
The one-shot relay is a minimal client-layer worker, not a deployed bot, a bot-token
login implementation, or a service accepting arbitrary Telegram links.

## Stage A: offline, no credentials and no Telegram access

From the repository root, using Python 3.10+ (tested here on Linux/Python 3.12.14):

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen --extra dev --extra fast
.venv/bin/python -m pytest -q tests integration -rs
.venv/bin/python examples/benchmark_transfers.py --size-mib 8 --latency-ms 40 --workers 1 2 4
```

The real Client, serialization and transfer pipeline run against simulated RPCs.
Checks cover allowed-chat selection, protected/expiring content refusal, SHA-256
at source and destination, worker concurrency, hash mismatch, FloodWait (abort,
no automatic retry), cancellation, temporary-file cleanup, and session location.
The main suite covers authentication, SRP, encryption, schema provenance, actual
loopback TCP, migration routing, timeouts, and session locking. Local protocol
peers and mock responses do not establish Telegram compatibility.

Default pytest discovery targets `tests/`; include `integration` explicitly.
`integration/test_live.py` skips both live stages unless `TG_RUN_LIVE=1` is set.
A credential or connectivity skip is unverified, never a pass. Live tests are not
invoked by the saved cloud installation/startup instructions.

## Stages B and C: opt-in on a machine with direct Telegram TCP

The present cloud machine refuses direct TCP to production and test DC 2.
EasyProto uses MTProto TCP to numeric DC addresses on port 443, not HTTPS.
Allowing an HTTPS domain or configuring an HTTPS placeholder secret cannot
supply a native TCP transport or usable local MTProto credentials. No proxy
transport was added. Use an authorized machine with this required connectivity.

Provide your own `TG_API_ID` and `TG_API_HASH` through secure local configuration;
never put their values in source control, command history, logs, or chat. The
harness reads them from the process environment. Existing legacy Telethon session
files cannot be used. No existing session was opened during validation.

Configure these non-secret controls in your local shell:

```sh
install -d -m 700 "$HOME/.local/share/easyproto-validation"
export TG_SESSION="$HOME/.local/share/easyproto-validation/account"
export TG_AUTHORIZED_TEST=1
export TG_TEST_CHAT=me
# Optional: a username or cached signed numeric ID of another test chat you control.
# TG_DESTINATION defaults to me; select only a destination you control.
# TG_TEST_MODE=1 selects Telegram's test network and requires its own session.
```

Use a separate account/session for testing, with an absolute session path outside
the checkout and a private parent directory. The harness rejects checkout-local
sessions. For numeric IDs, resolve/cache the entity in the same client lifecycle;
a fresh client does not restore the library's in-memory access-hash cache. A
username or `me` is simplest. This harness does not invite users or join chats.

Check connectivity before authenticating:

```sh
.venv/bin/python -m integration.validate --stage preflight
```

Preflight sends only an anonymous `req_pq_multi` if TCP is available. A matching
`resPQ` verifies that exchange only, not authentication, encryption or account RPCs.
First login is a separate explicit command, with hidden terminal prompts for
phone, login code and optional 2FA password:

```sh
.venv/bin/python -m integration.validate --stage login
.venv/bin/python -m integration.validate --stage live --workers 1 2 4
```

`live` uses an already-authorized session through `connect()`; it never silently
prompts. It verifies `me()`, reads up to three history messages from `TG_TEST_CHAT`
(logging counts only), sends one harmless message to Saved Messages, and uploads
and downloads the same synthetic 2 MiB + 11-byte document with 1/2/4 chunk workers.
It checks SHA-256 after each round trip and explicitly closes/reconnects the
session. A best-effort download cancellation checks destination preservation and
cleanup; if the operation already finished, cancellation is reported unverified.
Automatic reconnection is unsupported. Progress callbacks are unsupported and
reported as such. Test messages/files remain in the controlled destination for
inspection; cleanup in Telegram is manual.

For Stage C, put one small, non-expiring, unprotected document in the authorized
source chat. Set `TG_SOURCE_MESSAGE_ID` to that message's ID and
`TG_EXPECTED_SHA256` to the original local file's known SHA-256. Set
`TG_DESTINATION` to a destination you control, or leave it as `me`:

```sh
.venv/bin/python -m integration.validate --stage workflow --workers 1 2 4
```

Only that one selected message is fetched. The worker checks the source chat,
message ID, chat/message protection flags, document size and expiration. It
refuses protected content and never attempts a forwarding/download workaround.
It downloads, checks the known hash before uploading, fetches the stored
destination message, downloads again, and checks the hash. Each worker setting
copies that same fixture once. The default maximum source size is 8 MiB;
`TG_MAX_FILE_BYTES` may set a limit of 1 byte through 16 MiB. Unknown permissions
or server refusals abort; there is no fallback to another account or client.

Alternatively, after explicit login, opt in to the two pytest live tests:

```sh
TG_RUN_LIVE=1 .venv/bin/python -m pytest -q integration/test_live.py -rs
```

The account test needs credentials, session and test chat. The relay test also
needs the selected message and known source hash. Missing prerequisites skip;
authentication, integrity and RPC errors after prerequisites fail the tests.

## Measurement and privacy

Live transfer JSON reports operation, workers, bytes, elapsed seconds, decimal
MB/s (1 MB = 1,000,000 bytes), process CPU seconds and Linux process peak RSS in
KiB. RSS is the process lifetime high-water mark, not isolated per-transfer memory
or a sampled time series. Hashing occurs outside transfer timing; media upload
timing includes sending the document and its account RPC. Workers pipeline chunks
on one connection; these runs do not measure multiple simultaneous whole files.

Errors log exception class and FloodWait seconds, never raw exception messages,
message text, file contents, peer IDs, API hashes, session keys or login codes.
FloodWait aborts and is counted; there is no automatic harness retry or account
hammering. Summaries report failed/attempted transfers (including cancellations)
and observed FloodWait count. `harness_retry_count` is zero; internal library
migration retries are not instrumented, so `library_retry_count` is null. Do not
interpret it as zero internal retries. No live metrics were collected here.

A timeout after a mutation leaves the result unknown. Inspect the controlled
chat/account state before retrying; the harness does not replay it. Source and
destination test messages are not automatically deleted. Local working files use
private temporary directories and are removed on success/error/cancellation.
