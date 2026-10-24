# EasyProto validation: 2026-10-24

## Decision

The library supports offline development and passes its local checks. It is
**not yet established as reliable for a production Save Restricted Content Bot**.
No live Telegram account operation or end-to-end bot workflow was verified in
this environment. Passing protocol/unit tests does not establish live compatibility.

Baseline repository: `spycoderspro/telegram-lib`, `main` at
`80dcb34b0d39e11f1139bb297b6c8fc8986993d9` (two commits inspected). Validation was
completed on `validation/save-restricted-workflow` before committing or pushing
the changes. No merge, history rewrite, credential use or Telegram account
mutation occurred during validation.
The initially provisioned `spycoderspro/save-restricted-test` checkout is retained
unchanged; the existing EasyProto repository was cloned from its original remote.

## Current-instance results

Linux, Python 3.12.14, PyCryptodome 4.1.0, cryptg 0.6.0, pytest 9.1.1,
pytest-asyncio 1.4.0, uv 0.12.23. Dependencies installed from `uv.lock` using frozen
sync. Telethon and Pyrogram are absent. Dependency declarations and lockfile were
not changed. No schemas, pinned keys, checksums or TLS verification were altered.

| Check | Result | Scope |
|---|---|---|
| Original tests, before changes | 105 passed | Offline only |
| Expanded tests and harness, fast extra | 127 passed, 2 skipped | 114 library checks + 13 offline harness checks; 2 live stages skipped |
| Installed rebuilt wheel, fast extra | 127 passed, 2 skipped | Separate environment, tests from new source archive |
| Installed rebuilt wheel, base dependencies | 124 passed, 5 skipped | Same checks; 3 optional cryptg tests + 2 live stages skipped |
| Wheel and source distribution build | Passed | Outputs outside tracked `dist/`; integration instructions/tests included in source archive |
| Production DC 2, `149.154.167.51:443` | TCP refused, errno 111 | Failed before MTProto exchange |
| Test DC 2, `149.154.167.40:443` | TCP refused, errno 111 | Failed before MTProto exchange |
| Login / `me()` / private history / sending | Unverified | No credentials/session and no working TCP transport |
| Live upload/download / SHA-256 / reconnect | Unverified | No live transfer ran |
| Live authorized relay/bot workflow | Unverified | Offline worker simulation only |
| Real transfer throughput / resource usage / FloodWait rate | Unmeasured | Local simulation is recorded separately in BENCHMARKS.md |

The two live tests were skipped by default (`TG_RUN_LIVE` was not enabled).
Independent connectivity probes failed as above. `TG_API_ID`, `TG_API_HASH`,
`TG_SESSION` and bot credentials were absent from the running process and saved
configuration. Account operations were not attempted. No secret values were
printed, requested in chat, embedded in code or saved in setup instructions.

Raw XML reports, build logs, wheel/sdist and simulated benchmark output are in
`/workspace/validation-results/` on this machine. They are local artifacts, not
committed evidence or proof of restoration in a new task.

## Implementation and offline evidence

This is `easyproto-actions` 0.2.0a2, package `easyproto`, an independent asynchronous
MTProto 2.0 client. Python 3.10+ is required; `pycryptodome==4.1.0` is the only base
runtime dependency. Optional `cryptg==0.6.0` is enabled on Python 3.11+. Dev and
transitive resolutions are pinned in `uv.lock`. Old 0.1.0 artifacts in `dist/` use
a different, Telethon-based implementation and were not installed or overwritten.

README, manifests/lockfile, validation/benchmark reports, third-party notices,
all Python implementation files, examples, tests and both Git commits were
inspected. The vendored official Telegram schemas are layer 232, with source
provenance and SHA-256 checked by tests. All 2,628 registered declarations undergo
synthetic encode/decode checks. This does not test every real payload or account API.

Implemented convenience APIs include user-account login/code/SRP 2FA, `me`,
entity resolution, send/reply/edit/delete/forward, raw schema calls,
history/search/dialogs, read/react/join/leave/profile, event handlers and
upload/download/media/albums. Their existence in source is distinct from verified
live behavior. Bot-token authorization is not implemented. The relay harness
exercises the user-account client portion only, not a running public bot service.

Offline coverage includes:

- Generated-RSA local auth-key negotiation and independent SRP proof checks;
  tampered nonce, key fingerprint, checksum and confirmation are rejected.
- AES-IGE known-answer/equivalence checks, MTProto authentication and key-ID checks,
  replay/time windows, frames, gzip/nesting/vector limits, and schema provenance.
- Actual loopback encrypted TCP requests, containers, compressed vector replies,
  acknowledgements and four multiplexed requests with reversed responses.
- Private atomic session persistence, permissions, locking, environment separation,
  reloading after lock acquisition, and releasing a lock after refresh failure.
- Error parsing, bounded FloodWait retry with the same random ID, account migration
  export/import and lock preservation, file migration refusal as account migration,
  and cleanup after failed cross-DC authorization.
- No replay after unknown network outcomes; timeout/cancellation removes pending
  RPCs. Malformed compressed RPC replies complete with a protocol error.
- Bounded upload read-ahead, part numbering/MD5/big-file totals, source mutation
  detection, offset-based download integrity, out-of-order replies, atomic
  destination preservation and worker/thread cleanup under repeated cancellation.
- Simulated authorized one-message relay with workers 1, 2 and 4, SHA-256 at both
  ends, protection/chat/expiration/size checks, source-hash mismatch refusal,
  FloodWait abort, cancellation, temporary-directory cleanup and safe session paths.

## Verified bugs fixed

1. **Malformed compressed RPC reply left its caller pending.** `_handle()` removed
   the request before decompression, but decompression was outside the block that
   sets an exception on its future. The new regression failed on the baseline.
   Decompression/result-type resolution now run inside that block, so errors reach
   the caller immediately and pending state is removed. Validation/authentication
   was not relaxed.
2. **Session snapshot could be stale after waiting for another owner.** A Client
   loads its session at construction, before acquiring the session lock. Another
   process could complete login or migration before it opens the connection; the
   stale client would use an old/empty key. A new regression failed on the baseline.
   `_open()` now reloads the persisted session while holding the lock, transfers
   lock ownership, and releases it on refresh failure. No public signature changed.

## Credential hygiene and legacy artifact

The tracked `_memory_.session` is a legacy SQLite session database. Inspection of
counts only found one session row with **zero nonempty auth keys**; entity,
sent-file and update-state tables were empty. It was never used to authenticate.
A pattern scan of all 51 unique blobs in both Git commits and nested committed
wheel/source archives found no matching bot tokens, literal API hashes, private
keys or populated JSON authorization keys. This limited scan is not proof that all
possible secret encodings are absent; test-generated RSA keys are synthetic.

Keeping session databases in Git creates a future exposure risk even though this
one is empty. Recommended hygiene: remove the legacy artifact from tracking in a
separate cleanup change and continue ignoring all session files. No history was
rewritten or existing artifact removed here. If a session with a real authorization
key was ever published elsewhere, revoke it through Telegram's active-session
controls; deleting a file or commit alone does not invalidate the key. Rotate any
other actually exposed credentials through their issuing service.

## Remaining limitations and risks

- No live permanent-key exchange, login/2FA, account RPC, event stream, DC migration,
  cross-DC authorization or media transfer has passed. Cryptographic/protocol code
  has not received an independent security audit.
- Direct IPv4 MTProto TCP only; no MTProxy, SOCKS, HTTP/WebSocket or obfuscated
  transport. HTTPS allowlists/proxy secrets do not provide that capability.
- No automatic reconnect, unknown-outcome mutation replay, durable events or
  update-state gap recovery. Reconnect explicitly and reconcile account history.
- CDN downloads, expired file-reference refresh, signup and extra email/paid login
  flows are unsupported. Entity/access-hash caches are in memory.
- No upload/download progress callback API. Native cancellation has offline
  coverage; a best-effort live cancellation probe remains unrun.
- The harness runs one file at a time with 1/2/4 chunk workers on one connection.
  Simultaneous independent whole-file workloads and concurrent account migration
  have not been validated. Worker count should be chosen from safe live measurements.
- Harness retries are zero; it aborts on FloodWait or uncertain mutation outcome.
  Internal library migration retry counts are not instrumented and are reported
  as null, not fabricated as zero. CPU/RSS metrics are Linux process-level values.

## Reproduce

Run from `/workspace/telegram-lib`:

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv sync --frozen --extra dev --extra fast
.venv/bin/python -m pytest -q tests integration -rs --junitxml=/workspace/validation-results/full-fast.xml
.venv/bin/python examples/benchmark_transfers.py --size-mib 8 --latency-ms 40 --workers 1 2 4
UV_CACHE_DIR=/workspace/.cache/uv .venv/bin/python -m build --installer uv --outdir /workspace/validation-results/dist
.venv/bin/python -m integration.validate --stage preflight
TG_TEST_MODE=1 .venv/bin/python -m integration.validate --stage preflight
```

The last two commands currently exit 1 because TCP is refused; that is not an
account test failure or a passing Telegram check. The confirmed bug reproductions
were:

```sh
.venv/bin/python -m pytest -q tests/test_connection.py::test_malformed_compressed_rpc_completes_pending_with_protocol_error
.venv/bin/python -m pytest -q tests/test_client.py::test_open_reloads_session_after_acquiring_lock
```

Each first failed on the unfixed implementation and passed after its fix.
The installed-wheel checks used hash-pinned `uv export --frozen --extra dev`
requirements, separate virtual environments, and tests from the freshly built
source archive. Adding the `fast` extra supplied cryptg for its additional three
checks. See [integration/README.md](integration/README.md) for secure live setup,
explicit login, account tests and the allowlisted relay. Do not run those stages
against third-party or protected content.

Environment setup/start instructions are saved for offline development. Saving a
configuration draft is separate from publication and validation in a new task;
neither establishes live Telegram readiness.
