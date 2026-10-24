# Transfer performance: controlled local measurements

EasyProto 0.2.0a2, Python 3.12.14, cryptg 0.6.0 in the current cloud machine.
These measurements are one illustrative run, not a statistically controlled
Telegram benchmark or a comparison against Telethon/Kurigram.

## Pipeline benchmark

Command:

```sh
uv run --extra fast python examples/benchmark_transfers.py --size-mib 8 --latency-ms 40 --workers 1 4
```

The peer is an in-process simulation that sleeps 40 ms per RPC. The actual
upload/download pipeline reads and writes real temporary files and verifies their
SHA-256 digests. Network transport, MTProto encryption, account/DC throttling and
Telegram storage performance are excluded from this part of the benchmark.

| Workers | Peak in-flight RPCs | Upload, 8 MiB | Download, 8 MiB |
|---|---|---|---|
| 1 | 1 | 0.6903 seconds | 0.6918 seconds |
| 4 | 4 | 0.1863 seconds | 0.1787 seconds |

Four workers completed this simulated upload about 3.7 times sooner and download
about 3.9 times sooner. The result demonstrates overlapping RPC waiting rather
than a measured increase in Internet or Telegram throughput. Memory use is
bounded by the transfer worker/queue counts, not total file size.

## Separate encryption microbenchmark

The same script encrypts one synthetic 512 KiB block, checks byte-for-byte equality
between the independent Python AES-IGE implementation and the selected native
backend, and records elapsed wall time:

| AES-IGE implementation | 512 KiB encryption |
|---|---|
| Independent Python block loop | 0.179065 seconds |
| cryptg native backend | 0.001894 seconds |

This run shows reduced local encryption overhead; it is not a file-transfer speed
multiplier. Known-answer tests also compare both implementations to an independently
computed OpenSSL AES-256-IGE vector. All MTProto message authentication and integrity
checks are retained.

## Still unmeasured

Real Telegram upload/download throughput, actual account limits and comparative
Telethon/Kurigram speeds. The cloud previously refused the Telegram test DC TCP
connection, and no live account credentials were used. Benchmark actual files on
a reachable machine before choosing a worker count above the default four.

## Validation rerun, 2026-10-24

Same existing latency simulation, Python 3.12.14, cryptg 0.6.0, Linux cloud machine:

```sh
.venv/bin/python examples/benchmark_transfers.py --size-mib 8 --latency-ms 40 --workers 1 2 4
```

| Chunk workers | Peak simulated in-flight RPCs | Upload seconds | Download seconds |
|---|---|---|---|
| 1 | 1 | 0.6721 | 0.6580 |
| 2 | 2 | 0.3317 | 0.3360 |
| 4 | 4 | 0.1687 | 0.1713 |

All simulated transfers matched SHA-256. The separate 512 KiB encryption run took
0.149220 seconds in the Python implementation and 0.001162 seconds with cryptg,
with identical ciphertext. These are one-run local timings, excluding Telegram
networking, transport encryption in the transfer simulation, and account limits.
They must not be described as Telegram throughput or a client comparison.

No live transfer duration, speed, error rate, FloodWait frequency, CPU or memory
measurements are available. The opt-in [harness](integration/README.md) can record
those on a machine with credentials and reachable MTProto TCP; its documented
metrics include process CPU/RSS and observed transfer errors, with uninstrumented
internal library retry counts explicitly null.
