"""Offline latency model and crypto microbenchmark; never contacts Telegram.

Run with: uv run --extra fast python examples/benchmark_transfers.py
These results are not Telegram throughput measurements or a network speed claim.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import tempfile
import time
from pathlib import Path

from easyproto import Client, TLObject
from easyproto import crypto


class LatencyPeer:
    def __init__(self, data, latency):
        self.data, self.latency = data, latency
        self.parts = {}
        self.active = self.peak = 0

    async def invoke(self, request):
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            await asyncio.sleep(self.latency)
            if request.name.startswith('upload.save'):
                self.parts[request.file_part] = request.bytes
                return True
            return TLObject('upload.file',bytes=self.data[request.offset:request.offset+request.limit])
        finally:
            self.active -= 1


async def run(size_mib, latency_ms, workers):
    data = bytes(range(256)) * (size_mib*1024*1024//256)
    expected = hashlib.sha256(data).digest()
    results = []
    with tempfile.TemporaryDirectory(prefix='easyproto-benchmark-') as folder:
        source = Path(folder)/'source'; source.write_bytes(data)
        media = TLObject('messageMediaDocument',document=TLObject('document',id=1,
            access_hash=2,file_reference=b'test',size=len(data),dc_id=2,attributes=[]))
        for count in workers:
            peer = LatencyPeer(data, latency_ms/1000)
            client = Client(12345,'offline-test',session=':memory:',transfer_workers=count)
            client._connection = peer
            start = time.perf_counter()
            await client.upload(source)
            upload_seconds = time.perf_counter()-start
            uploaded = b''.join(peer.parts[i] for i in sorted(peer.parts))
            assert hashlib.sha256(uploaded).digest() == expected
            start = time.perf_counter()
            path = await client.download(media,Path(folder)/f'download-{count}')
            download_seconds = time.perf_counter()-start
            assert hashlib.sha256(path.read_bytes()).digest() == expected
            results.append({'workers':count,'peak_inflight':peer.peak,
                'upload_seconds':round(upload_seconds,4),
                'download_seconds':round(download_seconds,4)})
    # Both implementations encrypt the same non-secret synthetic block.
    block = data[:512*1024]
    key,iv = bytes(range(32)),bytes(range(32,64))
    start = time.perf_counter()
    expected_cipher = crypto._aes_ige_python(block,key,iv)
    python_seconds = time.perf_counter()-start
    start = time.perf_counter()
    actual_cipher = crypto.aes_ige(block,key,iv)
    selected_seconds = time.perf_counter()-start
    assert actual_cipher == expected_cipher
    return {'kind':'offline simulated RPC latency; excludes real transport/encryption',
        'size_mib':size_mib,'latency_ms':latency_ms,'transfers':results,
        'crypto_microbenchmark':{'backend':crypto.AES_IGE_BACKEND,
            'size_bytes':len(block),'python_seconds':round(python_seconds,6),
            'selected_seconds':round(selected_seconds,6)},
        'telegram_speed':'unmeasured; requires a live account and MTProto connectivity'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--size-mib',type=int,default=8)
    parser.add_argument('--latency-ms',type=float,default=40)
    parser.add_argument('--workers',type=int,nargs='+',default=[1,4])
    args = parser.parse_args()
    if not 1 <= args.size_mib <= 256 or not 0 <= args.latency_ms <= 1000:
        parser.error('size must be 1–256 MiB; latency must be 0–1000 ms')
    if any(not 1 <= n <= 16 for n in args.workers):
        parser.error('workers must be 1–16')
    print(json.dumps(asyncio.run(run(args.size_mib,args.latency_ms,args.workers)),indent=2))
