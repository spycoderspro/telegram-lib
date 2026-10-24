import asyncio
import hashlib
import os
import threading
from pathlib import Path

import pytest

from easyproto import Client, TLObject
from easyproto.errors import RPCError
from easyproto.media import PART_SIZE


class FilePeer:
    def __init__(self, data=b'', target=1):
        self.data, self.target = data, target
        self.active = self.peak = 0
        self.ready = asyncio.Event()
        self.calls, self.completed, self.parts = [], [], {}

    async def invoke(self, request):
        self.calls.append(request)
        if request.name == 'messages.sendMedia':
            return TLObject('updateShortSentMessage', id=7, date=1, out=True)
        self.active += 1
        self.peak = max(self.peak, self.active)
        if self.active >= self.target: self.ready.set()
        try:
            await asyncio.wait_for(self.ready.wait(), 3)
            index = request.file_part if request.name.startswith('upload.save') else request.offset // PART_SIZE
            if index == 0: await asyncio.sleep(0.01)
            self.completed.append(index)
            if request.name.startswith('upload.save'):
                self.parts[index] = request.bytes
                return True
            return TLObject('upload.file', bytes=self.data[request.offset:request.offset+request.limit])
        finally:
            self.active -= 1


def make_client(peer, workers=4):
    client = Client(12345, 'test-hash', session=':memory:', transfer_workers=workers)
    client._connection = peer
    return client


def document(data):
    return TLObject('messageMediaDocument', document=TLObject('document', id=1,
        access_hash=2, file_reference=b'ref', size=len(data), dc_id=2, attributes=[]))


def no_transfer_tasks():
    assert not any(t.get_name() == 'easyproto-transfer' and not t.done() for t in asyncio.all_tasks())


async def test_upload_overlaps_but_keeps_part_numbers_and_md5(tmp_path):
    data = b''.join(bytes([i])*PART_SIZE for i in range(6)) + b'final bytes'
    path = tmp_path/'source'; path.write_bytes(data)
    peer = FilePeer(target=3)
    result = await make_client(peer).upload(path, workers=3)
    assert peer.peak == 3 and peer.active == 0
    assert peer.completed[0] != 0
    assert b''.join(peer.parts[i] for i in sorted(peer.parts)) == data
    assert result.parts == 7 and result.md5_checksum == hashlib.md5(data).hexdigest()
    assert len({r.file_id for r in peer.calls}) == 1
    no_transfer_tasks()


async def test_big_upload_uses_total_parts_and_no_small_file_checksum(tmp_path):
    data = b'z'*(10*1024*1024+1)
    path = tmp_path/'big'; path.write_bytes(data)
    peer = FilePeer(target=4)
    result = await make_client(peer).upload(path)
    assert peer.peak == 4 and result.name == 'inputFileBig'
    assert result.parts == 21
    assert all(r.name == 'upload.saveBigFilePart' and r.file_total_parts == 21 for r in peer.calls)
    assert b''.join(peer.parts[i] for i in range(21)) == data


async def test_download_reassembles_out_of_order_responses(tmp_path):
    data = b''.join(bytes([i])*PART_SIZE for i in range(5)) + b'tail'
    peer = FilePeer(data, target=3)
    output = await make_client(peer).download(document(data), tmp_path/'output', workers=3)
    assert output.read_bytes() == data
    assert peer.peak == 3 and peer.completed[0] != 0
    assert sorted(r.offset for r in peer.calls) == list(range(0, len(data), PART_SIZE))
    assert all(r.limit == PART_SIZE for r in peer.calls)
    assert not list(tmp_path.glob('.easyproto-download-*'))
    no_transfer_tasks()


async def test_single_worker_remains_available(tmp_path):
    data = b'a'*(2*PART_SIZE+1)
    path = tmp_path/'input'; path.write_bytes(data)
    peer = FilePeer(data)
    client = make_client(peer, workers=1)
    await client.upload(path)
    await client.download(document(data), tmp_path/'output')
    assert peer.peak == 1
    assert (tmp_path/'output').read_bytes() == data


async def test_media_consumes_worker_option_without_sending_it_to_tl(tmp_path):
    path = tmp_path/'input'; path.write_bytes(b'a'*(3*PART_SIZE))
    peer = FilePeer(target=3)
    result = await make_client(peer).media('me', path, workers=3)
    assert result.id == 7 and peer.peak == 3
    assert peer.calls[-1].name == 'messages.sendMedia'
    assert 'workers' not in peer.calls[-1].fields


@pytest.mark.parametrize('bad', [0,-1,17,True,1.5,'4'])
async def test_invalid_worker_counts_fail_before_io(tmp_path, bad):
    with pytest.raises(ValueError): make_client(FilePeer(), workers=bad)
    client = make_client(FilePeer())
    with pytest.raises(ValueError): await client.upload(tmp_path/'missing', workers=bad)
    with pytest.raises(ValueError): await client.download(document(b''), tmp_path/'out', workers=bad)
    assert not list(tmp_path.iterdir())


async def test_short_download_never_publishes_or_overwrites(tmp_path):
    data = b'a'*(2*PART_SIZE+1)
    peer = FilePeer(b'partial')
    output = tmp_path/'output'; output.write_bytes(b'original')
    with pytest.raises(OSError, match='size'):
        await make_client(peer).download(document(data), output)
    assert output.read_bytes() == b'original' and peer.active == 0
    assert not list(tmp_path.glob('.easyproto-download-*'))
    no_transfer_tasks()


async def test_failure_cancels_all_other_workers(tmp_path):
    peer = FilePeer(bytes(4*PART_SIZE), target=3)
    original = peer.invoke
    async def invoke(request):
        if request.offset == PART_SIZE:
            await asyncio.sleep(0)
            raise RPCError(420,'FLOOD_WAIT_30')
        return await original(request)
    peer.invoke = invoke
    with pytest.raises(RPCError):
        await make_client(peer).download(document(bytes(4*PART_SIZE)), tmp_path/'out')
    assert peer.active == 0 and not (tmp_path/'out').exists()
    assert not list(tmp_path.glob('.easyproto-download-*'))
    no_transfer_tasks()


async def test_cancel_download_drains_workers_and_removes_partial_file(tmp_path):
    active = 0
    ready = asyncio.Event()
    class BlockedPeer:
        async def invoke(self, request):
            nonlocal active
            active += 1
            if active == 3: ready.set()
            try: await asyncio.Event().wait()
            finally: active -= 1
    client = make_client(BlockedPeer())
    task = asyncio.create_task(client.download(document(bytes(4*PART_SIZE)), tmp_path/'out', workers=3))
    await asyncio.wait_for(ready.wait(), 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert active == 0 and not (tmp_path/'out').exists()
    assert not list(tmp_path.glob('.easyproto-download-*'))
    no_transfer_tasks()


async def test_cancellation_waits_for_disk_thread_before_closing_file(tmp_path, monkeypatch):
    import easyproto.media as media
    entered, release = threading.Event(), threading.Event()
    closed_while_writing = []
    original = media._write_at
    def slow_write(stream, offset, data):
        entered.set()
        assert release.wait(3)
        closed_while_writing.append(stream.closed)
        return original(stream, offset, data)
    monkeypatch.setattr(media,'_write_at',slow_write)
    output = tmp_path/'out'; output.write_bytes(b'original')
    task = asyncio.create_task(make_client(FilePeer(b'hello')).download(document(b'hello'), output))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(entered.wait,3),4)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()  # Repeated cancellation must not abandon the I/O thread.
        assert not task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError): await task
    assert closed_while_writing == [False]
    assert output.read_bytes() == b'original'
    assert not list(tmp_path.glob('.easyproto-download-*'))
    no_transfer_tasks()


async def test_upload_queue_has_bounded_read_ahead_and_cancels(tmp_path, monkeypatch):
    path = tmp_path/'input'; path.write_bytes(bytes(30*PART_SIZE))
    opened = Path.open
    read_ahead = threading.Event()
    read_count = 0
    active = 0
    class CountingReader:
        def __init__(self): self.stream = opened(path, 'rb')
        def __enter__(self): return self
        def __exit__(self,*args): self.stream.close()
        def fileno(self): return self.stream.fileno()
        def read(self,size):
            nonlocal read_count
            read_count += 1
            if read_count == 7: read_ahead.set()
            return self.stream.read(size)
    class BlockedPeer:
        async def invoke(self, request):
            nonlocal active
            active += 1
            try: await asyncio.Event().wait()
            finally: active -= 1
    monkeypatch.setattr(Path,'open',lambda p,*a,**kw: CountingReader() if p==path and a==('rb',) else opened(p,*a,**kw))
    task = asyncio.create_task(make_client(BlockedPeer()).upload(path, workers=3))
    try:
        assert await asyncio.wait_for(asyncio.to_thread(read_ahead.wait,3),4)
        assert read_count == 7  # 3 in flight + 3 queued + 1 producer buffer.
        assert active == 3
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    assert active == 0
    no_transfer_tasks()


async def test_source_mutation_prevents_upload_completion(tmp_path):
    path = tmp_path/'input'; path.write_bytes(b'a'*(2*PART_SIZE+1))
    peer = FilePeer()
    original = peer.invoke
    async def invoke(request):
        if request.file_part == 0:
            info = path.stat()
            os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns+1000000))
        return await original(request)
    peer.invoke = invoke
    with pytest.raises(OSError, match='changed'):
        await make_client(peer).upload(path)
    assert peer.active == 0
    no_transfer_tasks()
