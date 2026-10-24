"""Stage A: real Client/media pipeline over an explicitly simulated RPC peer."""
import asyncio
import hashlib
from pathlib import Path

import pytest

from easyproto import Client, FloodWaitError, TLObject, types
from easyproto.media import PART_SIZE
from integration.validate import Config, ScopeError, private_session_path, relay_once


class AuthorizedPeer:
    def __init__(self, data):
        self.data = data
        self.parts = {}
        self.messages = {7: self.message(7, 10, len(data))}
        self.files = {10: data}
        self.calls = []
        self.closed = asyncio.Event()
        self.active = self.peak = 0
        self.block = False
        self.ready = asyncio.Event()
        self.failure = None

    @staticmethod
    def message(identifier, doc_id, size):
        return TLObject('message', id=identifier, peer_id=types.peerChat(chat_id=12),
            media=TLObject('messageMediaDocument', document=TLObject('document',
                id=doc_id, access_hash=2, file_reference=b'fixture', dc_id=2, size=size,
                attributes=[types.documentAttributeFilename(file_name='fixture.bin')])) )

    async def invoke(self, request):
        self.calls.append(request)
        if request.name == 'messages.getMessages':
            return TLObject('messages.messages', messages=[self.messages[i.id] for i in request.id])
        if request.name.startswith('upload.'):
            self.active += 1
            self.peak = max(self.peak, self.active)
            self.ready.set()
            try:
                if self.failure:
                    raise self.failure
                if self.block:
                    await asyncio.Event().wait()
                await asyncio.sleep(0.001)
                if request.name == 'upload.getFile':
                    data = self.files[request.location.id]
                    return TLObject('upload.file', bytes=data[request.offset:request.offset + request.limit])
                self.parts.setdefault(request.file_id, {})[request.file_part] = request.bytes
                return True
            finally:
                self.active -= 1
        if request.name == 'messages.sendMedia':
            file = request.media.file
            data = b''.join(self.parts[file.id][i] for i in range(file.parts))
            assert hashlib.md5(data).hexdigest() == file.md5_checksum
            self.files[20] = data
            self.messages[8] = self.message(8, 20, len(data))
            return TLObject('updateShortSentMessage', id=8, date=1, out=True)
        raise AssertionError(request.name)


def setup(data):
    peer = AuthorizedPeer(data)
    client = Client(12345, 'offline-placeholder', session=':memory:')
    client._connection = peer
    client._cache_result(TLObject('chat', id=12))
    config = Config(-12, -12, expected_sha256=hashlib.sha256(data).hexdigest(), source_message_id=7)
    return client, peer, config


def assert_drained(peer, temporary_root):
    assert peer.active == 0
    assert not any(t.get_name() == 'easyproto-transfer' and not t.done() for t in asyncio.all_tasks())
    assert not list(temporary_root.glob('easyproto-relay-*'))


@pytest.mark.parametrize('workers', [1, 2, 4])
async def test_authorized_relay_sha256_and_cleanup(tmp_path, monkeypatch, capsys, workers):
    import integration.validate as harness
    monkeypatch.setattr(harness.tempfile, 'tempdir', str(tmp_path))
    data = bytes(range(256)) * (3 * PART_SIZE // 256) + b'end'
    client, peer, config = setup(data)
    await relay_once(client, config, workers)
    assert peer.files[20] == data
    assert peer.peak == workers
    assert_drained(peer, tmp_path)
    output = capsys.readouterr().out
    assert 'sha256_matched' in output
    assert 'fixture' not in output and 'offline-placeholder' not in output


@pytest.mark.parametrize('restriction', ['chat_protected', 'message_protected', 'expiring', 'wrong_chat', 'oversize'])
async def test_unsafe_source_rejected_before_transfer(restriction):
    client, peer, config = setup(b'fixture')
    raw = peer.messages[7]
    if restriction == 'chat_protected': client._entities[-12].fields['noforwards'] = True
    if restriction == 'message_protected': raw.fields['noforwards'] = True
    if restriction == 'expiring': raw.media.fields['ttl_seconds'] = 10
    if restriction == 'wrong_chat': raw.fields['peer_id'] = types.peerChat(chat_id=99)
    if restriction == 'oversize': raw.media.document.fields['size'] = config.max_bytes + 1
    with pytest.raises(ScopeError):
        await relay_once(client, config)
    assert not any(r.name.startswith('upload.') for r in peer.calls)


async def test_bad_hash_prevents_any_upload(tmp_path, monkeypatch):
    import integration.validate as harness
    monkeypatch.setattr(harness.tempfile, 'tempdir', str(tmp_path))
    client, peer, config = setup(b'fixture')
    bad = Config(config.source, config.destination, source_message_id=7, expected_sha256='0' * 64)
    with pytest.raises(ScopeError, match='integrity'):
        await relay_once(client, bad)
    assert not peer.parts
    assert_drained(peer, tmp_path)


async def test_flood_wait_is_reported_without_retry_or_upload(tmp_path, monkeypatch, capsys):
    import integration.validate as harness
    monkeypatch.setattr(harness.tempfile, 'tempdir', str(tmp_path))
    client, peer, config = setup(b'fixture')
    peer.failure = FloodWaitError(420, 'FLOOD_WAIT_60', 60)
    with pytest.raises(FloodWaitError):
        await relay_once(client, config)
    assert sum(r.name == 'upload.getFile' for r in peer.calls) == 1
    assert not peer.parts
    assert '"flood_wait_seconds": 60' in capsys.readouterr().out
    assert_drained(peer, tmp_path)


async def test_relay_cancellation_drains_workers_and_temporary_directory(tmp_path, monkeypatch):
    import integration.validate as harness
    monkeypatch.setattr(harness.tempfile, 'tempdir', str(tmp_path))
    client, peer, config = setup(b'x' * (4 * PART_SIZE))
    peer.block = True
    task = asyncio.create_task(relay_once(client, config, 4))
    await asyncio.wait_for(peer.ready.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not peer.parts
    assert_drained(peer, tmp_path)


def test_configuration_requires_explicit_authorized_scope(monkeypatch):
    monkeypatch.delenv('TG_AUTHORIZED_TEST', raising=False)
    with pytest.raises(ScopeError): Config.from_env(workflow=True)
    monkeypatch.setenv('TG_AUTHORIZED_TEST', '1')
    monkeypatch.setenv('TG_TEST_CHAT', '-12')
    monkeypatch.delenv('TG_SOURCE_MESSAGE_ID', raising=False)
    with pytest.raises(ScopeError): Config.from_env(workflow=True)
    monkeypatch.setenv('TG_SOURCE_MESSAGE_ID', '7')
    monkeypatch.setenv('TG_EXPECTED_SHA256', 'a' * 64)
    assert Config.from_env(workflow=True).source == -12


def test_sessions_must_be_private_and_outside_checkout(tmp_path, monkeypatch):
    from integration.validate import ROOT
    monkeypatch.setenv('TG_SESSION', str(ROOT / 'account'))
    with pytest.raises(ScopeError): private_session_path()
    directory = tmp_path / 'private'; directory.mkdir(mode=0o700)
    monkeypatch.setenv('TG_SESSION', str(directory / 'account'))
    assert private_session_path() == directory / 'account'
    directory.chmod(0o755)
    with pytest.raises(ScopeError): private_session_path()
