"""Opt-in EasyProto validation. Never logs message bodies, peers, or credentials."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import logging
import os
import resource
import secrets
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from easyproto import Client, FloodWaitError, Message, TLObject, functions, types
from easyproto.client import peer_id
from easyproto.session import PRODUCTION_DCS, TEST_DCS
from easyproto.tl import default_schema
from easyproto.transport import IntermediateTransport

ROOT = Path(__file__).resolve().parents[1]
COUNTERS = {'attempted_transfers': 0, 'failed_transfers': 0, 'flood_wait_count': 0}


class ScopeError(ValueError):
    """The selected source is outside the authorized test scope."""


def emit(event, **fields):
    print(json.dumps({'event': event, **fields}, sort_keys=True), flush=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class Config:
    source: str | int
    destination: str | int = 'me'
    max_bytes: int = 8 * 1024 * 1024
    source_message_id: int | None = None
    expected_sha256: str | None = None

    @classmethod
    def from_env(cls, workflow=False):
        if os.getenv('TG_AUTHORIZED_TEST') != '1':
            raise ScopeError('Set TG_AUTHORIZED_TEST=1 only for test chats you control or may use')
        source = os.environ.get('TG_TEST_CHAT')
        if not source:
            raise ScopeError('TG_TEST_CHAT is required')
        def peer(value):
            return int(value) if value.lstrip('-').isdigit() else value
        maximum = int(os.getenv('TG_MAX_FILE_BYTES', str(8 * 1024 * 1024)))
        if not 1 <= maximum <= 16 * 1024 * 1024:
            raise ScopeError('TG_MAX_FILE_BYTES must be 1 to 16777216')
        identifier = os.getenv('TG_SOURCE_MESSAGE_ID')
        expected = os.getenv('TG_EXPECTED_SHA256', '').lower()
        if workflow:
            if not identifier or int(identifier) <= 0:
                raise ScopeError('TG_SOURCE_MESSAGE_ID must identify one approved test message')
            if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
                raise ScopeError('TG_EXPECTED_SHA256 must be the known source file SHA-256')
        return cls(peer(source), peer(os.getenv('TG_DESTINATION', 'me')), maximum,
                   int(identifier) if identifier else None, expected or None)


def private_session_path():
    value = os.environ.get('TG_SESSION')
    if not value or value == ':memory:':
        raise ScopeError('TG_SESSION must be an absolute private session path outside the checkout')
    path = Path(value).expanduser()
    if not path.is_absolute() or path.resolve().is_relative_to(ROOT):
        raise ScopeError('Keep TG_SESSION outside the checkout at an absolute path')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.parent.stat().st_mode & 0o077:
        raise ScopeError('TG_SESSION parent directory must be private (mode 0700)')
    return path


def test_mode():
    return os.getenv('TG_TEST_MODE', '0') == '1'


def new_client():
    return Client.from_env(session=private_session_path(), test_mode=test_mode(),
                           timeout=15, flood_sleep_threshold=0, transfer_workers=1)


async def source_peer(client, source):
    peer = await client.resolve(source)
    if peer.name != 'inputPeerSelf':
        entity = await client.user(peer)
        if entity.get('noforwards'):
            raise ScopeError('Protected-content chats are excluded')
    return peer


async def approved_message(client, config):
    """Fetch one selected message, with no scanning or arbitrary user input."""
    peer = await source_peer(client, config.source)
    ids = [types.inputMessageID(id=config.source_message_id)]
    if peer.name == 'inputPeerChannel':
        result = await client.raw.channels.getMessages(
            channel=types.inputChannel(channel_id=peer.channel_id, access_hash=peer.access_hash), id=ids)
    else:
        result = await client.raw.messages.getMessages(id=ids)
    matches = [m for m in result.get('messages', [])
               if m.name == 'message' and m.id == config.source_message_id]
    if len(matches) != 1:
        raise ScopeError('Selected test message is unavailable')
    raw = matches[0]
    actual = raw.get('peer_id')
    expected_id = client.session.user_id if peer.name == 'inputPeerSelf' else peer_id(peer)
    if not isinstance(actual, TLObject) or peer_id(actual) != expected_id:
        raise ScopeError('Selected message is outside TG_TEST_CHAT')
    if raw.get('noforwards') or raw.get('ttl_period'):
        raise ScopeError('Protected or disappearing messages are excluded')
    media = raw.get('media')
    if not isinstance(media, TLObject) or media.name != 'messageMediaDocument' or media.get('ttl_seconds'):
        raise ScopeError('Use a non-expiring document fixture')
    doc = media.get('document')
    if not isinstance(doc, TLObject) or doc.name != 'document' or not 0 < doc.size <= config.max_bytes:
        raise ScopeError('Document exceeds the configured size limit or is empty')
    return Message(client, raw, config.source)


async def measured(operation, size, workers, function):
    COUNTERS['attempted_transfers'] += 1
    start, cpu = time.perf_counter(), time.process_time()
    try:
        result = await function()
    except BaseException as exc:
        COUNTERS['failed_transfers'] += 1
        COUNTERS['flood_wait_count'] += int(isinstance(exc, FloodWaitError))
        emit('transfer', operation=operation, workers=workers, size_bytes=size,
             status='cancelled' if isinstance(exc, asyncio.CancelledError) else 'failed',
             error_type=type(exc).__name__, duration_seconds=time.perf_counter() - start,
             cpu_seconds=time.process_time() - cpu,
             process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
             flood_wait_count=int(isinstance(exc, FloodWaitError)),
             flood_wait_seconds=exc.seconds if isinstance(exc, FloodWaitError) else 0,
             harness_retry_count=0, library_retry_count=None)
        raise
    elapsed = time.perf_counter() - start
    emit('transfer', operation=operation, workers=workers, size_bytes=size, status='passed',
         duration_seconds=elapsed, mb_per_second=size / 1_000_000 / elapsed,
         cpu_seconds=time.process_time() - cpu,
         process_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
         flood_wait_count=0, harness_retry_count=0, library_retry_count=None)
    return result


async def relay_once(client, config, workers=1):
    message = await approved_message(client, config)
    await client.resolve(config.destination)  # Validate destination before any download.
    size = message.raw.media.document.size
    with tempfile.TemporaryDirectory(prefix='easyproto-relay-') as folder:
        path = await measured('relay_download', size, workers,
            lambda: client.download(message, Path(folder) / 'fixture.bin', workers=workers))
        if sha256_file(path) != config.expected_sha256:
            raise ScopeError('Source integrity mismatch; upload refused')
        sent = await measured('relay_upload', size, workers,
            lambda: client.media(config.destination, path, workers=workers))
        if not isinstance(sent, Message):
            raise ScopeError('No document message returned after upload')
        # Fetch the stored message if Telegram returned updateShortSentMessage without media.
        sent = await stored_message(client, config.destination, sent)
        output = await measured('relay_verify_download', size, workers,
            lambda: client.download(sent, Path(folder) / 'verified.bin', workers=workers))
        if sha256_file(output) != config.expected_sha256:
            raise ScopeError('Destination integrity mismatch')
    emit('workflow', status='passed', size_bytes=size, workers=workers, integrity='sha256_matched')


async def stored_message(client, target, sent):
    peer = await client.resolve(target)
    ids = [types.inputMessageID(id=sent.id)]
    if peer.name == 'inputPeerChannel':
        result = await client.raw.channels.getMessages(
            channel=types.inputChannel(channel_id=peer.channel_id, access_hash=peer.access_hash), id=ids)
    else:
        result = await client.raw.messages.getMessages(id=ids)
    expected_id = client.session.user_id if peer.name == 'inputPeerSelf' else peer_id(peer)
    for raw in result.get('messages', []):
        actual = raw.get('peer_id')
        if raw.name == 'message' and raw.id == sent.id and isinstance(actual, TLObject) and peer_id(actual) == expected_id:
            return Message(client, raw, target)
    raise ScopeError('Uploaded message could not be fetched from the expected destination')


async def cancellation_probe(client, message):
    with tempfile.TemporaryDirectory(prefix='easyproto-cancel-') as folder:
        path = Path(folder) / 'output'
        path.write_bytes(b'original')
        task = asyncio.create_task(client.download(message, path, workers=1))
        await asyncio.sleep(0.001)
        if task.done():
            await task
            emit('cancellation', status='unverified', reason='completed_before_cancel')
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            if path.read_bytes() != b'original' or list(Path(folder).glob('.easyproto-download-*')):
                raise AssertionError('Cancellation damaged destination or leaked temporary files')
            emit('cancellation', status='passed', destination_preserved=True)
        else:
            emit('cancellation', status='unverified', reason='completed_during_cancel')


async def live(config, workers):
    client = new_client()
    try:
        await client.connect()  # Never prompt or start login implicitly.
        emit('me', status='passed')
        await source_peer(client, config.source)
        history = [m async for m in client.history(config.source, limit=3)]
        emit('private_history', status='passed' if history else 'unverified', count=len(history))
        await client.send('me', 'EasyProto authorized integration test')
        emit('saved_message', status='passed')
        with tempfile.TemporaryDirectory(prefix='easyproto-live-') as folder:
            path = Path(folder) / 'fixture.bin'
            path.write_bytes(bytes(range(256)) * (2 * 1024 * 1024 // 256) + b'fixture-end')
            expected = sha256_file(path)
            for count in workers:
                sent = await measured('upload', path.stat().st_size, count,
                    lambda: client.media('me', path, workers=count))
                sent = await stored_message(client, 'me', sent)
                output = await measured('download', path.stat().st_size, count,
                    lambda: client.download(sent, Path(folder) / f'output-{count}', workers=count))
                if sha256_file(output) != expected:
                    raise AssertionError('Live round-trip integrity mismatch')
                emit('integrity', status='passed', workers=count, algorithm='sha256')
                if count == workers[0]:
                    await cancellation_probe(client, sent)
        await client.close()
        await client.connect()
        emit('explicit_reconnect', status='passed')
        emit('progress_callbacks', status='unsupported')
    finally:
        await client.close()


async def preflight():
    """Anonymous req_pq only; no account session or login attempt."""
    dc = (TEST_DCS if test_mode() else PRODUCTION_DCS)[2]
    transport = IntermediateTransport(dc, timeout=5)
    try:
        await transport.connect()
        nonce = secrets.token_bytes(16)
        body = default_schema().encode(TLObject('req_pq_multi', nonce=nonce))
        msg_id = int(time.time() * (1 << 32)) & ~3
        await transport.send(bytes(8) + struct.pack('<qi', msg_id, len(body)) + body)
        packet = await asyncio.wait_for(transport.receive(), 5)
        if len(packet) < 20 or packet[:8] != bytes(8):
            raise ValueError('Unexpected preflight response')
        server_id, length = struct.unpack('<qi', packet[8:20])
        if length != len(packet) - 20 or server_id % 4 not in (1, 3):
            raise ValueError('Invalid preflight envelope')
        result = default_schema().decode(packet[20:])
        if result.name != 'resPQ' or result.nonce != nonce:
            raise ValueError('Preflight nonce mismatch')
        emit('preflight', status='passed', environment='test' if test_mode() else 'production',
             verified='anonymous_req_pq_only')
    finally:
        await transport.close()


async def run(args):
    if args.stage == 'preflight':
        await preflight()
        return
    if args.stage == 'login':
        # Explicit opt-in command, secret input is never echoed or logged.
        if os.getenv('TG_AUTHORIZED_TEST') != '1':
            raise ScopeError('TG_AUTHORIZED_TEST=1 is required')
        client = new_client()
        try:
            await client.start(phone=getpass.getpass('Telegram phone (hidden): '),
                code_callback=lambda: getpass.getpass('Telegram code (hidden): '),
                password=lambda: getpass.getpass('Telegram 2FA (hidden): '))
            emit('login', status='passed')
        finally:
            await client.close()
        return
    config = Config.from_env(workflow=args.stage == 'workflow')
    if args.stage == 'live':
        await live(config, args.workers)
    else:
        client = new_client()
        try:
            await client.connect()
            # Each count processes only the same one allowlisted message. No bot token,
            # listener, public endpoint, forwarding fallback, or general download service.
            for count in args.workers:
                await relay_once(client, config, count)
        finally:
            await client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, choices=['preflight', 'login', 'live', 'workflow'])
    parser.add_argument('--workers', type=int, nargs='+', default=[1, 2, 4], choices=[1, 2, 4])
    args = parser.parse_args()
    # Library callback exceptions may include account data; this harness has no handlers.
    logging.getLogger('easyproto').disabled = True
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        emit('run', status='cancelled')
        return 130
    except Exception as exc:
        emit('run', stage=args.stage, status='failed', error_type=type(exc).__name__,
             reason=str(exc) if isinstance(exc, ScopeError) else None,
             flood_wait_seconds=exc.seconds if isinstance(exc, FloodWaitError) else None)
        return 1
    finally:
        if COUNTERS['attempted_transfers']:
            emit('summary', **COUNTERS,
                 transfer_error_rate=COUNTERS['failed_transfers'] / COUNTERS['attempted_transfers'],
                 harness_retry_count=0, library_retry_count=None)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
