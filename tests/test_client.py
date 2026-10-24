import asyncio
import hashlib
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from easyproto import Client, TLObject, functions, types
from easyproto.errors import AuthorizationRequired, FloodWaitError, RPCError, UnsupportedFeature


@pytest.fixture
def pair():
    client = Client(12345, 'test-hash', session=':memory:')
    connection = MagicMock()
    connection.closed = asyncio.Event()
    connection.updates = asyncio.Queue()
    connection.failure = None
    connection.invoke = AsyncMock(return_value=TLObject('updateShortSentMessage', id=7, date=1, out=True))
    connection.close = AsyncMock()
    client._connection = connection
    return client, connection


async def test_send_reply_and_schedule(pair):
    client, connection = pair
    when = datetime(2030, 1, 1, tzinfo=timezone.utc)
    message = await client.reply('me', 42, 'hello', silent=True, schedule=when)
    request = connection.invoke.call_args.args[0]
    assert request.name == 'messages.sendMessage'
    assert request.peer.name == 'inputPeerSelf'
    assert request.reply_to.reply_to_msg_id == 42
    assert request.silent is True
    assert request.schedule_date == int(when.timestamp())
    assert message.id == 7 and message.text == 'hello'
    assert request.random_id > 0


async def test_forward_direction(pair):
    client, connection = pair
    a = types.inputPeerUser(user_id=1, access_hash=2)
    b = types.inputPeerUser(user_id=3, access_hash=4)
    await client.forward(a, b, [10, 11])
    request = connection.invoke.call_args.args[0]
    assert request.from_peer == a and request.to_peer == b
    assert request.id == [10, 11]
    assert len(set(request.random_id)) == 2


async def test_cleanup_on_body_and_login_failure(pair, monkeypatch):
    client, connection = pair
    monkeypatch.setattr(client, 'start', AsyncMock(return_value=client))
    with pytest.raises(RuntimeError):
        async with client: raise RuntimeError('body failed')
    connection.close.assert_awaited_once()


async def test_connect_never_prompts(pair):
    client, connection = pair
    connection.invoke.side_effect = RPCError(401, 'AUTH_KEY_UNREGISTERED')
    with pytest.raises(AuthorizationRequired): await client.connect()
    connection.close.assert_awaited_once()


async def test_flood_wait_is_not_replayed_by_default(pair):
    client, connection = pair
    connection.invoke.side_effect = FloodWaitError(420, 'FLOOD_WAIT_90', 90)
    with pytest.raises(FloodWaitError) as caught: await client.send('me', 'hello')
    assert caught.value.seconds == 90
    connection.invoke.assert_awaited_once()


async def test_channel_and_user_delete_routing(pair):
    client, connection = pair
    await client.delete('me', 3)
    request = connection.invoke.call_args.args[0]
    assert request.name == 'messages.deleteMessages' and request.revoke is False
    channel = types.inputPeerChannel(channel_id=7, access_hash=8)
    await client.delete(channel, [3, 4])
    request = connection.invoke.call_args.args[0]
    assert request.name == 'channels.deleteMessages' and request.channel.channel_id == 7


@pytest.mark.parametrize('link', ['https://t.me/+abc', 'https://t.me/joinchat/abc', '+abc'])
async def test_invite_routes(pair, link):
    client, connection = pair
    await client.join(link)
    request = connection.invoke.call_args.args[0]
    assert request.name == 'messages.importChatInvite' and request.hash == 'abc'


async def test_invalid_links_and_unsupported_format_fail_before_rpc(pair):
    client, connection = pair
    with pytest.raises(ValueError): await client.join('https://example.com/+abc')
    with pytest.raises(UnsupportedFeature): await client.send('me', 'hello', parse_mode='html')
    with pytest.raises(ValueError): await client.send('me', 'hello', schedule=datetime(2030,1,1))
    connection.invoke.assert_not_awaited()


async def test_clear_reaction_and_profile_clearing(pair):
    client, connection = pair
    await client.react('me', 4, None)
    request = connection.invoke.call_args.args[0]
    assert request.reaction == [] and request.msg_id == 4
    await client.profile(first_name='', bio='hello')
    request = connection.invoke.call_args.args[0]
    assert request.first_name == '' and request.about == 'hello' and request.last_name is None


async def test_history_paginates_and_stops_at_limit(pair):
    client, connection = pair
    page1 = TLObject('messages.messages', messages=[TLObject('message',id=i,message=str(i)) for i in range(102,2,-1)])
    page2 = TLObject('messages.messages', messages=[TLObject('message',id=2,message='two'),TLObject('message',id=1,message='one')])
    connection.invoke.side_effect = [page1,page2]
    messages = [m async for m in client.history('me', limit=101)]
    assert len(messages) == 101 and messages[-1].id == 2
    assert connection.invoke.call_args.args[0].offset_id == 3
    with pytest.raises(ValueError): _ = [m async for m in client.history('me', limit=0)]


async def test_username_cache_and_unknown_numeric_id(pair):
    client, connection = pair
    connection.invoke.return_value = TLObject('contacts.resolvedPeer', peer=types.peerUser(user_id=42),
        users=[TLObject('user',id=42,access_hash=123,username='Alice')],chats=[])
    assert (await client.resolve('@Alice')).access_hash == 123
    assert await client.resolve(42) == await client.resolve('alice')
    connection.invoke.assert_awaited_once()
    with pytest.raises(ValueError, match='access hash'): await client.resolve(9999)


async def test_upload_chunks_and_md5(pair, tmp_path):
    client, connection = pair
    connection.invoke.return_value = True
    data = b'x' * (512*1024+3)
    path = tmp_path/'file.bin'; path.write_bytes(data)
    result = await client.upload(path)
    assert result.name == 'inputFile' and result.parts == 2
    assert result.md5_checksum == hashlib.md5(data).hexdigest()
    requests = [c.args[0] for c in connection.invoke.call_args_list]
    assert [r.file_part for r in requests] == [0,1]
    assert b''.join(r.bytes for r in requests) == data


async def test_media_is_native_rpc(pair, tmp_path):
    client, connection = pair
    path = tmp_path/'test.txt'; path.write_text('hello')
    connection.invoke.side_effect = [True, TLObject('updateShortSentMessage',id=7,date=1,out=True)]
    message = await client.media('me', path, caption='caption')
    request = connection.invoke.call_args.args[0]
    assert request.name == 'messages.sendMedia' and request.media.name == 'inputMediaUploadedDocument'
    assert message.text == 'caption'


async def test_download_is_atomic_and_sanitizes_server_filename(pair, tmp_path):
    client, connection = pair
    doc = TLObject('document',id=1,access_hash=2,file_reference=b'ref',size=5,dc_id=2,
        attributes=[TLObject('documentAttributeFilename',file_name='../../outside.txt')])
    media = TLObject('messageMediaDocument',document=doc)
    connection.invoke.return_value = TLObject('upload.file',bytes=b'hello')
    path = await client.download(media, tmp_path)
    assert path == tmp_path/'outside.txt' and path.read_bytes() == b'hello'
    connection.invoke.return_value = TLObject('upload.file',bytes=b'')
    with pytest.raises(OSError): await client.download(media,tmp_path/'failed.bin')
    assert not (tmp_path/'failed.bin').exists()
    assert not list(tmp_path.glob('.easyproto-download-*'))


async def test_raw_namespace_routes_typed_request(pair):
    client, connection = pair
    await client.raw.users.getUsers(id=[types.inputUserSelf()])
    assert connection.invoke.call_args.args[0].name == 'users.getUsers'


async def test_events_filter_and_remove(pair):
    client, connection = pair
    seen = []
    @client.on_message(pattern='^hi')
    async def handler(event): seen.append((event.id,event.sender_id,event.raw_text))
    await client._dispatch(TLObject('message',id=1,message='hi there',peer_id=types.peerUser(user_id=2),from_id=types.peerUser(user_id=2)))
    await client._dispatch(TLObject('message',id=2,message='hi',peer_id=types.peerUser(user_id=2),out=True))
    assert seen == [(1,2,'hi there')]
    assert client.off_message(handler) == 1


async def test_listener_gap_is_explicit_and_cancellation_cleans_tasks(pair):
    client, connection = pair
    connection.updates.put_nowait(TLObject('updatesTooLong'))
    with pytest.raises(UnsupportedFeature, match='gap'): await client.listen()
    listener = asyncio.create_task(client.listen())
    await asyncio.sleep(0)
    listener.cancel()
    with pytest.raises(asyncio.CancelledError): await listener
    assert client._listening is False


def test_env_missing(monkeypatch):
    monkeypatch.delenv('TG_API_ID', raising=False)
    with pytest.raises(ValueError, match='TG_API_ID'): Client.from_env()


async def test_existing_account_phone_code_login(pair):
    client, connection = pair
    connection.invoke.side_effect = [RPCError(401,'AUTH_KEY_UNREGISTERED'),
        TLObject('auth.sentCode',phone_code_hash='test-code-hash'),
        TLObject('auth.authorization',user=TLObject('user',id=42,access_hash=123))]
    assert await client.start(phone='+10000000000',code_callback=lambda:'12345') is client
    assert client.session.user_id==42
    requests=[call.args[0] for call in connection.invoke.call_args_list]
    assert [r.name for r in requests]==['users.getUsers','auth.sendCode','auth.signIn']
    assert requests[-1].phone_code_hash=='test-code-hash'
    assert requests[-1].phone_code=='12345'


async def test_login_failure_closes_connection(pair):
    client,connection=pair
    connection.invoke.side_effect=[RPCError(401,'AUTH_KEY_UNREGISTERED'),RPCError(400,'PHONE_NUMBER_INVALID')]
    with pytest.raises(RPCError): await client.start(phone='invalid',code_callback=lambda:'12345')
    connection.close.assert_awaited_once()


async def test_network_failure_never_replays_mutating_request(pair):
    client,connection=pair
    connection.invoke.side_effect=ConnectionError('lost response')
    with pytest.raises(ConnectionError): await client.send('me','hello')
    connection.invoke.assert_awaited_once()


async def test_chats_includes_self_without_access_hash(pair):
    client,connection=pair
    client.session.user_id=42
    connection.invoke.return_value=TLObject('messages.dialogs',
        users=[types.user(id=42,self=True,first_name='Self')],chats=[],messages=[],
        dialogs=[TLObject('dialog',peer=types.peerUser(user_id=42),top_message=7)])
    chats=[chat async for chat in client.chats(limit=1)]
    assert [chat.id for chat in chats]==[42]
    assert (await client.resolve(42)).name=='inputPeerSelf'
