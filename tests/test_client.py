from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from telethon import functions
from telethon.errors import FloodWaitError
from easyproto import Client


@pytest.fixture
def pair():
    raw = MagicMock()
    for name in ('start', 'disconnect', 'connect', 'is_user_authorized',
                 'send_message', 'forward_messages', 'get_input_entity',
                 'delete_messages', 'edit_message', 'send_file'):
        setattr(raw, name, AsyncMock())
    raw.is_user_authorized.return_value = True
    with patch('easyproto.client.TelegramClient', return_value=raw):
        client = Client(12345, 'test-hash')
    return client, raw


async def test_reply_and_schedule(pair):
    client, raw = pair
    await client.reply('me', 42, 'hello', silent=True)
    args = raw.send_message.call_args
    assert args.args == ('me', 'hello')
    assert args.kwargs['reply_to'] == 42
    assert args.kwargs['silent'] is True
    assert args.kwargs['parse_mode'] is None


async def test_forward_direction(pair):
    client, raw = pair
    await client.forward('source', 'destination', [10, 11])
    raw.forward_messages.assert_awaited_once_with('destination', [10, 11], from_peer='source')


async def test_context_cleanup_on_body_failure(pair):
    client, raw = pair
    with pytest.raises(RuntimeError):
        async with client:
            raise RuntimeError('test')
    raw.disconnect.assert_awaited_once()


async def test_login_failure_disconnects(pair):
    client, raw = pair
    raw.start.side_effect = ValueError('bad login')
    with pytest.raises(ValueError):
        await client.start()
    raw.disconnect.assert_awaited_once()


async def test_noninteractive_requires_authorization(pair):
    client, raw = pair
    raw.is_user_authorized.return_value = False
    with pytest.raises(RuntimeError, match='needs login'):
        await client.connect()
    raw.start.assert_not_called()
    raw.disconnect.assert_awaited_once()


async def test_flood_wait_is_not_replayed(pair):
    client, raw = pair
    raw.send_message.side_effect = FloodWaitError(request=None, capture=90)
    with pytest.raises(FloodWaitError) as caught:
        await client.send('me', 'hello')
    assert caught.value.seconds == 90
    raw.send_message.assert_awaited_once()


async def test_delete_local_default(pair):
    client, raw = pair
    await client.delete('me', 3)
    raw.delete_messages.assert_awaited_once_with('me', 3, revoke=False)


@pytest.mark.parametrize('link', ['https://t.me/+abc', 'https://t.me/joinchat/abc', '+abc'])
async def test_invite_routes(pair, link):
    client, _ = pair
    client.raw = AsyncMock()
    await client.join(link)
    request = client.raw.call_args.args[0]
    assert isinstance(request, functions.messages.ImportChatInviteRequest)
    assert request.hash == 'abc'


async def test_public_join(pair):
    client, _ = pair
    client.raw = AsyncMock()
    await client.join('https://t.me/example')
    request = client.raw.call_args.args[0]
    assert isinstance(request, functions.channels.JoinChannelRequest)
    assert request.channel == 'example'


async def test_invalid_join_link(pair):
    client, raw = pair
    with pytest.raises(ValueError):
        await client.join('https://example.com/+abc')
    raw.assert_not_called()


async def test_clear_reaction(pair):
    client, _ = pair
    client.raw = AsyncMock()
    await client.react('me', 4, None)
    request = client.raw.call_args.args[0]
    assert request.reaction == []
    assert request.msg_id == 4


async def test_history_streams_and_validates(pair):
    client, raw = pair
    async def messages():
        yield 'one'
        yield 'two'
    raw.iter_messages.return_value = messages()
    assert [m async for m in client.history('me', limit=2)] == ['one', 'two']
    with pytest.raises(ValueError):
        _ = [m async for m in client.history('me', limit=0)]


def test_env_missing(monkeypatch):
    monkeypatch.delenv('TG_API_ID', raising=False)
    with pytest.raises(ValueError, match='TG_API_ID'):
        Client.from_env()


def test_real_client_construction():
    client = Client(12345, 'test-hash', session=':memory:')
    assert client.raw.parse_mode is None
    assert client.raw.flood_sleep_threshold == 30


def test_event_registration(pair):
    client, raw = pair
    @client.on_message(chats='me', pattern='hi')
    async def handler(event):
        pass
    assert raw.add_event_handler.call_args.args[0] is handler
    client.off_message(handler)
    raw.remove_event_handler.assert_called_once()
