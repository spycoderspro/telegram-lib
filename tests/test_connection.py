import asyncio
import contextlib
import gzip
import secrets
import struct
import time

import pytest

from easyproto.connection import Connection, Pending
from easyproto.crypto import decrypt_message, encrypt_message
from easyproto.errors import FloodWaitError, ProtocolError
from easyproto.session import Session
from easyproto.tl import TLObject, default_schema, functions, pack_bytes, types
from easyproto.transport import IntermediateTransport


async def test_encrypted_rpc_over_real_loopback_tcp():
    auth=secrets.token_bytes(256)
    schema=default_schema()
    server_errors=[]
    completed=asyncio.Event()
    async def peer(reader,writer):
        try:
            assert await reader.readexactly(4) == b'\xee'*4
            length=struct.unpack('<I',await reader.readexactly(4))[0]
            salt,session_id,msg_id,seq,body=decrypt_message(auth,await reader.readexactly(length),incoming=False)
            request=schema.decode(body)
            assert request.name=='users.getUsers' and request.id[0].name=='inputUserSelf'
            assert seq==1
            result=struct.pack('<Ii',0x1CB5C415,1)+schema.encode(types.user(id=42,first_name='Test'))
            result=struct.pack('<I',0x3072CFA1)+pack_bytes(gzip.compress(result))
            body=struct.pack('<Iq',0xF35C6D01,msg_id)+result
            server_id=int(time.time()*(1<<32))|1
            inner=struct.pack('<qii',server_id,1,len(body))+body
            body=struct.pack('<Ii',0x73F1F8DC,1)+inner
            envelope=struct.pack('<q8sqii',salt,session_id,server_id+4,0,len(body))+body
            packet=encrypt_message(auth,envelope,outgoing=False)
            writer.write(struct.pack('<I',len(packet))+packet); await writer.drain()
            # Acknowledge the server's content-related inner message.
            length=struct.unpack('<I',await reader.readexactly(4))[0]
            _,_,_,seq,body=decrypt_message(auth,await reader.readexactly(length),incoming=False)
            assert seq==2 and schema.decode(body).msg_ids==[server_id]
        except Exception as exc:
            server_errors.append(exc)
        finally:
            completed.set(); writer.close(); await writer.wait_closed()
    server=await asyncio.start_server(peer,'127.0.0.1',0)
    port=server.sockets[0].getsockname()[1]
    connection=Connection(Session(None,auth_key=auth),transport=IntermediateTransport('127.0.0.1',port),timeout=3)
    try:
        await connection.connect()
        result=await connection.invoke(functions.users.getUsers(id=[types.inputUserSelf()]))
        assert result[0].id==42 and result[0].first_name=='Test'
        await asyncio.wait_for(completed.wait(),3)
        assert not server_errors
        assert not connection.pending
    finally:
        await connection.close(); server.close(); await server.wait_closed()


async def test_parallel_requests_correlate_reversed_encrypted_responses():
    auth=secrets.token_bytes(256)
    schema=default_schema()
    finished=asyncio.Event()
    failures=[]
    async def peer(reader,writer):
        try:
            assert await reader.readexactly(4)==b'\xee'*4
            requests=[]
            for index in range(4):
                length=struct.unpack('<I',await reader.readexactly(4))[0]
                salt,session_id,msg_id,sequence,body=decrypt_message(auth,await reader.readexactly(length),incoming=False)
                request=schema.decode(body)
                assert request.name=='upload.saveFilePart'
                assert sequence==index*2+1
                requests.append((msg_id,request.file_part))
            # No reply is sent until all four requests are already in flight.
            base=int(time.time()*(1<<32))|1
            for index,(request_id,part) in enumerate(reversed(requests)):
                # Different Bool results ensure correlation, not just eventual completion.
                result=struct.pack('<I',0x997275B5 if part%2==0 else 0xBC799737)
                body=struct.pack('<Iq',0xF35C6D01,request_id)+result
                plain=struct.pack('<q8sqii',salt,session_id,base+index*4,1,len(body))+body
                packet=encrypt_message(auth,plain,outgoing=False)
                writer.write(struct.pack('<I',len(packet))+packet)
            await writer.drain()
            for _ in range(4):
                length=struct.unpack('<I',await reader.readexactly(4))[0]
                _,_,_,_,body=decrypt_message(auth,await reader.readexactly(length),incoming=False)
                assert schema.decode(body).name=='msgs_ack'
        except Exception as exc:
            failures.append(exc)
        finally:
            finished.set()
            writer.close(); await writer.wait_closed()
    server=await asyncio.start_server(peer,'127.0.0.1',0)
    port=server.sockets[0].getsockname()[1]
    connection=Connection(Session(None,auth_key=auth),transport=IntermediateTransport('127.0.0.1',port),timeout=5)
    try:
        await connection.connect()
        results=await asyncio.gather(*(connection.invoke(functions.upload.saveFilePart(
            file_id=123,file_part=index,bytes=bytes(4096))) for index in range(4)))
        assert results==[True,False,True,False]
        await asyncio.wait_for(finished.wait(),5)
        assert not failures and not connection.pending
    finally:
        await connection.close(); server.close(); await server.wait_closed()


class MemoryTransport:
    def __init__(self): self.sent=[]
    async def send(self,packet): self.sent.append(packet)


def prepared():
    transport=MemoryTransport()
    connection=Connection(Session(None,auth_key=secrets.token_bytes(256)),transport=transport)
    return connection,transport


async def test_replay_suppression_and_request_error():
    connection,transport=prepared()
    error=default_schema().encode(TLObject('rpc_error',error_code=420,error_message='FLOOD_WAIT_8'))
    future=asyncio.get_running_loop().create_future()
    connection.pending[100]=Pending(functions.help.getConfig(),future,True)
    msg_id=int(time.time()*(1<<32))|1
    body=struct.pack('<Iq',0xF35C6D01,100)+error
    await connection._handle(msg_id,1,body)
    with pytest.raises(FloodWaitError) as caught: await future
    assert caught.value.seconds==8
    await connection._handle(msg_id,1,body)
    assert len(transport.sent)==2  # Replays get acknowledged but not dispatched.


async def test_bad_salt_resends_same_request_and_random_id():
    connection,transport=prepared()
    request=functions.messages.sendMessage(peer=types.inputPeerSelf(),message='hi',random_id=123)
    future=asyncio.get_running_loop().create_future()
    pending=Pending(request,future,True); connection.pending[100]=pending
    notification=default_schema().encode(TLObject('bad_server_salt',bad_msg_id=100,bad_msg_seqno=1,error_code=48,new_server_salt=17))
    await connection._handle(int(time.time()*(1<<32))|1,0,notification)
    assert connection.session.salt==17 and 100 not in connection.pending
    salt,_,_,_,body=decrypt_message(connection.session.auth_key,transport.sent[-1],incoming=False)
    assert salt==17 and default_schema().decode(body).random_id==123
    assert list(connection.pending.values())==[pending]
    future.cancel()


async def test_server_message_bounds_and_gzip_bomb(monkeypatch):
    connection,_=prepared()
    with pytest.raises(ProtocolError): connection._check_server_id(4)
    with pytest.raises(ProtocolError): connection._check_server_id(1)
    import easyproto.connection as module
    monkeypatch.setattr(module,'MAX_BYTES',100)
    body=struct.pack('<I',0x3072CFA1)+pack_bytes(gzip.compress(bytes(200)))
    with pytest.raises(ProtocolError,match='exceeds'): connection._unzip(body)


def test_replay_stays_rejected_after_recent_cache_rolls_over():
    connection,_=prepared()
    first=int(time.time()*(1<<32))|1
    for index in range(1025): assert connection._check_server_id(first+index*4)
    assert not connection._check_server_id(first)


async def test_future_salts_response_completes_request():
    connection,_=prepared()
    future=asyncio.get_running_loop().create_future()
    connection.pending[100]=Pending(functions.get_future_salts(num=1),future,True)
    now=int(time.time())
    body=default_schema().encode(TLObject('future_salts',req_msg_id=100,now=now,
        salts=[TLObject('future_salt',valid_since=now,valid_until=now+1800,salt=17)]))
    await connection._handle(int(time.time()*(1<<32))|1,1,body)
    assert (await future).req_msg_id==100
    assert connection._salts[17]==(now,now+1800)


def test_salt_changes_must_be_announced():
    connection,_=prepared()
    schema=default_schema()
    notification=schema.encode(TLObject('new_session_created',first_msg_id=1,unique_id=2,server_salt=123))
    assert connection._announces_salt(notification,123)
    assert not connection._announces_salt(notification,456)
    assert not connection._announces_salt(schema.encode(types.user(id=42)),123)


@pytest.mark.parametrize('length',[-1,0,3,20_000_000])
async def test_bad_transport_frame_bounds(length):
    transport=IntermediateTransport('unused')
    transport.reader=asyncio.StreamReader()
    transport.reader.feed_data(struct.pack('<i',length))
    with pytest.raises(ProtocolError): await transport.receive()
