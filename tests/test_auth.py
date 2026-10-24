import asyncio
import hashlib
import secrets
import struct
import time

import pytest
from Crypto.PublicKey import RSA

from easyproto.auth import create_auth_key
from easyproto.crypto import aes_ige, int_bytes, key_fingerprint, sha1, sha256, temporary_aes, xor
from easyproto.errors import ProtocolError
from easyproto.session import Session
from easyproto.tl import Reader, TLObject, default_schema


class HandshakeServer:
    """Protocol peer exercising every auth exchange, with its own RSA private key."""
    timeout = 5

    def __init__(self, private, prime, tamper=None):
        self.private, self.prime, self.tamper = private, prime, tamper
        self.queue = asyncio.Queue()
        self.schema = default_schema()
        self.server_nonce = secrets.token_bytes(16)
        self.a = int.from_bytes(secrets.token_bytes(256), 'big')
        self.key = None
        self.steps = []

    async def send(self, packet):
        assert packet[:8] == bytes(8)
        request = self.schema.decode(packet[20:])
        self.steps.append(request.name)
        if request.name == 'req_pq_multi':
            self.nonce = request.nonce
            response = TLObject('resPQ',nonce=self.nonce,server_nonce=self.server_nonce,pq=int_bytes(17*19),
                server_public_key_fingerprints=[key_fingerprint(self.private.n,self.private.e)])
            if self.tamper == 'nonce': response.fields['nonce'] = bytes(16)
            if self.tamper == 'fingerprint': response.fields['server_public_key_fingerprints'] = [1]
        elif request.name == 'req_DH_params':
            assert request.nonce == self.nonce and request.server_nonce == self.server_nonce
            block = int_bytes(pow(int.from_bytes(request.encrypted_data,'big'),self.private.d,self.private.n),256)
            temp_key = xor(block[:32],sha256(block[32:]))
            decoded = aes_ige(block[32:],temp_key,bytes(32),decrypt=True)
            padded = decoded[:192][::-1]
            assert decoded[192:] == sha256(temp_key+padded)
            inner = self.schema.read(Reader(padded))
            self.new_nonce = inner.new_nonce
            assert inner.p == int_bytes(17) and inner.q == int_bytes(19)
            self.aes_key,self.aes_iv = temporary_aes(self.new_nonce,self.server_nonce)
            inner = self.schema.encode(TLObject('server_DH_inner_data',nonce=self.nonce,server_nonce=self.server_nonce,
                g=3,dh_prime=int_bytes(self.prime),g_a=int_bytes(pow(3,self.a,self.prime)),server_time=int(time.time())))
            clear = sha1(inner)+inner
            if self.tamper == 'checksum': clear = bytes(20)+inner
            clear += secrets.token_bytes(-len(clear)%16)
            response = TLObject('server_DH_params_ok',nonce=self.nonce,server_nonce=self.server_nonce,
                encrypted_answer=aes_ige(clear,self.aes_key,self.aes_iv))
        elif request.name == 'set_client_DH_params':
            clear = aes_ige(request.encrypted_data,self.aes_key,self.aes_iv,decrypt=True)
            reader = Reader(clear[20:]); inner = self.schema.read(reader)
            assert clear[:20] == sha1(clear[20:20+reader.stream.tell()])
            self.key = int_bytes(pow(int.from_bytes(inner.g_b,'big'),self.a,self.prime),256)
            confirmation = sha1(self.new_nonce+b'\x01'+sha1(self.key)[:8])[4:20]
            if self.tamper == 'confirmation': confirmation = bytes(16)
            response = TLObject('dh_gen_ok',nonce=self.nonce,server_nonce=self.server_nonce,new_nonce_hash1=confirmation)
        else:
            raise AssertionError(request.name)
        body = self.schema.encode(response)
        self.queue.put_nowait(bytes(8)+struct.pack('<qi',int(time.time()*(1<<32))|1,len(body))+body)

    async def receive(self): return await self.queue.get()


@pytest.fixture(scope='module')
def rsa_private(): return RSA.generate(2048)


async def test_full_auth_key_negotiation(rsa_private, dh_prime, monkeypatch):
    import easyproto.auth as auth
    fingerprint=key_fingerprint(rsa_private.n,rsa_private.e)
    monkeypatch.setattr(auth,'trusted_keys',lambda test: {fingerprint:(rsa_private.n,rsa_private.e)})
    server=HandshakeServer(rsa_private,dh_prime)
    session=Session(None)
    await create_auth_key(server,session,default_schema())
    assert session.auth_key == server.key and len(session.auth_key)==256
    assert server.steps == ['req_pq_multi','req_DH_params','set_client_DH_params']
    assert session.salt == int.from_bytes(xor(server.new_nonce[:8],server.server_nonce[:8]),'little',signed=True)


@pytest.mark.parametrize('tamper',['nonce','fingerprint','checksum','confirmation'])
async def test_tampered_handshake_never_retains_key(rsa_private, dh_prime, monkeypatch, tamper):
    import easyproto.auth as auth
    fingerprint=key_fingerprint(rsa_private.n,rsa_private.e)
    monkeypatch.setattr(auth,'trusted_keys',lambda test: {fingerprint:(rsa_private.n,rsa_private.e)})
    server=HandshakeServer(rsa_private,dh_prime,tamper)
    session=Session(None)
    with pytest.raises(ProtocolError): await create_auth_key(server,session,default_schema())
    assert session.auth_key == b''


def test_srp_proof_matches_independent_server(dh_prime):
    from easyproto.crypto import password_proof
    p,g=dh_prime,3
    s1,s2=b'salt-one',b'salt-two'
    H=lambda x: hashlib.sha256(x).digest()
    pad=lambda n: n.to_bytes(256,'big')
    h1=H(s1+b'password'+s1)
    h2=H(s2+h1+s2)
    x=int.from_bytes(H(s2+hashlib.pbkdf2_hmac('sha512',h2,s1,100000)+s2),'big')
    v=pow(g,x,p); b=int.from_bytes(secrets.token_bytes(256),'big')
    k=int.from_bytes(H(pad(p)+pad(g)),'big')
    B=(k*v+pow(g,b,p))%p
    algo=TLObject('passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow',salt1=s1,salt2=s2,g=g,p=pad(p))
    proof=password_proof('password',TLObject('account.password',current_algo=algo,srp_B=pad(B),srp_id=123))
    A=int.from_bytes(proof.A,'big'); u=int.from_bytes(H(pad(A)+pad(B)),'big')
    server_shared=pow(A*pow(v,u,p)%p,b,p)
    expected=H(bytes(a^b for a,b in zip(H(pad(p)),H(pad(g))))+H(s1)+H(s2)+pad(A)+pad(B)+H(pad(server_shared)))
    assert proof.M1 == expected and proof.srp_id == 123
