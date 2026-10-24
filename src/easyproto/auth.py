"""Independent permanent authorization-key negotiation."""
from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import struct
import time
from importlib.resources import files

from Crypto.PublicKey import RSA

from .crypto import (aes_ige, factor_pq, int_bytes, key_fingerprint, rsa_pad,
                     sha1, temporary_aes, validate_dh, validate_public, xor)
from .errors import ProtocolError
from .session import Session
from .tl import Reader, Schema, TLObject
from .transport import IntermediateTransport


def trusted_keys(test_mode: bool) -> dict[int, tuple[int, int]]:
    data = json.loads(files("easyproto").joinpath("schemas/keys.json").read_text())
    key = RSA.import_key(data["test" if test_mode else "production"])
    return {key_fingerprint(key.n, key.e): (key.n, key.e)}


async def create_auth_key(transport: IntermediateTransport, session: Session, schema: Schema) -> None:
    last_id = 0

    async def exchange(request: TLObject) -> TLObject:
        nonlocal last_id
        body = schema.encode(request)
        last_id = max(int(time.time() * (1 << 32)) & ~3, last_id + 4)
        await transport.send(bytes(8) + struct.pack("<qi", last_id, len(body)) + body)
        packet = await asyncio.wait_for(transport.receive(), transport.timeout)
        if len(packet) < 20 or packet[:8] != bytes(8):
            raise ProtocolError("Expected unencrypted handshake response")
        msg_id, length = struct.unpack("<qi", packet[8:20])
        if length < 4 or length % 4 or length != len(packet) - 20 or msg_id % 4 not in (1, 3):
            raise ProtocolError("Invalid unencrypted handshake envelope")
        return schema.decode(packet[20:])

    nonce = secrets.token_bytes(16)
    response = await exchange(TLObject("req_pq_multi", nonce=nonce))
    if response.name != "resPQ" or response.nonce != nonce:
        raise ProtocolError("Invalid resPQ nonce or constructor")
    server_nonce = response.server_nonce
    pq = int.from_bytes(response.pq, "big")
    p, q = await asyncio.to_thread(factor_pq, pq)
    keys = trusted_keys(session.test_mode)
    fingerprint = next((f for f in response.server_public_key_fingerprints if f in keys), None)
    if fingerprint is None:
        raise ProtocolError("Server offered no pinned Telegram RSA key")
    new_nonce = secrets.token_bytes(32)
    inner = schema.encode(TLObject("p_q_inner_data_dc", pq=response.pq, p=int_bytes(p), q=int_bytes(q),
                                   nonce=nonce, server_nonce=server_nonce, new_nonce=new_nonce,
                                   dc=session.dc_id + (10000 if session.test_mode else 0)))
    n, e = keys[fingerprint]
    answer = await exchange(TLObject("req_DH_params", nonce=nonce, server_nonce=server_nonce,
                                     p=int_bytes(p), q=int_bytes(q), public_key_fingerprint=fingerprint,
                                     encrypted_data=rsa_pad(inner, n, e)))
    if answer.get("nonce") != nonce or answer.get("server_nonce") != server_nonce:
        raise ProtocolError("DH response nonce mismatch")
    if answer.name != "server_DH_params_ok":
        raise ProtocolError("Server refused DH negotiation")
    key, iv = temporary_aes(new_nonce, server_nonce)
    decoded = aes_ige(answer.encrypted_answer, key, iv, decrypt=True)
    reader = Reader(decoded[20:])
    dh = schema.read(reader)
    used = reader.stream.tell()
    if reader.remaining() > 15 or not hmac.compare_digest(decoded[:20], sha1(decoded[20:20 + used])):
        raise ProtocolError("DH inner data checksum or padding mismatch")
    if dh.name != "server_DH_inner_data" or dh.nonce != nonce or dh.server_nonce != server_nonce:
        raise ProtocolError("Invalid DH inner data")
    prime, g_a = int.from_bytes(dh.dh_prime, "big"), int.from_bytes(dh.g_a, "big")
    await asyncio.to_thread(validate_dh, prime, dh.g)
    validate_public(g_a, prime)
    session.time_offset = dh.server_time - time.time()
    retry_id = 0
    for _ in range(5):
        b = int.from_bytes(secrets.token_bytes(256), "big")
        g_b = pow(dh.g, b, prime)
        validate_public(g_b, prime)
        auth_key = int_bytes(pow(g_a, b, prime), 256)
        client_inner = schema.encode(TLObject("client_DH_inner_data", nonce=nonce,
                    server_nonce=server_nonce, retry_id=retry_id, g_b=int_bytes(g_b)))
        clear = sha1(client_inner) + client_inner
        clear += secrets.token_bytes(-len(clear) % 16)
        result = await exchange(TLObject("set_client_DH_params", nonce=nonce, server_nonce=server_nonce,
                                         encrypted_data=aes_ige(clear, key, iv)))
        if result.get("nonce") != nonce or result.get("server_nonce") != server_nonce:
            raise ProtocolError("Client DH response nonce mismatch")
        outcome = {"dh_gen_ok": 1, "dh_gen_retry": 2, "dh_gen_fail": 3}.get(result.name)
        if outcome is None:
            raise ProtocolError("Unexpected client DH result")
        aux = sha1(auth_key)[:8]
        expected = sha1(new_nonce + bytes([outcome]) + aux)[4:20]
        if not hmac.compare_digest(result.fields[f"new_nonce_hash{outcome}"], expected):
            raise ProtocolError("DH key confirmation failed")
        if outcome == 1:
            session.auth_key = auth_key
            session.salt = int.from_bytes(xor(new_nonce[:8], server_nonce[:8]), "little", signed=True)
            session.save()
            return
        if outcome == 3:
            raise ProtocolError("Server rejected the DH key")
        retry_id = int.from_bytes(aux, "little", signed=True)
    raise ProtocolError("Too many DH retries")
