import hashlib
import struct

import pytest
from Crypto.PublicKey import RSA

from easyproto.auth import trusted_keys
from easyproto.crypto import (aes_ige, decrypt_message, encrypt_message, factor_pq,
    int_bytes, key_fingerprint, rsa_pad, sha256, validate_dh, validate_public, xor)
from easyproto.errors import ProtocolError


def test_aes_ige_openssl_known_vector():
    # Independently computed with OpenSSL libcrypto AES_ige_encrypt (AES_ENCRYPT).
    plain, key, iv = bytes(range(64)), bytes(range(32)), bytes(range(32, 64))
    cipher = bytes.fromhex('42e66e1a756cccf5b27acc47523ad074ee39bf54e3db37bbdf415df6b400fca977f708327c9e9341cc3dc8efd31e76463daa65b1f0d0252f790d77f1824a662c')
    assert aes_ige(plain, key, iv) == cipher
    assert aes_ige(cipher, key, iv, decrypt=True) == plain


@pytest.mark.parametrize('outgoing', [False, True])
def test_authenticated_message_both_directions(outgoing):
    auth = bytes(range(256))
    plain = struct.pack('<q8sqii', 123, b'session1', 1001, 1, 4) + b'body'
    packet = encrypt_message(auth, plain, outgoing=outgoing)
    assert decrypt_message(auth, packet, incoming=not outgoing) == (123, b'session1', 1001, 1, b'body')
    corrupted = bytearray(packet); corrupted[-1] ^= 1
    with pytest.raises(ProtocolError, match='authentication'):
        decrypt_message(auth, bytes(corrupted), incoming=not outgoing)
    with pytest.raises(ProtocolError):
        decrypt_message(auth, packet, incoming=outgoing)
    with pytest.raises(ProtocolError, match='key ID'):
        decrypt_message(bytes(256), packet)


def test_rsa_pad_can_be_verified_with_private_key():
    private = RSA.generate(2048)
    data = b'a short handshake challenge'
    encrypted = rsa_pad(data, private.n, private.e)
    block = int_bytes(pow(int.from_bytes(encrypted, 'big'), private.d, private.n), 256)
    encrypted_aes = block[32:]
    key = xor(block[:32], sha256(encrypted_aes))
    plain = aes_ige(encrypted_aes, key, bytes(32), decrypt=True)
    padded = plain[:192][::-1]
    assert padded.startswith(data)
    assert plain[192:] == sha256(key + padded)


def test_pinned_rsa_fingerprints():
    assert set(trusted_keys(False)) == {-3414540481677951611}
    assert set(trusted_keys(True)) == {-5595554452916591101}


@pytest.mark.parametrize('p,q', [(17,19),(1009,1013),(1000000007,1000000009)])
def test_pq_factorization(p, q):
    assert factor_pq(p*q) == (p,q)


@pytest.mark.parametrize('pq', [-1, 0, 3, 1 << 65, 45])
def test_invalid_pq(pq):
    with pytest.raises(ProtocolError):
        factor_pq(pq)


def test_unsafe_dh_rejected():
    with pytest.raises(ProtocolError): validate_dh(23, 3)
    with pytest.raises(ProtocolError): validate_public(1, (1 << 2048) - 1)


def test_invalid_ige_sizes():
    with pytest.raises(ValueError): aes_ige(b'bad', bytes(32), bytes(32))


def test_python_fallback_matches_known_vector(monkeypatch):
    import easyproto.crypto as crypto
    monkeypatch.setattr(crypto,'_cryptg',None)
    test_aes_ige_openssl_known_vector()
    assert crypto.aes_ige(b'',bytes(32),bytes(32)) == b''


@pytest.mark.parametrize('size',[16,48,512*1024])
def test_optional_native_backend_matches_python(size):
    import easyproto.crypto as crypto
    if crypto._cryptg is None: pytest.skip('fast extra is not installed')
    data = bytes(range(256))*(size//256)+bytes(range(size%256))
    key,iv = bytes(range(32)),bytes(range(32,64))
    expected = crypto._aes_ige_python(data,key,iv)
    assert crypto.aes_ige(data,key,iv) == expected
    assert crypto.aes_ige(expected,key,iv,decrypt=True) == data
