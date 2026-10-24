"""MTProto 2.0 constructions over PyCryptodome's AES primitive.

This code is experimental and has not received an independent security audit.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import struct
from functools import lru_cache

from Crypto.Cipher import AES
from Crypto.Util.number import isPrime

try:
    import cryptg as _cryptg
except ImportError:
    _cryptg = None

AES_IGE_BACKEND = "cryptg" if _cryptg is not None else "python"

from .errors import ProtocolError, UnsupportedFeature
from .tl import TLObject, pack_bytes


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("XOR operands must have equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))


def aes_ige(data: bytes, key: bytes, iv: bytes, *, decrypt: bool = False) -> bytes:
    if len(data) % 16 or len(iv) != 32 or len(key) != 32:
        raise ValueError("AES-256-IGE requires aligned data, a 32-byte key and IV")
    if not data:
        return b""
    if _cryptg is not None:
        operation = _cryptg.decrypt_ige if decrypt else _cryptg.encrypt_ige
        return operation(data, key, iv)
    return _aes_ige_python(data, key, iv, decrypt=decrypt)


def _aes_ige_python(data: bytes, key: bytes, iv: bytes, *, decrypt: bool = False) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    previous_cipher, previous_plain = iv[:16], iv[16:]
    out = bytearray()
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        if decrypt:
            result = xor(aes.decrypt(xor(block, previous_plain)), previous_cipher)
            previous_cipher, previous_plain = block, result
        else:
            result = xor(aes.encrypt(xor(block, previous_cipher)), previous_plain)
            previous_cipher, previous_plain = result, block
        out += result
    return bytes(out)


def int_bytes(value: int, size: int | None = None) -> bytes:
    return value.to_bytes(size or max(1, (value.bit_length() + 7) // 8), "big")


def key_fingerprint(n: int, e: int) -> int:
    return int.from_bytes(sha1(pack_bytes(int_bytes(n)) + pack_bytes(int_bytes(e)))[-8:], "little", signed=True)


def rsa_pad(data: bytes, n: int, e: int) -> bytes:
    """Telegram's SHA-256/AES-IGE RSA_PAD, not legacy SHA-1 RSA padding."""
    if len(data) > 144 or n.bit_length() != 2048:
        raise ValueError("RSA_PAD needs <=144 bytes and a 2048-bit key")
    padded = data + secrets.token_bytes(192 - len(data))
    for _ in range(128):
        key = secrets.token_bytes(32)
        plain = padded[::-1] + sha256(key + padded)
        encrypted = aes_ige(plain, key, bytes(32))
        block = xor(key, sha256(encrypted)) + encrypted
        value = int.from_bytes(block, "big")
        if value < n:
            return int_bytes(pow(value, e, n), 256)
    raise ProtocolError("Could not construct RSA_PAD block")


def factor_pq(pq: int) -> tuple[int, int]:
    """Bounded Pollard rho for Telegram's small, unauthenticated pq challenge."""
    if not 4 <= pq < 1 << 64:
        raise ProtocolError("pq is outside the supported range")
    if pq % 2 == 0:
        factor = 2
    else:
        factor = 1
        for _ in range(32):
            x = y = secrets.randbelow(pq - 2) + 2
            c = secrets.randbelow(pq - 1) + 1
            for _ in range(200_000):
                x = (x * x + c) % pq
                y = (y * y + c) % pq
                y = (y * y + c) % pq
                factor = math.gcd(abs(x - y), pq)
                if factor != 1:
                    break
            if 1 < factor < pq:
                break
    if not 1 < factor < pq:
        raise ProtocolError("Could not factor server pq")
    a, b = sorted((factor, pq // factor))
    if a * b != pq or not isPrime(a) or not isPrime(b):
        raise ProtocolError("pq must be the product of two primes")
    return a, b


@lru_cache(maxsize=8)
def validate_dh(prime: int, g: int) -> None:
    if prime.bit_length() != 2048 or g not in range(2, 8):
        raise ProtocolError("Unsupported DH group")
    conditions = {
        2: prime % 8 == 7,
        3: prime % 3 == 2,
        4: True,
        5: prime % 5 in (1, 4),
        6: prime % 24 in (19, 23),
        7: prime % 7 in (3, 5, 6),
    }
    if not conditions[g] or not isPrime(prime, false_positive_prob=1e-30) or not isPrime((prime - 1) // 2, false_positive_prob=1e-30):
        raise ProtocolError("DH modulus is not a safe prime for the generator")


def validate_public(value: int, prime: int) -> None:
    if not (1 << (2048 - 64)) < value < prime - (1 << (2048 - 64)):
        raise ProtocolError("Unsafe DH public value")


def temporary_aes(new_nonce: bytes, server_nonce: bytes) -> tuple[bytes, bytes]:
    a = sha1(new_nonce + server_nonce)
    b = sha1(server_nonce + new_nonce)
    return a + b[:12], b[12:] + sha1(new_nonce + new_nonce) + new_nonce[:4]


def message_aes(auth_key: bytes, msg_key: bytes, *, outgoing: bool) -> tuple[bytes, bytes]:
    if len(auth_key) != 256 or len(msg_key) != 16:
        raise ValueError("Invalid MTProto key length")
    x = 0 if outgoing else 8
    a = sha256(msg_key + auth_key[x:x + 36])
    b = sha256(auth_key[40 + x:76 + x] + msg_key)
    return a[:8] + b[8:24] + a[24:32], b[:8] + a[8:24] + b[24:32]


def encrypt_message(auth_key: bytes, plain: bytes, *, outgoing: bool = True) -> bytes:
    padding = (-len(plain)) % 16
    if padding < 12:
        padding += 16
    padded = plain + secrets.token_bytes(padding)
    x = 0 if outgoing else 8
    msg_key = sha256(auth_key[88 + x:120 + x] + padded)[8:24]
    key, iv = message_aes(auth_key, msg_key, outgoing=outgoing)
    return sha1(auth_key)[-8:] + msg_key + aes_ige(padded, key, iv)


def decrypt_message(auth_key: bytes, packet: bytes, *, incoming: bool = True) -> tuple[int, bytes, int, int, bytes]:
    if len(packet) < 72 or (len(packet) - 24) % 16:
        raise ProtocolError("Invalid encrypted MTProto packet length")
    if not hmac.compare_digest(packet[:8], sha1(auth_key)[-8:]):
        raise ProtocolError("Wrong authorization key ID")
    msg_key = packet[8:24]
    key, iv = message_aes(auth_key, msg_key, outgoing=not incoming)
    plain = aes_ige(packet[24:], key, iv, decrypt=True)
    x = 8 if incoming else 0
    expected = sha256(auth_key[88 + x:120 + x] + plain)[8:24]
    if not hmac.compare_digest(expected, msg_key):
        raise ProtocolError("MTProto message authentication failed")
    salt, session, msg_id, seq_no, length = struct.unpack("<q8sqii", plain[:32])
    if length < 0 or length % 4 or length > len(plain) - 32:
        raise ProtocolError("Invalid MTProto body length")
    padding = len(plain) - 32 - length
    if not 12 <= padding <= 1024:
        raise ProtocolError("Invalid MTProto padding length")
    return salt, session, msg_id, seq_no, plain[32:32 + length]


def password_proof(password: str, settings: TLObject) -> TLObject:
    algo = settings.get("current_algo")
    if not algo or algo.name != "passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow":
        raise UnsupportedFeature("Telegram returned an unsupported password KDF")
    p, g = int.from_bytes(algo.p, "big"), algo.g
    validate_dh(p, g)
    B = int.from_bytes(settings.srp_B, "big")
    if not 0 < B < p:
        raise ProtocolError("Unsafe SRP B")
    padded_p, padded_g, padded_B = int_bytes(p, 256), int_bytes(g, 256), int_bytes(B, 256)
    h1 = sha256(algo.salt1 + password.encode() + algo.salt1)
    h2 = sha256(algo.salt2 + h1 + algo.salt2)
    h3 = hashlib.pbkdf2_hmac("sha512", h2, algo.salt1, 100_000)
    x = int.from_bytes(sha256(algo.salt2 + h3 + algo.salt2), "big")
    k = int.from_bytes(sha256(padded_p + padded_g), "big")
    base = (B - k * pow(g, x, p)) % p
    validate_public(base, p)
    for _ in range(128):
        a = int.from_bytes(secrets.token_bytes(256), "big")
        A = pow(g, a, p)
        try:
            validate_public(A, p)
        except ProtocolError:
            continue
        padded_A = int_bytes(A, 256)
        u = int.from_bytes(sha256(padded_A + padded_B), "big")
        if u:
            break
    else:
        raise ProtocolError("Could not generate SRP public value")
    shared = pow(base, a + u * x, p)
    K = sha256(int_bytes(shared, 256))
    M1 = sha256(xor(sha256(padded_p), sha256(padded_g)) + sha256(algo.salt1) + sha256(algo.salt2) + padded_A + padded_B + K)
    return TLObject("inputCheckPasswordSRP", srp_id=settings.srp_id, A=padded_A, M1=M1)
