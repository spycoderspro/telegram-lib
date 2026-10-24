# Third-party data and dependencies

EasyProto's Python implementation was written in this repository. It does not
include or require Telethon, Pyrogram, Kurigram or TDLib client code.

## Telegram protocol declarations and public key material

`src/easyproto/schemas/api.tl` and `mtproto.tl` were obtained unchanged from the
official Telegram Desktop repository at commit
`a7f453612f4896ac04d0007a36ab0d377e5bcbcf`. The production/test public RSA key data
and built-in DC addresses come from that repository's `mtproto_dc_options.cpp`.
The test DH group is the public constant from `mtproto_dh_utils.cpp`. These are
protocol declarations, public parameters and interoperability data, not copied
Python client implementations.

Source locations and hashes are recorded in `schemas/provenance.json`. The
upstream license and legal notice are preserved as `schemas/UPSTREAM_LICENSE`
and `schemas/UPSTREAM_LEGAL`. Those files retain the upstream's licensing terms.
Consult those terms before redistribution; this repository does not relicense
upstream material. This package is not an official Telegram product.

## PyCryptodome

PyCryptodome provides the AES primitive, RSA key parsing and primality testing.
Its own license is included with the dependency distribution. EasyProto uses the
normal verified package-manager installation and does not vendor its code.

## Optional cryptg acceleration

The `fast` extra installs cryptg 0.6.0 on Python 3.11+ for native AES-IGE. It
provides cryptographic acceleration, not Telegram transport, sessions, account
methods or a Telethon/Pyrogram client. The independent Python implementation
remains the fallback. Its license is provided by the dependency distribution;
cryptg source is not vendored here.

## Verification references

- Official pinned schema and DC-key URLs: `schemas/provenance.json`.
- MTProto 2.0 description: https://core.telegram.org/mtproto/description
- Authorization key creation: https://core.telegram.org/mtproto/auth_key
- SRP password authentication: https://core.telegram.org/api/srp

The documentation URLs above are references; this cloud's HTTPS proxy denied
access to core.telegram.org during implementation. The official Telegram Desktop
source and protocol declarations were accessible through GitHub. The AES-256-IGE
known-answer test was independently checked against OpenSSL libcrypto.
