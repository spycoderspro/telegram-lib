"""Explicit errors from the independent client and Telegram RPCs."""
from __future__ import annotations

import re


class ProtocolError(Exception):
    """Malformed, unauthenticated, or unsupported protocol data."""


class AuthorizationRequired(Exception):
    """The session needs an explicit user login."""


class UnsupportedFeature(Exception):
    """A feature is not implemented; no silent fallback is made."""


class RPCError(Exception):
    def __init__(self, code: int, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Telegram RPC {code}: {message}")


class FloodWaitError(RPCError):
    def __init__(self, code: int, message: str, seconds: int) -> None:
        self.seconds = seconds
        super().__init__(code, message)


class MigrationRequired(RPCError):
    def __init__(self, code: int, message: str, dc_id: int) -> None:
        self.dc_id = dc_id
        super().__init__(code, message)


def rpc_error(code: int, message: str) -> RPCError:
    if match := re.fullmatch(r"(?:FLOOD_WAIT|FLOOD_PREMIUM_WAIT|SLOWMODE_WAIT)_(\d+)", message):
        return FloodWaitError(code, message, int(match[1]))
    if match := re.fullmatch(r"(?:PHONE|NETWORK|USER|FILE)_MIGRATE_(\d+)", message):
        return MigrationRequired(code, message, int(match[1]))
    return RPCError(code, message)
