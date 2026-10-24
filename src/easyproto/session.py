"""Small private, atomic JSON sessions. Incompatible formats fail explicitly."""
from __future__ import annotations

import base64
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ProtocolError

PRODUCTION_DCS = {1: "149.154.175.50", 2: "149.154.167.51", 3: "149.154.175.100", 4: "149.154.167.91", 5: "149.154.171.5"}
TEST_DCS = {1: "149.154.175.10", 2: "149.154.167.40", 3: "149.154.175.117"}


@dataclass
class Session:
    path: Path | None
    dc_id: int = 2
    test_mode: bool = False
    auth_key: bytes = field(default=b"", repr=False)
    salt: int = 0
    user_id: int | None = None
    time_offset: float = 0
    _lock_file: object = field(default=None, init=False, repr=False)

    @classmethod
    def load(cls, path: str | Path, *, dc_id: int = 2, test_mode: bool = False) -> Session:
        if str(path) == ":memory:":
            return cls(None, dc_id, test_mode)
        target = Path(path).expanduser()
        if target.suffix != ".json":
            target = Path(str(target) + ".easyproto.json")
        if not target.exists():
            return cls(target, dc_id, test_mode)
        if not target.is_file() or target.is_symlink() or (os.name != "nt" and target.stat().st_mode & 0o077):
            raise PermissionError("Session must be a private regular file (mode 0600)")
        if target.stat().st_size > 16_384:
            raise ProtocolError("Session file exceeds size limit")
        try:
            data = json.loads(target.read_text())
            if data.pop("format") != "easyproto-mtproto-1":
                raise ValueError("Unknown session format")
            key = base64.b64decode(data.pop("auth_key"), validate=True)
            if len(key) not in (0, 256):
                raise ValueError("Invalid auth key length")
            result = cls(target, auth_key=key, **data)
            if result.test_mode != test_mode:
                raise ValueError("Session belongs to a different Telegram environment")
            if result.dc_id not in (TEST_DCS if test_mode else PRODUCTION_DCS):
                raise ValueError("Unknown data center")
            return result
        except (ValueError, KeyError, TypeError) as exc:
            raise ProtocolError("Invalid EasyProto session; legacy Telethon sessions cannot be imported") from exc

    @property
    def host(self) -> str:
        return (TEST_DCS if self.test_mode else PRODUCTION_DCS)[self.dc_id]

    def acquire(self) -> None:
        if self.path is None or self._lock_file is not None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = Path(str(self.path) + ".lock")
        if lock_path.is_symlink():
            raise PermissionError("Refusing a session lock symlink")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        stream = os.fdopen(fd, "r+b")
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    stream.write(b"\0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            raise RuntimeError("Session is already in use by another client") from exc
        self._lock_file = stream

    def release(self) -> None:
        if self._lock_file is not None:
            self._lock_file.close()
            self._lock_file = None

    def save(self) -> None:
        if self.path is None:
            return
        if self.path.is_symlink():
            raise PermissionError("Refusing to replace a session symlink")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"format": "easyproto-mtproto-1", "dc_id": self.dc_id, "test_mode": self.test_mode,
                "auth_key": base64.b64encode(self.auth_key).decode(), "salt": self.salt,
                "user_id": self.user_id, "time_offset": self.time_offset}
        fd, name = tempfile.mkstemp(prefix=".easyproto-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w") as stream:
                if hasattr(os, "fchmod"):
                    os.fchmod(stream.fileno(), 0o600)
                json.dump(data, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
