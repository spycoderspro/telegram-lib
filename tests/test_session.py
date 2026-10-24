import os

import pytest

from easyproto.errors import ProtocolError
from easyproto.session import Session


def test_memory_session_creates_no_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    session = Session.load(':memory:')
    session.acquire(); session.save(); session.release()
    assert list(tmp_path.iterdir()) == []


def test_private_atomic_roundtrip(tmp_path):
    session = Session.load(tmp_path / 'account')
    session.auth_key = bytes(range(256)); session.user_id = 123
    session.salt = -12; session.time_offset = 3.5
    session.save()
    assert session.path.stat().st_mode & 0o777 == 0o600
    other = Session.load(tmp_path / 'account')
    assert other == session
    assert session.auth_key.hex() not in repr(session)
    assert not list(tmp_path.glob('.easyproto-*'))


def test_unsafe_or_corrupt_session_rejected(tmp_path):
    path = tmp_path / 'session.json'; path.write_text('{}'); path.chmod(0o600)
    with pytest.raises(ProtocolError): Session.load(path)
    path.chmod(0o644)
    with pytest.raises(PermissionError): Session.load(path)


def test_session_lock_excludes_other_clients(tmp_path):
    a, b = Session.load(tmp_path/'one'), Session.load(tmp_path/'one')
    a.acquire()
    try:
        with pytest.raises(RuntimeError, match='already in use'): b.acquire()
    finally:
        a.release()
    b.acquire(); b.release()


def test_test_and_production_sessions_are_not_interchangeable(tmp_path):
    session = Session.load(tmp_path/'test', test_mode=True); session.save()
    with pytest.raises(ProtocolError): Session.load(tmp_path/'test')
