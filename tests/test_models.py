"""Tests for the plain-data models: round-trip to/from dict, defaults,
and nested history serialization.
"""

from __future__ import annotations

from credmgr.models import Account, Credentials, PasswordHistoryEntry


def test_password_history_entry_round_trip():
    entry = PasswordHistoryEntry(password="old-pw", changed_at=123.5)
    d = entry.to_dict()
    assert d == {"password": "old-pw", "changed_at": 123.5}

    restored = PasswordHistoryEntry.from_dict(d)
    assert restored.password == "old-pw"
    assert restored.changed_at == 123.5


def test_account_default_timestamps_and_history():
    acc = Account(userid="alice", password="secret", notes="n")
    assert acc.history == []
    assert isinstance(acc.created_at, float)
    assert isinstance(acc.updated_at, float)


def test_account_to_dict_includes_history():
    acc = Account(userid="alice", password="secret", notes="n", created_at=1.0, updated_at=2.0)
    acc.history.append(PasswordHistoryEntry(password="older", changed_at=0.5))

    d = acc.to_dict()
    assert d["userid"] == "alice"
    assert d["password"] == "secret"
    assert d["notes"] == "n"
    assert d["created_at"] == 1.0
    assert d["updated_at"] == 2.0
    assert d["history"] == [{"password": "older", "changed_at": 0.5}]


def test_account_from_dict_round_trip():
    d = {
        "userid": "bob",
        "password": "pw",
        "notes": "some notes",
        "created_at": 10.0,
        "updated_at": 20.0,
        "history": [{"password": "pw0", "changed_at": 5.0}],
    }
    acc = Account.from_dict(d)
    assert acc.userid == "bob"
    assert acc.password == "pw"
    assert acc.notes == "some notes"
    assert acc.created_at == 10.0
    assert acc.updated_at == 20.0
    assert len(acc.history) == 1
    assert acc.history[0].password == "pw0"


def test_account_from_dict_defaults_missing_optional_fields():
    d = {"userid": "carol", "password": "pw"}
    acc = Account.from_dict(d)
    assert acc.notes == ""
    assert acc.history == []
    assert isinstance(acc.created_at, float)
    assert isinstance(acc.updated_at, float)


def test_credentials_to_dict_and_from_dict_round_trip():
    creds = Credentials()
    creds.services["github"] = [
        Account(userid="alice", password="p1", notes="", created_at=1.0, updated_at=1.0),
        Account(userid="bob", password="p2", notes="", created_at=1.0, updated_at=1.0),
    ]

    d = creds.to_dict()
    assert set(d.keys()) == {"github"}
    assert len(d["github"]) == 2

    restored = Credentials.from_dict(d)
    assert list(restored.services.keys()) == ["github"]
    assert restored.services["github"][0].userid == "alice"
    assert restored.services["github"][1].userid == "bob"


def test_credentials_from_dict_empty():
    creds = Credentials.from_dict({})
    assert creds.services == {}


def test_credentials_default_services_is_independent_between_instances():
    """Guard against a shared mutable default (a classic dataclass footgun)."""
    a = Credentials()
    b = Credentials()
    a.services["x"] = []
    assert b.services == {}
