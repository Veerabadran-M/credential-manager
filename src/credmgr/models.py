"""Data models for the credentials schema.

Plain data only; the whole tree is serialized to JSON and encrypted as a
single blob (see vault.py, credmgr/schemas/plugins/credentials.py).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

@dataclass
class PasswordHistoryEntry:
    password: str
    changed_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"password": self.password, "changed_at": self.changed_at}

    @staticmethod
    def from_dict(d: dict) -> "PasswordHistoryEntry":
        return PasswordHistoryEntry(password=d["password"], changed_at=d["changed_at"])

@dataclass
class Account:
    userid: str
    password: str
    notes: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    history: list = field(default_factory=list)   # list[PasswordHistoryEntry]

    def to_dict(self) -> dict:
        return {
            "userid": self.userid,
            "password": self.password,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "history": [h.to_dict() for h in self.history]
        }

    @staticmethod
    def from_dict(d: dict) -> "Account":
        return Account(
            userid=d["userid"],
            password=d["password"],
            notes=d.get("notes", ""),
            created_at=d.get("created_at", time.time()),
            updated_at=d.get("updated_at", time.time()),
            history=[PasswordHistoryEntry.from_dict(h) for h in d.get("history", [])]
        )

@dataclass
class Credentials:
    services: dict = field(default_factory=dict)   # dict[str, list[Account]]

    def to_dict(self) -> dict:
        return {
            service: [acc.to_dict() for acc in accounts]
            for service, accounts in self.services.items()
        }

    @staticmethod
    def from_dict(d: dict) -> "Credentials":
        creds = Credentials()
        for service, accounts in d.items():
            creds.services[service] = [Account.from_dict(a) for a in accounts]
        return creds