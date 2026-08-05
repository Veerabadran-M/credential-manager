"""Schema interface implemented by every vault-content plugin.

A schema owns the *shape* of what a vault stores: vault.py only asks it
to turn decrypted bytes into a document (parse) and back (serialize),
then dispatches every CLI command to it generically. New schemas are
discovered automatically from credmgr/schemas/plugins/ (see
registry.py); nothing in vault.py or cli.py needs to change.

Subclass notes: only new_document/parse/serialize are required -- other
cmd_* methods default to raising SchemaError and should be overridden
only for supported operations. `args` is the raw CLI positional argument
list after the command name; `opts` is the shared option-flag dict
(generate, passphrase, length, words, notes). Mutating methods return
True if the document changed and should be persisted.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

class SchemaError(Exception):
    """Raised for both "unknown/invalid input" and "operation not
    supported by this schema" -- the CLI just prints the message."""

@dataclass
class IndexEntry:
    """One searchable row contributed by a schema to the cross-vault
    metadata index (see credmgr/globalindex.py and the `global` CLI
    command). An IndexEntry must never carry a secret value -- only
    identifiers.

    fields:  name -> value, matched case-insensitively/partially by
             `global <query>` against every field of every entry in
             every vault.
    summary: ordered (label, value) pairs shown to the user once a
             search narrows down to this entry (e.g. [("Service",
             "github"), ("User ID", "alice")]).
    args:    the positional args that resolve this exact entry via this
             schema's own `cmd_get(document, args, config)` once the
             owning vault has been unlocked. This is what lets `global`
             retrieve the secret without any schema-specific branching.
    """
    fields: dict[str, str]
    summary: list[tuple[str, str]]
    args: list[str] = field(default_factory=list)

class Schema(ABC):
    name: str

    @classmethod
    @abstractmethod
    def new_document(cls) -> Any:
        """A fresh, empty document for a brand-new vault."""

    @classmethod
    @abstractmethod
    def parse(cls, plaintext: bytes) -> Any:
        """Parse decrypted plaintext bytes into an in-memory document."""

    @classmethod
    @abstractmethod
    def serialize(cls, document: Any) -> bytes:
        """Serialize an in-memory document back to plaintext bytes."""

    # ---- CRUD, dispatched generically by the CLI ----

    def cmd_list(self, document, args: list, config) -> None:
        raise SchemaError(f"'list' is not supported by the '{self.name}' schema.")

    def cmd_list_all(self, document, config) -> None:
        """Print a bare, unfiltered listing of every entry in *this*
        document, schema-shaped: every service with every userid under it
        (credentials), or every key/LHS (env). No counts, no truncation --
        just the identifiers. Called once per vault by the `list-all` CLI
        command, which is the part that walks every vault on disk."""
        raise SchemaError(f"'list-all' is not supported by the '{self.name}' schema.")

    def cmd_get(self, document, args: list, config) -> None:
        raise SchemaError(f"'get' is not supported by the '{self.name}' schema.")

    def cmd_add(self, document, args: list, opts: dict, config) -> bool:
        raise SchemaError(f"'add' is not supported by the '{self.name}' schema.")

    def cmd_update(self, document, args: list, opts: dict, config) -> bool:
        raise SchemaError(f"'update' is not supported by the '{self.name}' schema.")

    def cmd_delete(self, document, args: list, config) -> bool:
        raise SchemaError(f"'delete' is not supported by the '{self.name}' schema.")

    def cmd_search(self, document, query: str, config) -> None:
        raise SchemaError(f"'search' is not supported by the '{self.name}' schema.")

    def cmd_copy(self, document, args: list, config) -> None:
        raise SchemaError(f"'copy' is not supported by the '{self.name}' schema.")

    def cmd_history(self, document, args: list, config) -> None:
        raise SchemaError(f"'history' is not supported by the '{self.name}' schema.")

    def cmd_audit(self, document, config) -> None:
        raise SchemaError(f"'audit' is not supported by the '{self.name}' schema.")

    def cmd_import(self, document, filepath: str, config) -> bool:
        raise SchemaError(f"'import' is not supported by the '{self.name}' schema.")

    def cmd_export(self, document, config) -> None:
        raise SchemaError(f"'export' is not supported by the '{self.name}' schema.")

    def index_entries(self, document) -> list[IndexEntry]:
        """Return one IndexEntry per searchable item in *this* document,
        for the cross-vault metadata index that powers `credmgr global`
        (see credmgr/globalindex.py). Called once per vault, right after
        any command that mutates and saves it, and during index rebuilds
        -- never on every search, which is the whole point of the index.

        Must return only identifiers (service names, userids, key
        names, ...) -- never passwords, values, or other secrets. The
        default raises SchemaError so a schema that doesn't implement
        this simply doesn't participate in `global` search (its vaults
        are skipped, not crashed on)."""
        raise SchemaError(f"'global' indexing is not supported by the '{self.name}' schema.")
