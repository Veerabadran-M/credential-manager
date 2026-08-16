"""Schema interface implemented by every vault-content plugin.

A schema owns the *shape* of what a vault stores: vault.py only asks it
to turn decrypted bytes into a document (parse) and back (serialize);
the application layer (credmgr/core/manager.py) dispatches every
operation to it generically. New schemas are discovered automatically
from credmgr/schemas/plugins/ (see registry.py); nothing in vault.py or
that layer needs to change.

Schemas are core application code: they must never import Typer, Rich,
or call print()/input() themselves. Instead every cmd_* method returns a
CommandResult -- plain data describing what happened, plus zero or more
user-facing Lines -- and raises SchemaError for usage/validation
problems. Frontends (see credmgr/cli/) turn that into whatever terminal
(or GUI, or REST response, ...) output makes sense for them.

Subclass notes: only new_document/parse/serialize are required -- other
cmd_* methods default to raising SchemaError and should be overridden
only for supported operations. `args` is the raw positional argument
list after the command name; `opts` is the shared option dict (generate,
passphrase, length, words, notes, and -- when the caller isn't
generating one -- password, collected however that frontend collects
secrets). `result.mutated` tells the caller whether the document changed
and should be persisted.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

class SchemaError(Exception):
    """Raised for both "unknown/invalid input" and "operation not
    supported by this schema" -- frontends just surface the message."""

class SecretRequired(SchemaError):
    """Raised by cmd_add/cmd_update when a new secret value (e.g. a
    password) is needed to complete the operation, and neither
    opts["generate"] nor opts["password"] supplied one. This schema
    never collects the value itself -- callers catch this, obtain the
    value however fits them (e.g. a terminal prompt), and retry the
    same call with opts["password"] set."""

    def __init__(self, label: str = "value"):
        self.label = label
        super().__init__(f"A {label.lower()} is required.")

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

@dataclass
class Line:
    """One line of user-facing text with a semantic Rich style string
    (e.g. "bold green", "dim"), or None for the frontend's default
    style. A frontend that doesn't understand Rich styles can just
    print `text` and ignore `style`."""
    text: str = ""
    style: str | None = None

@dataclass
class Table:
    """A simple headers+rows tabular payload (e.g. `get` results across
    several accounts). Frontends are free to render this however suits
    them -- a Rich table, a plain fixed-width table, HTML, ..."""
    headers: list[str]
    rows: list[list[str]]

@dataclass
class CommandResult:
    """What a schema command hands back to its caller (CredentialManager, then
    a frontend) instead of printing or reading from the terminal itself.

    lines:      user-facing messages, in display order.
    table:      optional tabular payload for commands that produce one
                (e.g. `get` against several accounts).
    raw:        optional plain, unstyled text for commands whose output
                is meant to be piped/redirected (e.g. `export`).
    mutated:    True if a write command changed `document`; the caller
                must persist the vault when this is True.
    choices:    for commands that would otherwise need to ask "which one
                did you mean?" interactively (e.g. `copy` against a
                service with several accounts and no userid given):
                the list of values a caller can retry the same command
                with, once it has picked one out-of-band.
    needs_confirmation: True if a *destructive* write command stopped
                short of mutating and is waiting for the caller to retry
                the call with `confirmed=True` (e.g. deleting every
                account under a service at once).
    """
    lines: list[Line] = field(default_factory=list)
    table: Table | None = None
    raw: str | None = None
    mutated: bool = False
    choices: list[Any] | None = None
    needs_confirmation: bool = False

    def say(self, text: str, style: str | None = None) -> "CommandResult":
        """Append a line and return self, so callers can chain a few of
        these before returning."""
        self.lines.append(Line(text, style))
        return self

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

    # ---- CRUD, dispatched generically by CredentialManager ----

    def cmd_list(self, document, args: list, config) -> CommandResult:
        raise SchemaError(f"'list' is not supported by the '{self.name}' schema.")

    def cmd_list_all(self, document, config) -> CommandResult:
        """A bare, unfiltered listing of every entry in *this* document,
        schema-shaped: every service with every userid under it
        (credentials), or every key (env). No counts, no truncation --
        just the identifiers. Used once per vault by the `list-all`
        command, which is the part that walks every vault on disk."""
        raise SchemaError(f"'list-all' is not supported by the '{self.name}' schema.")

    def cmd_get(self, document, args: list, config) -> CommandResult:
        raise SchemaError(f"'get' is not supported by the '{self.name}' schema.")

    def cmd_add(self, document, args: list, opts: dict, config) -> CommandResult:
        raise SchemaError(f"'add' is not supported by the '{self.name}' schema.")

    def cmd_update(self, document, args: list, opts: dict, config) -> CommandResult:
        raise SchemaError(f"'update' is not supported by the '{self.name}' schema.")

    def cmd_delete(self, document, args: list, config, confirmed: bool = False) -> CommandResult:
        raise SchemaError(f"'delete' is not supported by the '{self.name}' schema.")

    def cmd_search(self, document, query: str, config) -> CommandResult:
        raise SchemaError(f"'search' is not supported by the '{self.name}' schema.")

    def cmd_copy(self, document, args: list, config) -> CommandResult:
        raise SchemaError(f"'copy' is not supported by the '{self.name}' schema.")

    def cmd_history(self, document, args: list, config) -> CommandResult:
        raise SchemaError(f"'history' is not supported by the '{self.name}' schema.")

    def cmd_audit(self, document, config) -> CommandResult:
        raise SchemaError(f"'audit' is not supported by the '{self.name}' schema.")

    def cmd_import(self, document, filepath: str, config) -> CommandResult:
        raise SchemaError(f"'import' is not supported by the '{self.name}' schema.")

    def cmd_export(self, document, config) -> CommandResult:
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
