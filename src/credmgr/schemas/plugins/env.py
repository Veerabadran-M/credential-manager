"""Env schema: flat KEY=VALUE configuration entries.

Decrypted plaintext is one KEY=VALUE pair per line. Blank lines and
lines starting with '#' are ignored on parse, the first '=' splits key
from value, order is preserved, and values are stored verbatim
(untrimmed), so this doubles as a lightweight secrets/config store.
"""

from __future__ import annotations

import difflib

from ...clipboard import copy_to_clipboard
from ...ui import console
from ...validation import validate_text
from ..base import IndexEntry, Schema, SchemaError

MAX_KEY_LENGTH = 256
MAX_VALUE_LENGTH = 8192

class EnvDocument:
    """An ordered list of (key, value) pairs. A plain list rather than a
    dict so insertion order -- and therefore file order on save -- is
    always preserved exactly, including across renames/edits."""

    def __init__(self):
        self.entries: list[tuple[str, str]] = []

    def index_of(self, key: str) -> int:
        for i, (k, _v) in enumerate(self.entries):
            if k == key:
                return i
        return -1

    def get(self, key: str):
        idx = self.index_of(key)
        return self.entries[idx][1] if idx >= 0 else None

    def set(self, key: str, value: str) -> None:
        idx = self.index_of(key)
        if idx >= 0:
            self.entries[idx] = (key, value)
        else:
            self.entries.append((key, value))

    def delete(self, key: str) -> bool:
        idx = self.index_of(key)
        if idx < 0:
            return False
        del self.entries[idx]
        return True

def _validate_key(key: str) -> str:
    try:
        return validate_text(key, "key", max_length=MAX_KEY_LENGTH, allow_chars="=")
    except ValueError as e:
        raise SchemaError(str(e)) from e

def _validate_value(value: str) -> str:
    if value is None:
        raise SchemaError("value is required.")
    if not isinstance(value, str):
        raise SchemaError("value must be text.")
    if len(value) > MAX_VALUE_LENGTH:
        raise SchemaError(f"value must be {MAX_VALUE_LENGTH} characters or fewer.")
    if "\n" in value or "\r" in value:
        raise SchemaError("value cannot contain a newline (one entry per line).")
    return value

def _match_keys(document: EnvDocument, query: str) -> list:
    """Exact match first, then substring, then fuzzy -- same spirit as the
    Credentials schema's service/account search, adapted to a flat list
    of keys instead of a nested service/account tree."""
    keys = [k for k, _v in document.entries]

    exact = [k for k in keys if k == query]
    if exact:
        return exact

    lowered = query.lower()
    partial = [k for k in keys if lowered in k.lower()]
    if partial:
        return partial

    scored = [(difflib.SequenceMatcher(None, lowered, k.lower()).ratio(), k) for k in keys]
    return [k for score, k in sorted(scored, reverse=True) if score >= 0.75]

class EnvSchema(Schema):
    name = "env"

    # ---- parse/serialize ----

    @classmethod
    def new_document(cls) -> EnvDocument:
        return EnvDocument()

    @classmethod
    def parse(cls, plaintext: bytes) -> EnvDocument:
        document = EnvDocument()
        for line in plaintext.decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if "=" not in line:
                continue  # malformed line -- skip rather than fail the whole vault
            key, value = line.split("=", 1)
            key = key.strip()
            if not key:
                continue
            document.entries.append((key, value))
        return document

    @classmethod
    def serialize(cls, document: EnvDocument) -> bytes:
        lines = [f"{k}={v}" for k, v in document.entries]
        text = "\n".join(lines)
        if lines:
            text += "\n"
        return text.encode("utf-8")

    # ---- read ----

    def cmd_list(self, document: EnvDocument, args, config) -> None:
        if not document.entries:
            console.print("No entries stored.", style="bold yellow")
            return
        console.print(f"{len(document.entries)} entr{'y' if len(document.entries) == 1 else 'ies'}:", style="bold magenta")
        for key, _value in document.entries:
            console.print(f"  - {key}", style="white")

    def cmd_list_all(self, document: EnvDocument, config) -> None:
        if not document.entries:
            console.print("No entries stored.", style="bold yellow")
            return
        for key, _value in document.entries:
            console.print(key, style="white")

    def cmd_get(self, document: EnvDocument, args, config) -> None:
        if not args:
            if not document.entries:
                console.print("No entries stored.", style="bold yellow")
                return
            for key, value in document.entries:
                console.print(f"  [bold green]{key}[/bold green] = [white]{value}[/white]")
            return

        if len(args) != 1:
            raise SchemaError("Usage: credmgr get [key]")

        key = args[0]
        matches = _match_keys(document, key)
        if not matches:
            console.print(f"No key matching '{key}' found.", style="bold yellow")
            return

        for k in matches:
            console.print(f"  [bold green]{k}[/bold green] = [white]{document.get(k)}[/white]")

    def cmd_search(self, document: EnvDocument, query: str, config) -> None:
        matches = _match_keys(document, query)
        if not matches:
            console.print(f"No matches for '{query}'.", style="bold yellow")
            return
        console.print(f"\n[bold cyan]{len(matches)} match(es) for '{query}':[/bold cyan]\n")
        for k in matches:
            console.print(f"  [bold green]{k}[/bold green] = [white]{document.get(k)}[/white]")

    def cmd_copy(self, document: EnvDocument, args, config) -> None:
        if len(args) != 1:
            raise SchemaError("Usage: credmgr copy <key>")
        matches = _match_keys(document, args[0])
        if not matches:
            console.print(f"Key '{args[0]}' not found.", style="bold red")
            return
        if len(matches) > 1:
            console.print(f"Ambiguous key '{args[0]}'. Be more specific. Matches: {', '.join(matches)}", style="bold yellow")
            return
        key = matches[0]
        copy_to_clipboard(document.get(key), label=key)

    # ---- write ----

    def cmd_add(self, document: EnvDocument, args, opts: dict, config) -> bool:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr add <KEY> <VALUE>")
        key, value = args
        key = _validate_key(key)
        value = _validate_value(value)

        if document.index_of(key) >= 0:
            console.print(f"Key '{key}' already exists. Use 'update'.", style="bold yellow")
            return False

        document.set(key, value)
        console.print(f"Added '{key}'", style="bold green")
        return True

    def cmd_update(self, document: EnvDocument, args, opts: dict, config) -> bool:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr update <KEY> <VALUE>")
        key, value = args
        key = _validate_key(key)
        value = _validate_value(value)

        if document.index_of(key) < 0:
            console.print(f"Key '{key}' not found. Use 'add'.", style="bold yellow")
            return False

        document.set(key, value)
        console.print(f"Updated '{key}'", style="bold green")
        return True

    def cmd_delete(self, document: EnvDocument, args, config) -> bool:
        if len(args) != 1:
            raise SchemaError("Usage: credmgr delete <KEY>")
        key = args[0]
        matches = _match_keys(document, key)
        if not matches:
            console.print(f"Key '{key}' not found.", style="bold red")
            return False
        if len(matches) > 1:
            console.print(f"Ambiguous key '{key}'. Be more specific. Matches: {', '.join(matches)}", style="bold yellow")
            return False

        document.delete(matches[0])
        console.print(f"Deleted '{matches[0]}'.", style="bold red")
        return True

    def cmd_import(self, document: EnvDocument, filepath: str, config) -> bool:
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except OSError as e:
            console.print(f"Failed to read import file: {e}", style="bold red")
            return False

        imported = EnvSchema.parse(raw)
        if not imported.entries:
            console.print("No valid KEY=VALUE entries found in import file.", style="bold yellow")
            return False

        added = 0
        for key, value in imported.entries:
            if document.index_of(key) >= 0:
                console.print(f"Skipping duplicate: {key}", style="bold yellow")
                continue
            document.entries.append((key, value))
            added += 1

        console.print(f"Import completed ({added} added).", style="bold green")
        return added > 0

    def cmd_export(self, document: EnvDocument, config) -> None:
        print(EnvSchema.serialize(document).decode("utf-8"), end="")

    # ---- global (cross-vault) search index ----

    def index_entries(self, document: EnvDocument) -> list[IndexEntry]:
        return [
            IndexEntry(fields={"lhs": key}, summary=[("Key", key)], args=[key])
            for key, _value in document.entries
        ]
