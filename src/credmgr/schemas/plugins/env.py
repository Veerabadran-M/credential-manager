"""Env schema: flat KEY=VALUE configuration entries.

Decrypted plaintext is one KEY=VALUE pair per line. Blank lines and
lines starting with '#' are ignored on parse, the first '=' splits key
from value, order is preserved, and values are stored verbatim
(untrimmed), so this doubles as a lightweight secrets/config store.
"""

from __future__ import annotations

import difflib

from ...clipboard import copy_to_clipboard
from ...validation import validate_text
from ..base import CommandResult, IndexEntry, Schema, SchemaError

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

    def cmd_list(self, document: EnvDocument, args, config) -> CommandResult:
        result = CommandResult()
        if not document.entries:
            return result.say("No entries stored.", "bold yellow")
        result.say(f"{len(document.entries)} entr{'y' if len(document.entries) == 1 else 'ies'}:", "bold magenta")
        for key, _value in document.entries:
            result.say(f"  - {key}", "white")
        return result

    def cmd_list_all(self, document: EnvDocument, config) -> CommandResult:
        result = CommandResult()
        if not document.entries:
            return result.say("No entries stored.", "bold yellow")
        for key, _value in document.entries:
            result.say(key, "white")
        return result

    def cmd_get(self, document: EnvDocument, args, config) -> CommandResult:
        result = CommandResult()
        if not args:
            if not document.entries:
                return result.say("No entries stored.", "bold yellow")
            for key, value in document.entries:
                result.say(f"  {key} = {value}")
            return result

        if len(args) != 1:
            raise SchemaError("Usage: credmgr get [key]")

        key = args[0]
        matches = _match_keys(document, key)
        if not matches:
            return result.say(f"No key matching '{key}' found.", "bold yellow")

        for k in matches:
            result.say(f"  {k} = {document.get(k)}")
        return result

    def cmd_search(self, document: EnvDocument, query: str, config) -> CommandResult:
        result = CommandResult()
        matches = _match_keys(document, query)
        if not matches:
            return result.say(f"No matches for '{query}'.", "bold yellow")
        result.say(f"{len(matches)} match(es) for '{query}':", "bold cyan")
        for k in matches:
            result.say(f"  {k} = {document.get(k)}")
        return result

    def cmd_copy(self, document: EnvDocument, args, config) -> CommandResult:
        if len(args) != 1:
            raise SchemaError("Usage: credmgr copy <key>")
        result = CommandResult()
        matches = _match_keys(document, args[0])
        if not matches:
            return result.say(f"Key '{args[0]}' not found.", "bold red")
        if len(matches) > 1:
            return result.say(f"Ambiguous key '{args[0]}'. Be more specific. Matches: {', '.join(matches)}", "bold yellow")
        key = matches[0]

        clip = copy_to_clipboard(document.get(key), label=key)
        if clip.copied:
            result.say(f"{clip.label} copied to clipboard. Clears in {clip.timeout}s.", "bold green")
        else:
            result.say(f"{clip.label} was not copied ({clip.reason}).", "bold yellow")
        return result

    # ---- write ----

    def cmd_add(self, document: EnvDocument, args, opts: dict, config) -> CommandResult:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr add <KEY> <VALUE>")
        key, value = args
        key = _validate_key(key)
        value = _validate_value(value)

        result = CommandResult()
        if document.index_of(key) >= 0:
            return result.say(f"Key '{key}' already exists. Use 'update'.", "bold yellow")

        document.set(key, value)
        result.say(f"Added '{key}'", "bold green")
        result.mutated = True
        return result

    def cmd_update(self, document: EnvDocument, args, opts: dict, config) -> CommandResult:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr update <KEY> <VALUE>")
        key, value = args
        key = _validate_key(key)
        value = _validate_value(value)

        result = CommandResult()
        if document.index_of(key) < 0:
            return result.say(f"Key '{key}' not found. Use 'add'.", "bold yellow")

        document.set(key, value)
        result.say(f"Updated '{key}'", "bold green")
        result.mutated = True
        return result

    def cmd_delete(self, document: EnvDocument, args, config, confirmed: bool = False) -> CommandResult:
        if len(args) != 1:
            raise SchemaError("Usage: credmgr delete <KEY>")
        key = args[0]
        result = CommandResult()
        matches = _match_keys(document, key)
        if not matches:
            return result.say(f"Key '{key}' not found.", "bold red")
        if len(matches) > 1:
            return result.say(f"Ambiguous key '{key}'. Be more specific. Matches: {', '.join(matches)}", "bold yellow")

        document.delete(matches[0])
        result.say(f"Deleted '{matches[0]}'.", "bold red")
        result.mutated = True
        return result

    def cmd_import(self, document: EnvDocument, filepath: str, config) -> CommandResult:
        result = CommandResult()
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except OSError as e:
            return result.say(f"Failed to read import file: {e}", "bold red")

        imported = EnvSchema.parse(raw)
        if not imported.entries:
            return result.say("No valid KEY=VALUE entries found in import file.", "bold yellow")

        added = 0
        for key, value in imported.entries:
            if document.index_of(key) >= 0:
                result.say(f"Skipping duplicate: {key}", "bold yellow")
                continue
            document.entries.append((key, value))
            added += 1

        result.say(f"Import completed ({added} added).", "bold green")
        result.mutated = added > 0
        return result

    def cmd_export(self, document: EnvDocument, config) -> CommandResult:
        return CommandResult(raw=EnvSchema.serialize(document).decode("utf-8"))

    # ---- global (cross-vault) search index ----

    def index_entries(self, document: EnvDocument) -> list[IndexEntry]:
        return [
            IndexEntry(fields={"key": key}, summary=[("Key", key)], args=[key])
            for key, _value in document.entries
        ]
