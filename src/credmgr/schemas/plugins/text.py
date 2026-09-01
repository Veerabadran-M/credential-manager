"""Text schema: a vault that is, in effect, one encrypted text file.

Unlike `credentials` (a service/account tree) or `env` (a flat list of
KEY=VALUE pairs), this schema has no keyed entries at all -- the
decrypted plaintext *is* the document, verbatim. It's the right choice
for a vault that just needs to hold a secret note, a private key, a
block of freeform text, or anything else that doesn't naturally split
into named fields.

Because there are no identifiers to speak of, this schema does not
implement `index_entries()` / `cmd_list_all()` / `cmd_history()` /
`cmd_audit()` -- the defaults (raise SchemaError) are correct here: a
`text` vault simply doesn't participate in `credmgr global` or
`credmgr list-all`, and has no service/account concept to audit or
version. `list`/`get`/`search`/`copy` treat the content as a list of
lines (1-indexed, matching how most editors and `grep -n` count them)
purely for addressing convenience -- the stored document is still one
undivided string, not a list.
"""

from __future__ import annotations

import os

from ...clipboard import copy_to_clipboard
from ...validation import validate_multiline_text
from ..base import CommandResult, ContentRequired, Schema, SchemaError

MAX_CONTENT_LENGTH = 1_000_000  # ~1 MB of text per vault
PREVIEW_LINES = 5

class TextDocument:
    """The entire decrypted vault content, as a single string. Kept in
    a mutable wrapper (rather than passing a bare `str` around) so
    schema commands can update `.content` in place and have that
    change visible to the caller that holds the reference."""

    def __init__(self, content: str = ""):
        self.content = content

def _lines(document: TextDocument) -> list[str]:
    return document.content.splitlines()

def _parse_line_ref(ref: str, total: int) -> tuple[int, int]:
    """Parse a 1-indexed line number ("3") or inclusive range ("3-5")
    into a 0-indexed [start, end) slice over `total` lines. Raises
    SchemaError on anything malformed or out of bounds."""
    if total == 0:
        raise SchemaError("Vault is empty.")

    if "-" in ref[1:]:  # skip index 0 so a leading '-' isn't mistaken for a range
        start_s, _, end_s = ref.partition("-")
    else:
        start_s = end_s = ref

    try:
        start, end = int(start_s), int(end_s)
    except ValueError:
        raise SchemaError(f"Invalid line reference '{ref}'. Use a line number or 'start-end'.")

    if start < 1 or end < start:
        raise SchemaError(f"Invalid line reference '{ref}'.")
    if start > total:
        raise SchemaError(f"Vault only has {total} line(s).")

    return start - 1, min(end, total)

def _validate_content(text: str) -> str:
    try:
        return validate_multiline_text(text, "text", max_length=MAX_CONTENT_LENGTH)
    except ValueError as e:
        raise SchemaError(str(e)) from e

def _looks_like_file(arg: str) -> bool:
    """True if `arg` names an existing regular file, i.e. `add`/`update`
    should treat it as "upload this file's content" rather than as the
    literal text to store. `os.path.isfile` already swallows OSError
    (permission issues, names too long to even stat, ...) and just
    returns False, so this never raises."""
    return os.path.isfile(arg)

def _read_file_content(filepath: str) -> str:
    try:
        with open(filepath, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise SchemaError(f"Failed to read '{filepath}': {e}") from e

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise SchemaError(f"'{filepath}' is not valid UTF-8 text: {e}") from e

def _append_raw(document: TextDocument, text: str) -> None:
    """Append `text` verbatim -- preserving whatever internal line
    breaks (or lack of them) it already has -- separated from any
    existing content by exactly one newline. Used for content that
    arrives as a ready-made block (a file, or the editor) rather than
    as words to be joined into a single new line."""
    if document.content and not document.content.endswith("\n"):
        document.content += "\n"
    document.content += text

class TextSchema(Schema):
    name = "text"

    # ---- parse/serialize ----

    @classmethod
    def new_document(cls) -> TextDocument:
        return TextDocument()

    @classmethod
    def parse(cls, plaintext: bytes) -> TextDocument:
        return TextDocument(plaintext.decode("utf-8"))

    @classmethod
    def serialize(cls, document: TextDocument) -> bytes:
        return document.content.encode("utf-8")

    # ---- read ----

    def cmd_list(self, document: TextDocument, args, config) -> CommandResult:
        result = CommandResult()
        if not document.content:
            return result.say("Vault is empty.", "bold yellow")

        lines = _lines(document)
        words = len(document.content.split())
        result.say(f"{len(lines)} line(s), {words} word(s), {len(document.content)} character(s).", "bold magenta")
        for i, line in enumerate(lines[:PREVIEW_LINES], start=1):
            result.say(f"  {i}: {line}")
        if len(lines) > PREVIEW_LINES:
            result.say(f"  ... ({len(lines) - PREVIEW_LINES} more line(s))", "dim")
        return result

    def cmd_get(self, document: TextDocument, args, config) -> CommandResult:
        result = CommandResult()
        lines = _lines(document)

        if not args:
            if not lines:
                return result.say("Vault is empty.", "bold yellow")
            for line in lines:
                result.say(line)
            return result

        if len(args) != 1:
            raise SchemaError("Usage: credmgr get [line|start-end]")

        start, end = _parse_line_ref(args[0], len(lines))
        for i in range(start, end):
            result.say(f"{i + 1}: {lines[i]}")
        return result

    def cmd_search(self, document: TextDocument, query: str, config) -> CommandResult:
        result = CommandResult()
        if not query:
            raise SchemaError("Usage: credmgr search <text>")

        lowered = query.lower()
        matches = [(i + 1, line) for i, line in enumerate(_lines(document)) if lowered in line.lower()]
        if not matches:
            return result.say(f"No matches for '{query}'.", "bold yellow")

        result.say(f"{len(matches)} match(es) for '{query}':", "bold cyan")
        for lineno, line in matches:
            result.say(f"  {lineno}: {line}")
        return result

    def cmd_copy(self, document: TextDocument, args, config) -> CommandResult:
        result = CommandResult()
        if not document.content:
            return result.say("Vault is empty -- nothing to copy.", "bold yellow")

        if not args:
            value, label = document.content, "Vault content"
        else:
            if len(args) != 1:
                raise SchemaError("Usage: credmgr copy [line]")
            lines = _lines(document)
            start, end = _parse_line_ref(args[0], len(lines))
            if end != start + 1:
                raise SchemaError("Only a single line can be copied at a time.")
            value, label = lines[start], f"Line {start + 1}"

        clip = copy_to_clipboard(value, label=label)
        if clip.copied:
            result.say(f"{clip.label} copied to clipboard. Clears in {clip.timeout}s.", "bold green")
        else:
            result.say(f"{clip.label} was not copied ({clip.reason}).", "bold yellow")
        return result

    # ---- write ----

    def cmd_add(self, document: TextDocument, args, opts: dict, config) -> CommandResult:
        """Adds content to the vault, in one of three ways:

          * `add <path>` -- a single argument naming an existing file
            uploads that file's content, appended verbatim (like
            `import`).
          * `add` (no arguments) -- raises ContentRequired so the
            caller can open an editor and retry with opts["content"]
            set to what the user wrote.
          * `add <text...>` -- args are joined with a single space and
            appended as one new line, same as always.
        """
        result = CommandResult()

        if not args:
            content = opts.get("content")
            if content is None:
                raise ContentRequired("")
            text = _validate_content(content)
            if not text.strip():
                return result.say("No content entered -- nothing added.", "bold yellow")
            if len(document.content) + len(text) > MAX_CONTENT_LENGTH:
                raise SchemaError(f"Vault content would exceed the {MAX_CONTENT_LENGTH}-character limit.")
            _append_raw(document, text)
            result.say(f"Appended {len(text)} character(s) from the editor.", "bold green")
            result.mutated = True
            return result

        if len(args) == 1 and _looks_like_file(args[0]):
            filepath = args[0]
            text = _validate_content(_read_file_content(filepath))
            if not text:
                return result.say(f"'{filepath}' is empty -- nothing to add.", "bold yellow")
            if len(document.content) + len(text) > MAX_CONTENT_LENGTH:
                raise SchemaError(f"Vault content would exceed the {MAX_CONTENT_LENGTH}-character limit.")
            _append_raw(document, text)
            result.say(f"Added {len(text)} character(s) from '{filepath}'.", "bold green")
            result.mutated = True
            return result

        text = _validate_content(" ".join(args))
        projected = len(document.content) + len(text) + 1
        if projected > MAX_CONTENT_LENGTH:
            raise SchemaError(f"Vault content would exceed the {MAX_CONTENT_LENGTH}-character limit.")

        if document.content and not document.content.endswith("\n"):
            document.content += "\n"
        document.content += text + "\n"
        result.say(f"Appended line {len(_lines(document))}.", "bold green")
        result.mutated = True
        return result

    def cmd_update(self, document: TextDocument, args, opts: dict, config) -> CommandResult:
        """Replaces the entire vault content, in the same three ways as
        `add`: an existing filepath uploads that file's content, no
        arguments raises ContentRequired (with the *current* content as
        the editor's starting point, so the user edits in place), and
        any other args are joined with a single space and stored
        verbatim. Pass a single empty-string argument to clear the
        vault without a confirmation prompt.
        """
        result = CommandResult()

        if not args:
            content = opts.get("content")
            if content is None:
                raise ContentRequired(document.content)
            document.content = _validate_content(content)
            result.say("Vault content replaced from the editor.", "bold green")
            result.mutated = True
            return result

        if len(args) == 1 and _looks_like_file(args[0]):
            filepath = args[0]
            document.content = _validate_content(_read_file_content(filepath))
            result.say(f"Vault content replaced with '{filepath}'.", "bold green")
            result.mutated = True
            return result

        document.content = _validate_content(" ".join(args))
        result.say("Vault content replaced.", "bold green")
        result.mutated = True
        return result

    def cmd_delete(self, document: TextDocument, args, config, confirmed: bool = False) -> CommandResult:
        result = CommandResult()
        if not document.content:
            return result.say("Vault is already empty.", "bold yellow")

        if not args:
            lines = _lines(document)
            if not confirmed:
                result.say(f"Delete all {len(lines)} line(s) of vault content?", "bold yellow")
                result.needs_confirmation = True
                return result
            document.content = ""
            result.say("Vault content cleared.", "bold red")
            result.mutated = True
            return result

        if len(args) != 1:
            raise SchemaError("Usage: credmgr delete [line]")

        lines = _lines(document)
        start, end = _parse_line_ref(args[0], len(lines))
        if end != start + 1:
            raise SchemaError("Only a single line can be deleted at a time.")

        removed = lines.pop(start)
        document.content = ("\n".join(lines) + "\n") if lines else ""
        result.say(f"Deleted line {start + 1}: {removed}", "bold red")
        result.mutated = True
        return result

    def cmd_import(self, document: TextDocument, filepath: str, config) -> CommandResult:
        """Appends the file's content to whatever is already stored,
        the same additive spirit as `credentials`/`env` import (neither
        of which clobbers existing data either)."""
        result = CommandResult()
        try:
            with open(filepath, "rb") as f:
                raw = f.read()
        except OSError as e:
            return result.say(f"Failed to read import file: {e}", "bold red")

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            return result.say(f"Import file is not valid UTF-8 text: {e}", "bold red")

        if not text:
            return result.say("Import file is empty -- nothing to add.", "bold yellow")
        if len(document.content) + len(text) > MAX_CONTENT_LENGTH:
            return result.say(f"Import would exceed the {MAX_CONTENT_LENGTH}-character vault limit.", "bold red")

        if document.content and not document.content.endswith("\n"):
            document.content += "\n"
        document.content += text
        result.say(f"Imported {len(text)} character(s) from '{filepath}'.", "bold green")
        result.mutated = True
        return result

    def cmd_export(self, document: TextDocument, config) -> CommandResult:
        return CommandResult(raw=document.content)