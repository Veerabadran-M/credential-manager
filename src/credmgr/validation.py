"""Shared text-input validation used across schema plugins.

Kept separate from any one schema so new schemas (SSH config, notes,
certificates, ...) get the same baseline validation for free.
"""

from __future__ import annotations

def validate_text(value: str, name: str, *, max_length: int, allow_chars: str | None = None) -> str:
    """Validate a single-line text field. Raises ValueError with a
    human-readable message on failure; returns `value` unchanged on success.

    `allow_chars`, if given, is a string of extra characters to reject
    (e.g. "=" for env keys, where it's the parser's delimiter).
    """
    if value is None:
        raise ValueError(f"{name} is required.")
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text.")
    if value != value.strip():
        raise ValueError(f"{name} cannot start or end with whitespace.")
    if not value:
        raise ValueError(f"{name} cannot be empty.")
    if len(value) > max_length:
        raise ValueError(f"{name} must be {max_length} characters or fewer.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} cannot contain control characters.")
    if allow_chars:
        for ch in allow_chars:
            if ch in value:
                raise ValueError(f"{name} cannot contain '{ch}'.")
    return value

def validate_multiline_text(value: str, name: str, *, max_length: int) -> str:
    """Like validate_text, but allows internal newlines/whitespace (e.g. a
    stored value or notes field) -- only rejects other control characters
    and disallows a leading/trailing-whitespace-only value.
    """
    if value is None:
        raise ValueError(f"{name} is required.")
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text.")
    if len(value) > max_length:
        raise ValueError(f"{name} must be {max_length} characters or fewer.")
    if any((ord(ch) < 32 and ch not in ("\n", "\t")) or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} cannot contain control characters.")
    return value
