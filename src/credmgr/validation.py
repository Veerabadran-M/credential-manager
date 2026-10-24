"""Shared text-input validation used across schema plugins.

Kept separate from any one schema so new schemas get the same baseline validation for free.
"""

from __future__ import annotations

def validate_text(value: str | None, name: str, *, max_length: int, reject_chars: str | None = None) -> str:
    """Validate a single-line text field.

    Raises ValueError with a human-readable message on failure and returns
    `value` unchanged on success.

    `reject_chars`, if given, specifies additional characters that are not
    allowed.
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
    if reject_chars:
        for ch in reject_chars:
            if ch in value:
                raise ValueError(f"{name} cannot contain '{ch}'.")
    return value

def validate_multiline_text(value: str | None, name: str, *, max_length: int) -> str:
    """Validate a multiline text field.

    Allows newlines, tabs, surrounding whitespace, and empty/blank
    values (callers decide what blank means). Raises ValueError
    with a human-readable message on failure and returns `value` unchanged
    on success.
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