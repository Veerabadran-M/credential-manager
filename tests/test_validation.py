"""Tests for shared text-input validation."""

from __future__ import annotations

import pytest

from credmgr.validation import validate_multiline_text, validate_text


# ---- validate_text ----

def test_validate_text_accepts_normal_value():
    assert validate_text("hello", "field", max_length=10) == "hello"


def test_validate_text_rejects_none():
    with pytest.raises(ValueError, match="is required"):
        validate_text(None, "field", max_length=10)


def test_validate_text_rejects_non_string():
    with pytest.raises(ValueError, match="must be text"):
        validate_text(123, "field", max_length=10)


def test_validate_text_rejects_empty_string():
    with pytest.raises(ValueError, match="cannot be empty"):
        validate_text("", "field", max_length=10)


@pytest.mark.parametrize("value", [" hello", "hello ", " hello ", "\thello"])
def test_validate_text_rejects_leading_or_trailing_whitespace(value):
    with pytest.raises(ValueError, match="whitespace"):
        validate_text(value, "field", max_length=10)


def test_validate_text_rejects_too_long():
    with pytest.raises(ValueError, match="10 characters or fewer"):
        validate_text("x" * 11, "field", max_length=10)


def test_validate_text_accepts_exact_max_length():
    assert validate_text("x" * 10, "field", max_length=10) == "x" * 10


def test_validate_text_rejects_control_characters():
    with pytest.raises(ValueError, match="control characters"):
        validate_text("hel\x01lo", "field", max_length=10)


def test_validate_text_rejects_del_character():
    with pytest.raises(ValueError, match="control characters"):
        validate_text("hel\x7flo", "field", max_length=10)


def test_validate_text_allow_chars_rejects_disallowed_char():
    with pytest.raises(ValueError, match="cannot contain '='"):
        validate_text("KEY=VALUE", "key", max_length=20, allow_chars="=")


def test_validate_text_allow_chars_accepts_when_absent():
    assert validate_text("KEYVALUE", "key", max_length=20, allow_chars="=") == "KEYVALUE"


# ---- validate_multiline_text ----

def test_validate_multiline_text_allows_internal_newlines():
    value = "line one\nline two"
    assert validate_multiline_text(value, "notes", max_length=100) == value


def test_validate_multiline_text_allows_tabs():
    value = "col1\tcol2"
    assert validate_multiline_text(value, "notes", max_length=100) == value


def test_validate_multiline_text_rejects_none():
    with pytest.raises(ValueError, match="is required"):
        validate_multiline_text(None, "notes", max_length=100)


def test_validate_multiline_text_rejects_non_string():
    with pytest.raises(ValueError, match="must be text"):
        validate_multiline_text(["a"], "notes", max_length=100)


def test_validate_multiline_text_rejects_too_long():
    with pytest.raises(ValueError, match="fewer"):
        validate_multiline_text("x" * 101, "notes", max_length=100)


def test_validate_multiline_text_allows_empty_string():
    # Unlike validate_text, an empty multiline value (e.g. blank notes) is fine.
    assert validate_multiline_text("", "notes", max_length=100) == ""


def test_validate_multiline_text_rejects_other_control_characters():
    with pytest.raises(ValueError, match="control characters"):
        validate_multiline_text("hel\x01lo", "notes", max_length=100)


def test_validate_multiline_text_rejects_del_character():
    with pytest.raises(ValueError, match="control characters"):
        validate_multiline_text("hel\x7flo", "notes", max_length=100)
