"""Tests for the Text schema plugin: a vault whose document is one
undivided block of decrypted plaintext, addressed by line number for
convenience only.
"""

from __future__ import annotations

import pytest

import credmgr.schemas.plugins.text as text_mod
from credmgr.schemas.base import ContentRequired, SchemaError
from credmgr.schemas.plugins.text import TextDocument, TextSchema
from credmgr.clipboard import ClipboardResult


@pytest.fixture(autouse=True)
def no_clipboard(monkeypatch):
    monkeypatch.setattr(text_mod, "copy_to_clipboard", lambda value, label="Password": ClipboardResult(copied=False, label=label, reason="disabled in tests"))


@pytest.fixture
def schema():
    return TextSchema()


# ---- parse / serialize ----

def test_parse_decodes_utf8():
    doc = TextSchema.parse("hello\nworld\n".encode("utf-8"))
    assert doc.content == "hello\nworld\n"


def test_serialize_round_trips_with_parse():
    doc = TextDocument("some notes\nsecond line\n")
    blob = TextSchema.serialize(doc)
    restored = TextSchema.parse(blob)
    assert restored.content == doc.content


def test_new_document_is_empty():
    assert TextSchema.new_document().content == ""


def test_serialize_empty_document_is_empty_bytes():
    assert TextSchema.serialize(TextDocument()) == b""


# ---- cmd_add ----

def test_cmd_add_appends_line(schema, config):
    doc = TextDocument()
    result = schema.cmd_add(doc, ["first", "line"], {}, config)
    assert result.mutated is True
    assert doc.content == "first line\n"


def test_cmd_add_appends_second_line_after_first(schema, config):
    doc = TextDocument()
    schema.cmd_add(doc, ["line", "one"], {}, config)
    schema.cmd_add(doc, ["line", "two"], {}, config)
    assert doc.content == "line one\nline two\n"


def test_cmd_add_requires_args(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_add(TextDocument(), [], {}, config)


def test_cmd_add_rejects_oversized_content(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_add(TextDocument(), ["x" * (text_mod.MAX_CONTENT_LENGTH + 1)], {}, config)


def test_cmd_add_no_args_raises_content_required(schema, config):
    with pytest.raises(ContentRequired) as excinfo:
        schema.cmd_add(TextDocument(), [], {}, config)
    assert excinfo.value.initial == ""


def test_cmd_add_uses_content_from_opts_when_no_args(schema, config):
    doc = TextDocument("existing\n")
    result = schema.cmd_add(doc, [], {"content": "typed in the editor\n"}, config)
    assert result.mutated is True
    assert doc.content == "existing\ntyped in the editor\n"


def test_cmd_add_blank_editor_content_does_not_mutate(schema, config):
    doc = TextDocument()
    result = schema.cmd_add(doc, [], {"content": "   \n  "}, config)
    assert result.mutated is False
    assert doc.content == ""


def test_cmd_add_single_arg_existing_file_uploads_content(schema, config, tmp_path):
    doc = TextDocument("existing\n")
    path = tmp_path / "notes.txt"
    path.write_text("uploaded content\n", encoding="utf-8")

    result = schema.cmd_add(doc, [str(path)], {}, config)
    assert result.mutated is True
    assert doc.content == "existing\nuploaded content\n"


def test_cmd_add_single_arg_nonexistent_path_treated_as_string(schema, config):
    doc = TextDocument()
    result = schema.cmd_add(doc, ["not-a-real-file.txt"], {}, config)
    assert result.mutated is True
    assert doc.content == "not-a-real-file.txt\n"


def test_cmd_add_empty_file_says_nothing_added(schema, config, tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("", encoding="utf-8")

    result = schema.cmd_add(TextDocument(), [str(path)], {}, config)
    assert result.mutated is False


# ---- cmd_update ----

def test_cmd_update_replaces_entire_content(schema, config):
    doc = TextDocument("old content\n")
    result = schema.cmd_update(doc, ["brand", "new", "content"], {}, config)
    assert result.mutated is True
    assert doc.content == "brand new content"


def test_cmd_update_can_clear_with_empty_string(schema, config):
    doc = TextDocument("old content\n")
    schema.cmd_update(doc, [""], {}, config)
    assert doc.content == ""


def test_cmd_update_requires_args(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_update(TextDocument(), [], {}, config)


def test_cmd_update_no_args_raises_content_required_with_current_content(schema, config):
    doc = TextDocument("old content\n")
    with pytest.raises(ContentRequired) as excinfo:
        schema.cmd_update(doc, [], {}, config)
    assert excinfo.value.initial == "old content\n"


def test_cmd_update_uses_content_from_opts_when_no_args(schema, config):
    doc = TextDocument("old content\n")
    result = schema.cmd_update(doc, [], {"content": "edited content\n"}, config)
    assert result.mutated is True
    assert doc.content == "edited content\n"


def test_cmd_update_single_arg_existing_file_replaces_content(schema, config, tmp_path):
    doc = TextDocument("old content\n")
    path = tmp_path / "notes.txt"
    path.write_text("replacement content\n", encoding="utf-8")

    result = schema.cmd_update(doc, [str(path)], {}, config)
    assert result.mutated is True
    assert doc.content == "replacement content\n"


# ---- cmd_delete ----

def test_cmd_delete_all_needs_confirmation_first(schema, config):
    doc = TextDocument("some text\n")
    result = schema.cmd_delete(doc, [], config)
    assert result.needs_confirmation is True
    assert result.mutated is False
    assert doc.content == "some text\n"


def test_cmd_delete_all_confirmed_clears_content(schema, config):
    doc = TextDocument("some text\n")
    result = schema.cmd_delete(doc, [], config, confirmed=True)
    assert result.mutated is True
    assert doc.content == ""


def test_cmd_delete_empty_vault_returns_false(schema, config):
    result = schema.cmd_delete(TextDocument(), [], config)
    assert result.mutated is False
    assert result.needs_confirmation is False


def test_cmd_delete_single_line_no_confirmation_needed(schema, config):
    doc = TextDocument("line one\nline two\nline three\n")
    result = schema.cmd_delete(doc, ["2"], config)
    assert result.mutated is True
    assert doc.content == "line one\nline three\n"


def test_cmd_delete_rejects_multi_line_range(schema, config):
    doc = TextDocument("a\nb\nc\n")
    with pytest.raises(SchemaError):
        schema.cmd_delete(doc, ["1-2"], config)


def test_cmd_delete_out_of_range_line_raises(schema, config):
    doc = TextDocument("only one line\n")
    with pytest.raises(SchemaError):
        schema.cmd_delete(doc, ["5"], config)


# ---- cmd_get ----

def test_cmd_get_no_args_returns_all_lines(schema, config):
    doc = TextDocument("alpha\nbeta\n")
    result = schema.cmd_get(doc, [], config)
    text = "\n".join(line.text for line in result.lines)
    assert "alpha" in text
    assert "beta" in text


def test_cmd_get_empty_vault(schema, config):
    result = schema.cmd_get(TextDocument(), [], config)
    assert any("empty" in line.text.lower() for line in result.lines)


def test_cmd_get_single_line(schema, config):
    doc = TextDocument("alpha\nbeta\ngamma\n")
    result = schema.cmd_get(doc, ["2"], config)
    text = "\n".join(line.text for line in result.lines)
    assert "beta" in text
    assert "alpha" not in text
    assert "gamma" not in text


def test_cmd_get_line_range(schema, config):
    doc = TextDocument("alpha\nbeta\ngamma\n")
    result = schema.cmd_get(doc, ["1-2"], config)
    text = "\n".join(line.text for line in result.lines)
    assert "alpha" in text
    assert "beta" in text
    assert "gamma" not in text


def test_cmd_get_invalid_line_raises(schema, config):
    doc = TextDocument("only one line\n")
    with pytest.raises(SchemaError):
        schema.cmd_get(doc, ["99"], config)


# ---- cmd_search ----

def test_cmd_search_finds_matching_lines(schema, config):
    doc = TextDocument("the api key is secret\nsome other line\n")
    result = schema.cmd_search(doc, "api key", config)
    text = "\n".join(line.text for line in result.lines)
    assert "api key" in text
    assert "other line" not in text


def test_cmd_search_no_matches(schema, config):
    doc = TextDocument("hello world\n")
    result = schema.cmd_search(doc, "nope", config)
    assert any("no matches" in line.text.lower() for line in result.lines)


def test_cmd_search_requires_query(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_search(TextDocument("x\n"), "", config)


# ---- cmd_copy ----

def test_cmd_copy_whole_content_when_no_args(schema, config, monkeypatch):
    copied = {}
    monkeypatch.setattr(text_mod, "copy_to_clipboard", lambda value, label="Password": copied.update(value=value, label=label) or ClipboardResult(copied=True, label=label, timeout=30))
    doc = TextDocument("full body\n")
    schema.cmd_copy(doc, [], config)
    assert copied["value"] == "full body\n"
    assert copied["label"] == "Vault content"


def test_cmd_copy_single_line(schema, config, monkeypatch):
    copied = {}
    monkeypatch.setattr(text_mod, "copy_to_clipboard", lambda value, label="Password": copied.update(value=value, label=label) or ClipboardResult(copied=True, label=label, timeout=30))
    doc = TextDocument("first\nsecond\n")
    schema.cmd_copy(doc, ["2"], config)
    assert copied["value"] == "second"


def test_cmd_copy_empty_vault(schema, config):
    result = schema.cmd_copy(TextDocument(), [], config)
    assert any("empty" in line.text.lower() for line in result.lines)


# ---- cmd_list ----

def test_cmd_list_empty_vault(schema, config):
    result = schema.cmd_list(TextDocument(), [], config)
    assert any("empty" in line.text.lower() for line in result.lines)


def test_cmd_list_shows_counts_and_preview(schema, config):
    doc = TextDocument("one\ntwo\n")
    result = schema.cmd_list(doc, [], config)
    text = "\n".join(line.text for line in result.lines)
    assert "2 line" in text
    assert "one" in text


def test_cmd_list_truncates_long_content(schema, config):
    doc = TextDocument("\n".join(f"line{i}" for i in range(20)) + "\n")
    result = schema.cmd_list(doc, [], config)
    text = "\n".join(line.text for line in result.lines)
    assert "more line" in text


# ---- cmd_import / cmd_export ----

def test_cmd_import_appends_file_content(schema, config, tmp_path):
    doc = TextDocument("existing\n")
    path = tmp_path / "notes.txt"
    path.write_text("imported text\n", encoding="utf-8")

    result = schema.cmd_import(doc, str(path), config)
    assert result.mutated is True
    assert doc.content == "existing\nimported text\n"


def test_cmd_import_into_empty_document(schema, config, tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("brand new\n", encoding="utf-8")

    doc = TextDocument()
    schema.cmd_import(doc, str(path), config)
    assert doc.content == "brand new\n"


def test_cmd_import_empty_file_returns_false(schema, config, tmp_path):
    path = tmp_path / "empty.txt"
    path.write_text("", encoding="utf-8")

    result = schema.cmd_import(TextDocument(), str(path), config)
    assert result.mutated is False


def test_cmd_import_missing_file_returns_false(schema, config, tmp_path):
    result = schema.cmd_import(TextDocument(), str(tmp_path / "missing.txt"), config)
    assert result.mutated is False


def test_cmd_import_rejects_non_utf8(schema, config, tmp_path):
    path = tmp_path / "binary.txt"
    path.write_bytes(b"\xff\xfe\x00\x01")

    result = schema.cmd_import(TextDocument(), str(path), config)
    assert result.mutated is False


def test_cmd_export_returns_raw_content(schema, config):
    doc = TextDocument("export me\n")
    result = schema.cmd_export(doc, config)
    assert result.raw == "export me\n"


# ---- unsupported operations ----

def test_index_entries_not_supported(schema):
    with pytest.raises(SchemaError):
        schema.index_entries(TextDocument("x\n"))


def test_cmd_list_all_not_supported(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_list_all(TextDocument("x\n"), config)


def test_cmd_history_not_supported(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_history(TextDocument("x\n"), [], config)


def test_cmd_audit_not_supported(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_audit(TextDocument("x\n"), config)
