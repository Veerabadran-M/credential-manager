"""Tests for the Env schema plugin: parse/serialize of KEY=VALUE text and
the CRUD command implementations.
"""

from __future__ import annotations

import pytest

import credmgr.schemas.plugins.env as env_mod
from credmgr.schemas.base import SchemaError
from credmgr.schemas.plugins.env import EnvDocument, EnvSchema


@pytest.fixture(autouse=True)
def no_clipboard(monkeypatch):
    monkeypatch.setattr(env_mod, "copy_to_clipboard", lambda value, label="Password": None)


@pytest.fixture
def schema():
    return EnvSchema()


# ---- EnvDocument ----

def test_env_document_set_and_get():
    doc = EnvDocument()
    doc.set("KEY", "value")
    assert doc.get("KEY") == "value"


def test_env_document_set_updates_existing_key_in_place():
    doc = EnvDocument()
    doc.set("KEY", "one")
    doc.set("OTHER", "x")
    doc.set("KEY", "two")
    assert [k for k, _ in doc.entries] == ["KEY", "OTHER"]
    assert doc.get("KEY") == "two"


def test_env_document_get_missing_key_returns_none():
    doc = EnvDocument()
    assert doc.get("MISSING") is None


def test_env_document_delete_existing_key():
    doc = EnvDocument()
    doc.set("KEY", "value")
    assert doc.delete("KEY") is True
    assert doc.get("KEY") is None


def test_env_document_delete_missing_key_returns_false():
    doc = EnvDocument()
    assert doc.delete("MISSING") is False


# ---- parse / serialize ----

def test_parse_basic_key_value_lines():
    doc = EnvSchema.parse(b"KEY1=value1\nKEY2=value2\n")
    assert doc.entries == [("KEY1", "value1"), ("KEY2", "value2")]


def test_parse_ignores_blank_lines_and_comments():
    doc = EnvSchema.parse(b"# a comment\n\nKEY=value\n")
    assert doc.entries == [("KEY", "value")]


def test_parse_ignores_malformed_lines_without_equals():
    doc = EnvSchema.parse(b"not-a-kv-line\nKEY=value\n")
    assert doc.entries == [("KEY", "value")]


def test_parse_preserves_value_with_embedded_equals():
    doc = EnvSchema.parse(b"KEY=a=b=c\n")
    assert doc.get("KEY") == "a=b=c"


def test_parse_skips_line_with_empty_key():
    doc = EnvSchema.parse(b"=value\nKEY=value2\n")
    assert doc.entries == [("KEY", "value2")]


def test_serialize_round_trips_with_parse():
    doc = EnvDocument()
    doc.set("A", "1")
    doc.set("B", "2")
    blob = EnvSchema.serialize(doc)
    restored = EnvSchema.parse(blob)
    assert restored.entries == [("A", "1"), ("B", "2")]


def test_serialize_empty_document_is_empty_bytes():
    assert EnvSchema.serialize(EnvDocument()) == b""


# ---- cmd_add / cmd_update / cmd_delete ----

def test_cmd_add_creates_entry(schema, config):
    doc = EnvDocument()
    changed = schema.cmd_add(doc, ["API_KEY", "secret123"], {}, config)
    assert changed is True
    assert doc.get("API_KEY") == "secret123"


def test_cmd_add_duplicate_key_rejected(schema, config):
    doc = EnvDocument()
    schema.cmd_add(doc, ["API_KEY", "one"], {}, config)
    changed = schema.cmd_add(doc, ["API_KEY", "two"], {}, config)
    assert changed is False
    assert doc.get("API_KEY") == "one"


def test_cmd_add_rejects_key_with_equals(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_add(EnvDocument(), ["KEY=X", "value"], {}, config)


def test_cmd_add_rejects_value_with_newline(schema, config):
    with pytest.raises(SchemaError, match="newline"):
        schema.cmd_add(EnvDocument(), ["KEY", "line1\nline2"], {}, config)


def test_cmd_update_existing_key(schema, config):
    doc = EnvDocument()
    schema.cmd_add(doc, ["API_KEY", "old"], {}, config)
    changed = schema.cmd_update(doc, ["API_KEY", "new"], {}, config)
    assert changed is True
    assert doc.get("API_KEY") == "new"


def test_cmd_update_missing_key_returns_false(schema, config):
    changed = schema.cmd_update(EnvDocument(), ["API_KEY", "new"], {}, config)
    assert changed is False


def test_cmd_delete_existing_key(schema, config):
    doc = EnvDocument()
    schema.cmd_add(doc, ["API_KEY", "value"], {}, config)
    changed = schema.cmd_delete(doc, ["API_KEY"], config)
    assert changed is True
    assert doc.get("API_KEY") is None


def test_cmd_delete_missing_key_returns_false(schema, config):
    changed = schema.cmd_delete(EnvDocument(), ["API_KEY"], config)
    assert changed is False


def test_cmd_delete_ambiguous_key_returns_false(schema, config):
    doc = EnvDocument()
    schema.cmd_add(doc, ["API_KEY_ONE", "v"], {}, config)
    schema.cmd_add(doc, ["API_KEY_TWO", "v"], {}, config)
    changed = schema.cmd_delete(doc, ["API_KEY"], config)
    assert changed is False


# ---- cmd_get / cmd_search ----

def test_cmd_get_all_entries(schema, config, capsys):
    doc = EnvDocument()
    schema.cmd_add(doc, ["API_KEY", "secret"], {}, config)
    schema.cmd_get(doc, [], config)
    out = capsys.readouterr().out
    assert "API_KEY" in out
    assert "secret" in out


def test_cmd_get_specific_key(schema, config, capsys):
    doc = EnvDocument()
    schema.cmd_add(doc, ["API_KEY", "secret"], {}, config)
    schema.cmd_get(doc, ["API_KEY"], config)
    out = capsys.readouterr().out
    assert "secret" in out


def test_cmd_search_partial_match(schema, config, capsys):
    doc = EnvDocument()
    schema.cmd_add(doc, ["DATABASE_URL", "postgres://x"], {}, config)
    schema.cmd_search(doc, "DATABASE", config)
    out = capsys.readouterr().out
    assert "DATABASE_URL" in out


# ---- cmd_import / cmd_export ----

def test_cmd_import_adds_new_entries(schema, config, tmp_path):
    doc = EnvDocument()
    path = tmp_path / "env.txt"
    path.write_text("A=1\nB=2\n", encoding="utf-8")

    changed = schema.cmd_import(doc, str(path), config)
    assert changed is True
    assert doc.get("A") == "1"
    assert doc.get("B") == "2"


def test_cmd_import_skips_duplicates(schema, config, tmp_path):
    doc = EnvDocument()
    schema.cmd_add(doc, ["A", "existing"], {}, config)

    path = tmp_path / "env.txt"
    path.write_text("A=new\nB=2\n", encoding="utf-8")

    schema.cmd_import(doc, str(path), config)
    assert doc.get("A") == "existing"
    assert doc.get("B") == "2"


def test_cmd_import_no_valid_entries_returns_false(schema, config, tmp_path):
    path = tmp_path / "env.txt"
    path.write_text("not valid content\n", encoding="utf-8")
    changed = schema.cmd_import(EnvDocument(), str(path), config)
    assert changed is False


def test_cmd_export_serializes_document(schema, config, capsys):
    doc = EnvDocument()
    schema.cmd_add(doc, ["A", "1"], {}, config)
    capsys.readouterr()  # discard "Added 'A'" output from cmd_add

    schema.cmd_export(doc, config)
    out = capsys.readouterr().out
    assert out == "A=1\n"


# ---- index_entries (credmgr global) ----

def test_index_entries_empty_document_returns_empty_list(schema):
    assert schema.index_entries(EnvDocument()) == []


def test_index_entries_one_row_per_key(schema, config):
    doc = EnvDocument()
    schema.cmd_add(doc, ["OPENAI_API_KEY", "sk-secret"], {}, config)
    schema.cmd_add(doc, ["DB_PASSWORD", "hunter2"], {}, config)

    entries = schema.index_entries(doc)
    assert sorted(e.fields["lhs"] for e in entries) == ["DB_PASSWORD", "OPENAI_API_KEY"]


def test_index_entries_args_resolve_via_cmd_get(schema, config, capsys):
    doc = EnvDocument()
    schema.cmd_add(doc, ["OPENAI_API_KEY", "sk-secret"], {}, config)
    capsys.readouterr()

    [entry] = schema.index_entries(doc)
    assert entry.args == ["OPENAI_API_KEY"]
    assert entry.summary == [("Key", "OPENAI_API_KEY")]

    schema.cmd_get(doc, entry.args, config)
    out = capsys.readouterr().out
    assert "OPENAI_API_KEY" in out


def test_index_entries_never_include_the_value(schema, config):
    doc = EnvDocument()
    schema.cmd_add(doc, ["OPENAI_API_KEY", "sk-super-secret-value"], {}, config)
    [entry] = schema.index_entries(doc)
    assert "sk-super-secret-value" not in entry.fields.values()
    assert all("sk-super-secret-value" != value for _label, value in entry.summary)
