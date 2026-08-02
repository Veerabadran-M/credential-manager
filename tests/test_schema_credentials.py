"""Tests for the Credentials schema plugin: parse/serialize and the
CRUD command implementations, using pre-generated passwords (opts with
generate=True) to avoid interactive prompts.
"""

from __future__ import annotations

import json

import pytest

import credmgr.schemas.plugins.credentials as credentials_mod
from credmgr.models import Account, Credentials
from credmgr.schemas.base import SchemaError
from credmgr.schemas.plugins.credentials import CredentialsSchema


@pytest.fixture(autouse=True)
def no_clipboard(monkeypatch):
    """Never touch the real clipboard/fork a background process in tests."""
    monkeypatch.setattr(credentials_mod, "copy_to_clipboard", lambda value, label="Password": None)


@pytest.fixture
def schema():
    return CredentialsSchema()


GEN_OPTS = {"generate": True, "length": 16, "words": 5}


# ---- parse / serialize ----

def test_new_document_is_empty():
    doc = CredentialsSchema.new_document()
    assert isinstance(doc, Credentials)
    assert doc.services == {}


def test_parse_and_serialize_round_trip():
    doc = Credentials()
    doc.services["github"] = [Account(userid="alice", password="p1", notes="n", created_at=1.0, updated_at=1.0)]

    blob = CredentialsSchema.serialize(doc)
    restored = CredentialsSchema.parse(blob)

    assert restored.services["github"][0].userid == "alice"
    assert restored.services["github"][0].password == "p1"


# ---- cmd_add ----

def test_cmd_add_creates_new_account(schema, config):
    doc = Credentials()
    changed = schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    assert changed is True
    assert doc.services["github"][0].userid == "alice"
    assert len(doc.services["github"][0].password) == 16


def test_cmd_add_duplicate_userid_rejected(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    changed = schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    assert changed is False
    assert len(doc.services["github"]) == 1


def test_cmd_add_wrong_arg_count_raises(schema, config):
    with pytest.raises(SchemaError, match="Usage"):
        schema.cmd_add(Credentials(), ["github"], GEN_OPTS, config)


def test_cmd_add_rejects_invalid_service_name(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_add(Credentials(), [" bad", "alice"], GEN_OPTS, config)


def test_cmd_add_with_notes(schema, config):
    doc = Credentials()
    opts = dict(GEN_OPTS, notes="my note")
    schema.cmd_add(doc, ["github", "alice"], opts, config)
    assert doc.services["github"][0].notes == "my note"


# ---- cmd_update ----

def test_cmd_update_userid_renames_account(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    changed = schema.cmd_update(doc, ["github", "alice", "userid", "alice2"], GEN_OPTS, config)
    assert changed is True
    assert doc.services["github"][0].userid == "alice2"


def test_cmd_update_userid_missing_new_value_raises(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    with pytest.raises(SchemaError, match="requires a"):
        schema.cmd_update(doc, ["github", "alice", "userid"], GEN_OPTS, config)


def test_cmd_update_password_pushes_history(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    old_password = doc.services["github"][0].password

    schema.cmd_update(doc, ["github", "alice", "password"], GEN_OPTS, config)

    acc = doc.services["github"][0]
    assert acc.password != old_password
    assert acc.history[0].password == old_password


def test_cmd_update_notes(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    changed = schema.cmd_update(doc, ["github", "alice", "notes", "updated note"], GEN_OPTS, config)
    assert changed is True
    assert doc.services["github"][0].notes == "updated note"


def test_cmd_update_notes_missing_value_raises(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    with pytest.raises(SchemaError, match="requires a"):
        schema.cmd_update(doc, ["github", "alice", "notes"], GEN_OPTS, config)


def test_cmd_update_account_changes_userid_and_password(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    old_password = doc.services["github"][0].password

    changed = schema.cmd_update(doc, ["github", "alice", "account", "alice3"], GEN_OPTS, config)
    assert changed is True
    acc = doc.services["github"][0]
    assert acc.userid == "alice3"
    assert acc.password != old_password


def test_cmd_update_unknown_field_raises(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    with pytest.raises(SchemaError, match="Unknown field"):
        schema.cmd_update(doc, ["github", "alice", "bogus", "x"], GEN_OPTS, config)


def test_cmd_update_too_few_args_raises(schema, config):
    with pytest.raises(SchemaError, match="Usage"):
        schema.cmd_update(Credentials(), ["github", "alice"], GEN_OPTS, config)


def test_cmd_update_nonexistent_account_returns_false(schema, config):
    doc = Credentials()
    changed = schema.cmd_update(doc, ["github", "alice", "notes", "x"], GEN_OPTS, config)
    assert changed is False


# ---- cmd_delete ----

def test_cmd_delete_specific_account(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_add(doc, ["github", "bob"], GEN_OPTS, config)

    changed = schema.cmd_delete(doc, ["github", "alice"], config)
    assert changed is True
    assert [a.userid for a in doc.services["github"]] == ["bob"]


def test_cmd_delete_last_account_removes_service(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    changed = schema.cmd_delete(doc, ["github", "alice"], config)
    assert changed is True
    assert "github" not in doc.services


def test_cmd_delete_whole_service_confirmed(schema, config, monkeypatch):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_add(doc, ["github", "bob"], GEN_OPTS, config)

    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    changed = schema.cmd_delete(doc, ["github"], config)
    assert changed is True
    assert "github" not in doc.services


def test_cmd_delete_whole_service_aborted(schema, config, monkeypatch):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    changed = schema.cmd_delete(doc, ["github"], config)
    assert changed is False
    assert "github" in doc.services


def test_cmd_delete_nonexistent_service_returns_false(schema, config):
    changed = schema.cmd_delete(Credentials(), ["nope"], config)
    assert changed is False


# ---- cmd_get / cmd_search / cmd_history (smoke tests -- must not raise) ----

def test_cmd_get_existing_service(schema, config, capsys):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_get(doc, ["github"], config)
    out = capsys.readouterr().out
    assert "alice" in out


def test_cmd_get_missing_service_does_not_raise(schema, config):
    schema.cmd_get(Credentials(), ["nope"], config)


def test_cmd_get_bad_args_raises(schema, config):
    with pytest.raises(SchemaError):
        schema.cmd_get(Credentials(), [], config)


def test_cmd_search_finds_match(schema, config, capsys):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_search(doc, "alice", config)
    out = capsys.readouterr().out
    assert "alice" in out


def test_cmd_history_no_history_message(schema, config, capsys):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_history(doc, ["github", "alice"], config)
    out = capsys.readouterr().out
    assert "No password history" in out


def test_cmd_history_shows_entries_after_password_update(schema, config, capsys):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_update(doc, ["github", "alice", "password"], GEN_OPTS, config)

    schema.cmd_history(doc, ["github", "alice"], config)
    out = capsys.readouterr().out
    assert "Password history" in out


def test_cmd_copy_single_account_no_prompt_needed(schema, config):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    # Should not raise/prompt since there's exactly one account.
    schema.cmd_copy(doc, ["github"], config)


# ---- cmd_import / cmd_export ----

def test_cmd_import_valid_file(schema, config, tmp_path):
    doc = Credentials()
    import_data = {"github": [{"userid": "alice", "password": "p1", "notes": "n"}]}
    path = tmp_path / "import.json"
    path.write_text(json.dumps(import_data), encoding="utf-8")

    changed = schema.cmd_import(doc, str(path), config)
    assert changed is True
    assert doc.services["github"][0].userid == "alice"


def test_cmd_import_skips_duplicate_userid(schema, config, tmp_path):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    import_data = {"github": [{"userid": "alice", "password": "p1", "notes": "n"}]}
    path = tmp_path / "import.json"
    path.write_text(json.dumps(import_data), encoding="utf-8")

    schema.cmd_import(doc, str(path), config)
    assert len(doc.services["github"]) == 1


def test_cmd_import_missing_file_returns_false(schema, config):
    changed = schema.cmd_import(Credentials(), "/nonexistent/path.json", config)
    assert changed is False


def test_cmd_import_invalid_json_returns_false(schema, config, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    changed = schema.cmd_import(Credentials(), str(path), config)
    assert changed is False


def test_cmd_import_non_object_top_level_returns_false(schema, config, tmp_path):
    path = tmp_path / "list.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    changed = schema.cmd_import(Credentials(), str(path), config)
    assert changed is False


def test_cmd_export_prints_valid_json(schema, config, capsys):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    capsys.readouterr()  # discard "Generated Password"/"Added" output from cmd_add

    schema.cmd_export(doc, config)
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["github"][0]["userid"] == "alice"


# ---- cmd_audit (smoke test) ----

def test_cmd_audit_runs_without_error(schema, config, capsys):
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    schema.cmd_audit(doc, config)
    out = capsys.readouterr().out
    assert "Password Audit" in out
