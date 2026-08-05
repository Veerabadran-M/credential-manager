"""Tests for the cross-vault metadata search index (credmgr/globalindex.py):
persistence, staleness detection, and search matching. Never touches real
vault encryption -- documents are built directly against the schema
plugins, mirroring how cli.py already has a decrypted document in hand
when it calls update_vault().
"""

from __future__ import annotations

import json
import time

import pytest

from credmgr import globalindex
from credmgr.models import Credentials
from credmgr.schemas.plugins.credentials import CredentialsSchema
from credmgr.schemas.plugins.env import EnvDocument, EnvSchema
from credmgr.vault import Vault

GEN_OPTS = {"generate": True, "length": 16, "words": 5}


@pytest.fixture(autouse=True)
def no_clipboard(monkeypatch):
    import credmgr.schemas.plugins.credentials as credentials_mod
    import credmgr.schemas.plugins.env as env_mod
    monkeypatch.setattr(credentials_mod, "copy_to_clipboard", lambda value, label="Password": None)
    monkeypatch.setattr(env_mod, "copy_to_clipboard", lambda value, label="Password": None)


def _make_vault(config, name, backend_name):
    Vault(config, name=name).create(backend_name, "hunter2", "credentials")


# ---- index file contents / security ----

def test_index_file_never_written_until_update_called(config):
    assert not config.index_file.exists()


def test_update_vault_persists_only_metadata(config, available_backend_name):
    schema = CredentialsSchema()
    doc = Credentials()
    schema.cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    globalindex.update_vault(config, "personal", "credentials", doc)

    raw = json.loads(config.index_file.read_text(encoding="utf-8"))
    dumped = json.dumps(raw)

    # The real password/DEK/master-key material must never land in the index.
    assert doc.services["github"][0].password not in dumped
    assert "encrypted_key" not in dumped
    assert raw["vaults"]["personal"]["schema"] == "credentials"
    entries = raw["vaults"]["personal"]["entries"]
    assert entries == [{
        "fields": {"service": "github", "userid": "alice"},
        "summary": [["Service", "github"], ["User ID", "alice"]],
        "args": ["github", "alice"],
    }]


def test_index_file_permissions_are_owner_only(config):
    globalindex.update_vault(config, "personal", "credentials", Credentials())
    mode = config.index_file.stat().st_mode & 0o777
    assert mode == 0o600


# ---- update_vault / remove_vault ----

def test_update_vault_overwrites_previous_entries_for_same_vault(config):
    doc = Credentials()
    CredentialsSchema().cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    globalindex.update_vault(config, "personal", "credentials", doc)

    doc2 = Credentials()
    CredentialsSchema().cmd_add(doc2, ["gitlab", "bob"], GEN_OPTS, config)
    globalindex.update_vault(config, "personal", "credentials", doc2)

    results = globalindex.search(config, "git")
    assert len(results) == 1
    assert results[0]["summary"] == [("Service", "gitlab"), ("User ID", "bob")]


def test_update_vault_never_raises_when_indexing_fails(config):
    # Passing a document the schema can't actually introspect makes
    # index_entries() raise internally -- update_vault must swallow that
    # rather than letting it break the mutating command that triggered it.
    globalindex.update_vault(config, "weird", "credentials", None)
    raw = json.loads(config.index_file.read_text(encoding="utf-8"))
    assert raw["vaults"]["weird"]["entries"] == []


def test_remove_vault_drops_its_entries(config):
    globalindex.update_vault(config, "personal", "credentials", Credentials())
    globalindex.remove_vault(config, "personal")

    raw = json.loads(config.index_file.read_text(encoding="utf-8"))
    assert "personal" not in raw["vaults"]


def test_remove_vault_is_a_no_op_for_unknown_vault(config):
    globalindex.remove_vault(config, "nonexistent")  # must not raise
    assert not config.index_file.exists()


# ---- prune_removed_vaults ----

def test_prune_removed_vaults_drops_entries_not_in_known_names(config):
    globalindex.update_vault(config, "gone", "credentials", Credentials())
    globalindex.update_vault(config, "kept", "credentials", Credentials())

    globalindex.prune_removed_vaults(config, ["kept"])

    raw = json.loads(config.index_file.read_text(encoding="utf-8"))
    assert set(raw["vaults"]) == {"kept"}


# ---- stale_vault_names ----

def test_stale_vault_names_flags_vault_missing_from_index(config, available_backend_name):
    _make_vault(config, "personal", available_backend_name)
    assert globalindex.stale_vault_names(config, ["personal"]) == ["personal"]


def test_stale_vault_names_empty_once_indexed_and_unchanged(config, available_backend_name):
    _make_vault(config, "personal", available_backend_name)
    globalindex.update_vault(config, "personal", "credentials", Credentials())
    assert globalindex.stale_vault_names(config, ["personal"]) == []


def test_stale_vault_names_flags_vault_touched_after_indexing(config, available_backend_name):
    _make_vault(config, "personal", available_backend_name)
    globalindex.update_vault(config, "personal", "credentials", Credentials())

    # Simulate the vault file changing after the index was last written.
    vault_file = config.vault_dir("personal") / "vault.json"
    time.sleep(0.01)
    vault_file.write_text(vault_file.read_text(encoding="utf-8"), encoding="utf-8")

    assert globalindex.stale_vault_names(config, ["personal"]) == ["personal"]


def test_stale_vault_names_flags_schema_mismatch(config, available_backend_name):
    _make_vault(config, "personal", available_backend_name)
    globalindex.update_vault(config, "personal", "credentials", Credentials())

    # Hand-edit the vault's schema field without updating the index.
    vault_file = config.vault_dir("personal") / "vault.json"
    raw = json.loads(vault_file.read_text(encoding="utf-8"))
    raw["schema"] = "env"
    vault_file.write_text(json.dumps(raw), encoding="utf-8")

    assert globalindex.stale_vault_names(config, ["personal"]) == ["personal"]


def test_stale_vault_names_ignores_vaults_not_in_known_names(config):
    assert globalindex.stale_vault_names(config, []) == []


# ---- search ----

def test_search_is_case_insensitive_and_partial(config):
    doc = Credentials()
    CredentialsSchema().cmd_add(doc, ["GitHub", "alice"], GEN_OPTS, config)
    globalindex.update_vault(config, "personal", "credentials", doc)

    results = globalindex.search(config, "git")
    assert len(results) == 1
    assert results[0]["vault"] == "personal"

    results_upper = globalindex.search(config, "GIT")
    assert len(results_upper) == 1


def test_search_matches_across_multiple_vaults_and_schemas(config):
    creds_doc = Credentials()
    CredentialsSchema().cmd_add(creds_doc, ["github-enterprise", "admin"], GEN_OPTS, config)
    globalindex.update_vault(config, "servers", "credentials", creds_doc)

    env_doc = EnvDocument()
    EnvSchema().cmd_add(env_doc, ["OPENAI_API_KEY", "sk-secret"], {}, config)
    globalindex.update_vault(config, "research", "env", env_doc)

    results = globalindex.search(config, "OPEN")
    assert len(results) == 1
    assert results[0] == {
        "vault": "research",
        "schema": "env",
        "summary": [("Key", "OPENAI_API_KEY")],
        "args": ["OPENAI_API_KEY"],
    }


def test_search_no_match_returns_empty_list(config):
    globalindex.update_vault(config, "personal", "credentials", Credentials())
    assert globalindex.search(config, "nonexistent-query") == []


def test_search_results_are_ordered_by_vault_name(config):
    globalindex.update_vault(config, "zeta", "credentials", Credentials())
    doc = Credentials()
    CredentialsSchema().cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    globalindex.update_vault(config, "alpha", "credentials", doc)

    doc2 = Credentials()
    CredentialsSchema().cmd_add(doc2, ["github", "bob"], GEN_OPTS, config)
    globalindex.update_vault(config, "zeta", "credentials", doc2)

    results = globalindex.search(config, "github")
    assert [r["vault"] for r in results] == ["alpha", "zeta"]


# ---- corrupt/incompatible index files degrade gracefully ----

def test_corrupt_index_file_is_treated_as_empty(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    config.index_file.write_text("{not json", encoding="utf-8")
    assert globalindex.search(config, "anything") == []


def test_wrong_version_index_file_is_treated_as_empty(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    config.index_file.write_text(json.dumps({"version": 999, "vaults": {}}), encoding="utf-8")
    assert globalindex.search(config, "anything") == []


def test_update_vault_recovers_from_corrupt_index_file(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    config.index_file.write_text("not even json", encoding="utf-8")

    doc = Credentials()
    CredentialsSchema().cmd_add(doc, ["github", "alice"], GEN_OPTS, config)
    globalindex.update_vault(config, "personal", "credentials", doc)

    results = globalindex.search(config, "github")
    assert len(results) == 1
