"""Tests for multi-vault directory management: name validation, listing,
deletion, schema peeking, and the legacy single-vault migration.
"""

from __future__ import annotations

import json

import pytest

from credmgr.vault import Vault
from credmgr.vaultmgr import (VaultManagerError, delete_vault,
                               list_vault_names, migrate_legacy_layout,
                               peek_schema, validate_vault_name,
                               vault_exists)


# ---- validate_vault_name ----

@pytest.mark.parametrize("name", ["default", "work-account", "my_vault", "A1", "x" * 64])
def test_validate_vault_name_accepts_valid_names(name):
    assert validate_vault_name(name) == name


@pytest.mark.parametrize("name", ["", "has space", "bad!char", "x" * 65, None])
def test_validate_vault_name_rejects_invalid_names(name):
    with pytest.raises(VaultManagerError):
        validate_vault_name(name)


# ---- vault_exists / list_vault_names ----

def test_vault_exists_false_when_nothing_created(config):
    assert vault_exists(config, "default") is False


def test_vault_exists_true_after_creation(config, available_backend_name):
    Vault(config, name="default").create(available_backend_name, "hunter2")
    assert vault_exists(config, "default") is True


def test_list_vault_names_empty_when_no_vaults_dir(config):
    assert list_vault_names(config) == []


def test_list_vault_names_lists_created_vaults_sorted(config, available_backend_name):
    Vault(config, name="zeta").create(available_backend_name, "pw")
    Vault(config, name="alpha").create(available_backend_name, "pw")

    assert list_vault_names(config) == ["alpha", "zeta"]


def test_list_vault_names_ignores_directories_without_vault_json(config):
    config.vaults_dir.mkdir(parents=True, exist_ok=True)
    (config.vaults_dir / "empty_dir").mkdir()
    assert list_vault_names(config) == []


# ---- peek_schema ----

def test_peek_schema_returns_credentials_by_default(config, available_backend_name):
    Vault(config, name="default").create(available_backend_name, "pw")
    assert peek_schema(config, "default") == "credentials"


def test_peek_schema_returns_question_mark_for_missing_vault(config):
    assert peek_schema(config, "nonexistent") == "?"


def test_peek_schema_returns_question_mark_for_corrupt_json(config):
    vault_dir = config.vault_dir("broken")
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "vault.json").write_text("{not json", encoding="utf-8")
    assert peek_schema(config, "broken") == "?"


# ---- delete_vault ----

def test_delete_vault_removes_directory(config, available_backend_name):
    Vault(config, name="temp").create(available_backend_name, "pw")
    assert vault_exists(config, "temp") is True

    delete_vault(config, "temp")
    assert vault_exists(config, "temp") is False
    assert not config.vault_dir("temp").exists()


def test_delete_vault_raises_for_nonexistent_vault(config):
    with pytest.raises(VaultManagerError):
        delete_vault(config, "nonexistent")


# ---- migrate_legacy_layout ----

def test_migrate_legacy_layout_no_op_when_no_legacy_vault(config):
    migrate_legacy_layout(config)
    assert not config.vaults_dir.exists()


def test_migrate_legacy_layout_moves_legacy_vault_into_default(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    legacy_content = {"version": 1, "backend": "aesgcm-cryptography"}
    (config.master_dir / "vault.json").write_text(json.dumps(legacy_content), encoding="utf-8")

    migrate_legacy_layout(config)

    assert not (config.master_dir / "vault.json").exists()
    new_path = config.vault_dir("default") / "vault.json"
    assert new_path.exists()
    raw = json.loads(new_path.read_text())
    assert raw["schema"] == "credentials"
    assert config.active_vault == "default"


def test_migrate_legacy_layout_moves_backup_file_too(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    (config.master_dir / "vault.json").write_text(json.dumps({"version": 1}), encoding="utf-8")
    (config.master_dir / "vault.bak").write_text(json.dumps({"version": 1}), encoding="utf-8")

    migrate_legacy_layout(config)

    assert (config.vault_dir("default") / "vault.bak").exists()


def test_migrate_legacy_layout_is_a_no_op_if_vaults_dir_already_exists(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    (config.master_dir / "vault.json").write_text(json.dumps({"version": 1}), encoding="utf-8")
    config.vaults_dir.mkdir(parents=True, exist_ok=True)

    migrate_legacy_layout(config)

    # Legacy file must be left untouched since vaults_dir already existed.
    assert (config.master_dir / "vault.json").exists()
    assert not (config.vault_dir("default") / "vault.json").exists()


def test_migrate_legacy_layout_never_overwrites_existing_default_vault(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    (config.master_dir / "vault.json").write_text(json.dumps({"marker": "legacy"}), encoding="utf-8")

    default_dir = config.vault_dir("default")
    default_dir.mkdir(parents=True, exist_ok=True)
    (default_dir / "vault.json").write_text(json.dumps({"marker": "existing"}), encoding="utf-8")

    migrate_legacy_layout(config)

    raw = json.loads((default_dir / "vault.json").read_text())
    assert raw["marker"] == "existing"
    # The legacy file is untouched too, since the whole migration bails out.
    assert (config.master_dir / "vault.json").exists()
