"""Tests for Configuration: field parsing/validation, save/load
round-trips, and derived path properties.
"""

from __future__ import annotations

import json

import pytest

from credmgr.config import Configuration


# ---- derived paths ----

def test_vault_file_paths_are_scoped_to_active_vault(config):
    config.active_vault = "work"
    assert config.vault_file == config.master_dir / "vaults" / "work" / "vault.json"
    assert config.vault_bak_file.name == "vault.bak"
    assert config.vault_temp_file.name == "vault.tmp"


def test_data_dir_and_dataset_file_paths(config):
    assert config.data_dir == config.master_dir / "data"
    assert config.wordlist_file == config.data_dir / "wordlist.txt"
    assert config.common_passwords_file == config.data_dir / "common_passwords.txt"
    assert config.sequences_file == config.data_dir / "sequences.txt"
    assert config.breach_db_file == config.data_dir / "breached_hash.txt"


def test_settings_file_path(config):
    assert config.settings_file == config.master_dir / "config.json"


# ---- set_value / _parse_value / _validate_value ----

def test_set_value_parses_int_field():
    cfg = Configuration()
    cfg.set_value("password_length", "42")
    assert cfg.password_length == 42
    assert isinstance(cfg.password_length, int)


def test_set_value_parses_float_field():
    cfg = Configuration()
    cfg.set_value("fuzzy_threshold", "0.5")
    assert cfg.fuzzy_threshold == 0.5


def test_set_value_rejects_out_of_range_int():
    cfg = Configuration()
    with pytest.raises(ValueError, match="must be between"):
        cfg.set_value("password_length", "1000")


def test_set_value_rejects_out_of_range_float():
    cfg = Configuration()
    with pytest.raises(ValueError, match="must be between"):
        cfg.set_value("fuzzy_threshold", "1.5")


def test_set_value_rejects_unknown_key():
    cfg = Configuration()
    with pytest.raises(KeyError):
        cfg.set_value("not_a_real_key", "1")


def test_set_value_rejects_master_dir():
    cfg = Configuration()
    with pytest.raises(KeyError):
        cfg.set_value("master_dir", "/tmp/whatever")


def test_set_value_rejects_hidden_parameter():
    cfg = Configuration()
    with pytest.raises(KeyError):
        cfg.set_value("active_vault", "work")


def test_set_value_boolean_like_strings():
    # No boolean fields currently exist on Configuration, but _parse_value's
    # boolean branch is exercised indirectly via int/float branches; this
    # test instead confirms int fields reject boolean-looking junk cleanly.
    cfg = Configuration()
    with pytest.raises(ValueError):
        cfg.set_value("password_length", "not-a-number")


def test_set_value_int_field_rejects_bool_input_type():
    cfg = Configuration()
    with pytest.raises(ValueError, match="must be an integer"):
        cfg._parse_value("password_length", True)


def test_validate_value_backend_must_be_known():
    cfg = Configuration()
    with pytest.raises(ValueError, match="backend must be one of"):
        cfg._validate_value("backend", "not-a-real-backend")


def test_validate_value_unlimited_key_passes_through():
    cfg = Configuration()
    # active_vault has no entry in CONFIG_VALUE_LIMITS, so any value is fine
    # at the _validate_value layer (set_value blocks it earlier for other reasons).
    cfg._validate_value("active_vault", "anything")


# ---- save / load round trip ----

def test_save_then_load_round_trips_mutable_fields(config):
    config.password_length = 32
    config.fuzzy_threshold = 0.6
    config.save()

    assert config.settings_file.exists()

    reloaded = Configuration()
    reloaded.master_dir = config.master_dir
    reloaded.load()

    assert reloaded.password_length == 32
    assert reloaded.fuzzy_threshold == 0.6


def test_save_sets_restrictive_permissions(config):
    config.save()
    mode = config.settings_file.stat().st_mode & 0o777
    assert mode == 0o600


def test_load_no_settings_file_is_a_no_op(config):
    # No file exists yet -- load() should just return self unchanged.
    result = config.load()
    assert result is config
    assert config.password_length == Configuration.password_length


def test_load_rejects_invalid_json(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    config.settings_file.write_text("{not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="not valid JSON"):
        config.load()


def test_load_rejects_non_object_json(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    config.settings_file.write_text(json.dumps([1, 2, 3]), encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a JSON object"):
        config.load()


def test_load_rejects_invalid_field_value(config):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    config.settings_file.write_text(json.dumps({"password_length": 99999}), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid configuration"):
        config.load()


def test_load_ignores_master_dir_in_file(config, tmp_path):
    config.master_dir.mkdir(parents=True, exist_ok=True)
    other_dir = str(tmp_path / "other")
    config.settings_file.write_text(json.dumps({"master_dir": other_dir}), encoding="utf-8")

    config.load()
    # master_dir must never be overwritten by the settings file itself.
    assert config.master_dir != other_dir


def test_as_dict_serializes_paths_as_strings(config):
    d = config.as_dict()
    assert isinstance(d["master_dir"], str)
    assert d["master_dir"] == str(config.master_dir)


def test_mutable_and_immutable_parameter_lists_are_disjoint(config):
    mutable = set(config.mutable_parameters)
    immutable = set(config.immutable_parameters)
    assert mutable.isdisjoint(immutable)
