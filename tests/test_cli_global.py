"""Integration tests for `credmgr global <query>` through the actual
Typer CLI app -- multiple real (encrypted) vaults on disk, driven via
`CliRunner`, exercising the whole flow: index search, interactive
match selection, authenticating only the selected vault, and leaving
the active vault/config untouched.

`credmgr.config.config` is a process-wide singleton that `cli/commands.py`,
`auth.py`, and `globalindex.py` all import the *same instance* of, so
each test redirects it at a throwaway `tmp_path` via the `redirect_config`
fixture rather than trying to swap the module-level name.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

import credmgr.auth as auth_mod
import credmgr.cli.commands as cli_commands_mod
import credmgr.schemas.plugins.credentials as credentials_mod
import credmgr.schemas.plugins.env as env_mod
from credmgr import globalindex
from credmgr.cli import app
from credmgr.config import config as real_config
from credmgr.schemas.plugins.credentials import CredentialsSchema
from credmgr.schemas.plugins.env import EnvSchema
from credmgr.vault import Vault
from credmgr.clipboard import ClipboardResult

runner = CliRunner()

GEN_OPTS = {"generate": True, "length": 16, "words": 5}


@pytest.fixture(autouse=True)
def redirect_config(tmp_path, monkeypatch):
    """Point the real config singleton (shared by cli/commands.py, auth.py,
    core/manager.py, and globalindex.py) at a throwaway directory,
    and never touch the real clipboard or session cache."""
    monkeypatch.setattr(real_config, "master_dir", tmp_path / ".credmgr")
    monkeypatch.setattr(real_config, "active_vault", "default")
    monkeypatch.setattr(credentials_mod, "copy_to_clipboard", lambda value, label="Password": ClipboardResult(copied=False, label=label, reason="disabled in tests"))
    monkeypatch.setattr(env_mod, "copy_to_clipboard", lambda value, label="Password": ClipboardResult(copied=False, label=label, reason="disabled in tests"))
    # Force a fresh master password prompt every time instead of hitting
    # a session cache from a previous test/process.
    monkeypatch.setattr(auth_mod, "load_cached_dek", lambda config=None, vault_name=None: None)
    monkeypatch.setattr(auth_mod, "cache_session", lambda dek, config=None, vault_name=None: None)
    # `safe_getpass` calls `getpass.getpass`, which opens /dev/tty directly
    # when one is available -- bypassing CliRunner's simulated stdin and
    # forcing a real human to type a password. Route it through `input()`
    # instead, which CliRunner's `input=` param does feed, so the
    # already-scripted passwords in each test drive the prompt
    # automatically regardless of whether a real tty is attached.
    # (Patched on credmgr.cli.commands -- that's where
    # PasswordRequired is now caught and prompted for, not credmgr.auth.)
    monkeypatch.setattr(cli_commands_mod, "safe_getpass", lambda prompt="": input(prompt))
    return real_config


def _seed_vault(config, name, backend_name, schema_name, password, populate):
    """Create a real encrypted vault, populate it via the schema (like a
    normal `add` would), save it, and update the search index -- exactly
    what core/manager.py's mutation hooks do after every add/update/delete."""
    vault = Vault(config, name=name)
    dek = vault.create(backend_name, password, schema_name)
    document = vault.unlock_with_dek(dek)
    populate(document)
    vault.save(document, dek)
    globalindex.update_vault(config, name, schema_name, document)


@pytest.fixture
def two_vaults(redirect_config, available_backend_name):
    config = redirect_config

    def populate_personal(doc):
        CredentialsSchema().cmd_add(doc, ["github", "alice"], GEN_OPTS, config)

    def populate_research(doc):
        EnvSchema().cmd_add(doc, ["OPENAI_API_KEY", "sk-super-secret"], {}, config)

    _seed_vault(config, "personal", available_backend_name, "credentials", "pw-personal", populate_personal)
    _seed_vault(config, "research", available_backend_name, "env", "pw-research", populate_research)
    return config


# ---- no vaults / no matches ----

def test_global_with_no_vaults_reports_none_found(redirect_config):
    result = runner.invoke(app, ["global", "anything"])
    assert result.exit_code == 0
    assert "No vaults found" in result.output


def test_global_with_no_matching_entries(two_vaults):
    result = runner.invoke(app, ["global", "totally-nonexistent-query"])
    assert result.exit_code == 0
    assert "No matching entries found." in result.output


# ---- single match ----

def test_global_single_match_confirmed_retrieves_secret(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="y\npw-research\n")
    assert result.exit_code == 0, result.output
    assert "Found 1 match" in result.output
    assert "research" in result.output
    assert "OPENAI_API_KEY" in result.output
    assert "sk-super-secret" in result.output


def test_global_single_match_declined_does_not_prompt_for_password(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="n\n")
    assert result.exit_code == 0, result.output
    assert "Found 1 match" in result.output
    assert "sk-super-secret" not in result.output


def test_global_single_match_wrong_password_terminates(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="y\nwrong-password\n")
    assert result.exit_code != 0
    assert "sk-super-secret" not in result.output


# ---- multiple matches ----

def test_global_multiple_matches_lists_and_selects_by_number(two_vaults):
    config = two_vaults

    def populate(doc):
        CredentialsSchema().cmd_add(doc, ["github-enterprise", "admin"], GEN_OPTS, config)

    _seed_vault(config, "servers", _first_backend(), "credentials", "pw-servers", populate)

    result = runner.invoke(app, ["global", "git"])
    assert "Found 2 matches" in result.output
    assert "1. personal" in result.output
    assert "2. servers" in result.output


def test_global_multiple_matches_invalid_selection_is_reported(two_vaults):
    config = two_vaults

    def populate(doc):
        CredentialsSchema().cmd_add(doc, ["github-enterprise", "admin"], GEN_OPTS, config)

    _seed_vault(config, "servers", _first_backend(), "credentials", "pw-servers", populate)

    result = runner.invoke(app, ["global", "git"], input="9\n")
    assert "Invalid selection." in result.output


def test_global_multiple_matches_selection_retrieves_correct_vault(two_vaults):
    config = two_vaults

    def populate(doc):
        CredentialsSchema().cmd_add(doc, ["github-enterprise", "admin"], GEN_OPTS, config)

    _seed_vault(config, "servers", _first_backend(), "credentials", "pw-servers", populate)

    result = runner.invoke(app, ["global", "git"], input="2\npw-servers\n")
    assert result.exit_code == 0, result.output
    assert "github-enterprise" in result.output
    assert "admin" in result.output


# ---- active vault / config untouched ----

def test_global_never_changes_the_active_vault(two_vaults):
    config = two_vaults
    config.active_vault = "personal"

    runner.invoke(app, ["global", "OPEN"], input="y\npw-research\n")

    assert config.active_vault == "personal"


def test_global_never_writes_config_file(two_vaults):
    config = two_vaults
    runner.invoke(app, ["global", "OPEN"], input="y\npw-research\n")
    assert not config.settings_file.exists()


# ---- index freshness ----

def test_global_finds_entries_added_outside_cli_after_index_refresh(two_vaults, available_backend_name):
    """Simulate a vault whose contents changed without the index being
    told (e.g. hand-edited, or an older credmgr build) -- `global` must
    notice via stale_vault_names() and re-index it before searching."""
    config = two_vaults

    vault = Vault(config, name="personal")
    dek, document = vault.unlock("pw-personal")
    CredentialsSchema().cmd_add(document, ["newsvc", "carol"], GEN_OPTS, config)
    vault.save(document, dek)
    # Deliberately do NOT call globalindex.update_vault() here -- the
    # index now disagrees with vault.json's mtime.

    result = runner.invoke(app, ["global", "newsvc"], input="pw-personal\ny\npw-personal\n")
    assert "Found 1 match" in result.output
    assert "newsvc" in result.output


def _first_backend():
    from credmgr.crypto.registry import available_backends
    return sorted(available_backends())[0]
