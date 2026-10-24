"""Integration tests for `credmgr global <query>` through the actual
Typer CLI app -- multiple real (encrypted) vaults on disk, driven via
`CliRunner`, exercising the whole flow: in-memory search across every
vault, interactive match selection, and leaving the active vault/config
untouched. Nothing is indexed or persisted by a global search.

`credmgr.config.config` is a process-wide singleton that `cli/commands.py`,
`auth.py`, and `globalsearch.py` all import the *same instance* of, so
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
    core/manager.py, and globalsearch.py) at a throwaway directory,
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
    normal `add` would) and save it."""
    vault = Vault(config, name=name)
    dek = vault.create(backend_name, password, schema_name)
    document = vault.unlock_with_dek(dek)
    populate(document)
    vault.save(document, dek)


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
    result = runner.invoke(app, ["global", "totally-nonexistent-query"], input="pw-personal\npw-research\n")
    assert result.exit_code == 0
    assert "No matching entries found." in result.output


# ---- single match ----
# Every searchable vault is unlocked in turn (sorted by name: personal,
# research), so the scripted input is "<personal pw>\n<research pw>\n"
# followed by the answer to "View this secret?".

def test_global_single_match_confirmed_retrieves_secret(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\ny\n")
    assert result.exit_code == 0, result.output
    assert "Found 1 match" in result.output
    assert "research" in result.output
    assert "OPENAI_API_KEY" in result.output
    assert "sk-super-secret" in result.output


def test_global_single_match_declined_does_not_show_secret(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\nn\n")
    assert result.exit_code == 0, result.output
    assert "Found 1 match" in result.output
    assert "sk-super-secret" not in result.output


def test_global_does_not_prompt_a_second_time_for_selected_vault(two_vaults):
    # Session caching is disabled in these tests, so a second prompt
    # would consume "y" as a password and break the flow.
    result = runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\ny\n")
    assert "sk-super-secret" in result.output


def test_global_wrong_password_skips_that_vault_only(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="pw-personal\nwrong-password\n")
    assert result.exit_code == 0, result.output
    assert "Skipped vault 'research'" in result.output
    assert "No matching entries found." in result.output
    assert "sk-super-secret" not in result.output


def test_global_blank_password_skips_vault(two_vaults):
    result = runner.invoke(app, ["global", "OPEN"], input="\n\n")
    assert result.exit_code == 0, result.output
    assert "Skipped vault 'personal'" in result.output
    assert "Skipped vault 'research'" in result.output
    assert "No matching entries found." in result.output


def test_global_does_not_unlock_vaults_whose_schema_cannot_be_searched(redirect_config, available_backend_name):
    config = redirect_config
    _seed_vault(config, "notes", available_backend_name, "text", "pw-notes", lambda doc: None)
    result = runner.invoke(app, ["global", "anything"])  # no input: any prompt would hit EOF
    assert result.exit_code == 0, result.output
    assert "No matching entries found." in result.output


# ---- multiple matches ----

def test_global_multiple_matches_lists_and_selects_by_number(two_vaults):
    config = two_vaults

    def populate(doc):
        CredentialsSchema().cmd_add(doc, ["github-enterprise", "admin"], GEN_OPTS, config)

    _seed_vault(config, "servers", _first_backend(), "credentials", "pw-servers", populate)

    result = runner.invoke(app, ["global", "git"], input="pw-personal\npw-research\npw-servers\n\n")
    assert "Found 2 matches" in result.output
    assert "1. personal" in result.output
    assert "2. servers" in result.output


def test_global_multiple_matches_invalid_selection_is_reported(two_vaults):
    config = two_vaults

    def populate(doc):
        CredentialsSchema().cmd_add(doc, ["github-enterprise", "admin"], GEN_OPTS, config)

    _seed_vault(config, "servers", _first_backend(), "credentials", "pw-servers", populate)

    result = runner.invoke(app, ["global", "git"], input="pw-personal\npw-research\npw-servers\n9\n")
    assert "Invalid selection." in result.output


def test_global_multiple_matches_selection_retrieves_correct_vault(two_vaults):
    config = two_vaults

    def populate(doc):
        CredentialsSchema().cmd_add(doc, ["github-enterprise", "admin"], GEN_OPTS, config)

    _seed_vault(config, "servers", _first_backend(), "credentials", "pw-servers", populate)

    result = runner.invoke(app, ["global", "git"], input="pw-personal\npw-research\npw-servers\n2\n")
    assert result.exit_code == 0, result.output
    assert "github-enterprise" in result.output
    assert "admin" in result.output


# ---- active vault / config untouched ----

def test_global_never_changes_the_active_vault(two_vaults):
    config = two_vaults
    config.active_vault = "personal"

    runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\ny\n")

    assert config.active_vault == "personal"


def test_global_never_writes_config_file(two_vaults):
    config = two_vaults
    runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\ny\n")
    assert not config.settings_file.exists()


# ---- nothing persisted ----

def test_global_finds_entries_added_outside_the_cli(two_vaults):
    """No index to go stale: whatever is in the vault right now is searched."""
    config = two_vaults

    vault = Vault(config, name="personal")
    dek, document = vault.unlock("pw-personal")
    CredentialsSchema().cmd_add(document, ["newsvc", "carol"], GEN_OPTS, config)
    vault.save(document, dek)

    result = runner.invoke(app, ["global", "newsvc"], input="pw-personal\npw-research\nn\n")
    assert "Found 1 match" in result.output
    assert "newsvc" in result.output


def test_global_writes_no_index_file(two_vaults):
    config = two_vaults
    runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\nn\n")
    assert not (config.master_dir / "index.json").exists()
    assert not any("index" in p.name for p in config.master_dir.rglob("*"))


def test_global_never_stores_identifiers_outside_the_encrypted_vaults(two_vaults):
    config = two_vaults
    runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\ny\n")
    for path in config.master_dir.rglob("*"):
        if path.is_file() and path.name not in ("vault.json", "vault.bak"):
            data = path.read_bytes()
            assert b"OPENAI_API_KEY" not in data and b"github" not in data


def test_global_removes_legacy_plaintext_index(two_vaults):
    config = two_vaults
    legacy = config.master_dir / "index.json"
    legacy.write_text('{"version": 1, "vaults": {"personal": {"entries": [{"fields": {"service": "github"}}]}}}')
    runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\nn\n")
    assert not legacy.exists()


def _first_backend():
    from credmgr.crypto.registry import available_backends
    return sorted(available_backends())[0]


# ---- list-all: unsupported schema skips only that vault ----

def test_list_all_skips_vault_whose_schema_lacks_list_all(two_vaults, available_backend_name):
    _seed_vault(two_vaults, "notes", available_backend_name, "text", "pw-notes", lambda doc: None)
    # names are sorted: notes, personal, research -- notes must not prompt
    result = runner.invoke(app, ["list-all"], input="pw-personal\npw-research\n")
    assert result.exit_code == 0, result.output
    assert "does not support list-all" in result.output
    assert "github" in result.output
    assert "OPENAI_API_KEY" in result.output


def test_list_all_wrong_password_skips_that_vault_only(two_vaults):
    result = runner.invoke(app, ["list-all"], input="pw-personal\nwrong\n")
    assert result.exit_code == 0, result.output
    assert "Skipped vault 'research'" in result.output
    assert "github" in result.output


# ---- global: master password seeds the session cache ----

def test_global_caches_session_key_after_password_unlock(two_vaults, monkeypatch):
    cached = []
    monkeypatch.setattr(auth_mod, "cache_session",
                        lambda dek, config=None, vault_name=None: cached.append(vault_name))
    runner.invoke(app, ["global", "OPEN"], input="pw-personal\npw-research\nn\n")
    assert sorted(cached) == ["personal", "research"]
