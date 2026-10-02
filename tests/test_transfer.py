"""`credmgr transfer`: moving/copying entries between vaults of the same
schema, at both the CredentialManager level and through the CLI."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

import credmgr.auth as auth_mod
import credmgr.cli.commands as cli_commands_mod
from credmgr.cli import app
from credmgr.config import config as real_config
from credmgr.core import CredentialManager, PasswordRequired, VaultError
from credmgr.schemas import SchemaError
from credmgr.schemas.plugins.credentials import CredentialsSchema
from credmgr.schemas.plugins.env import EnvSchema
from credmgr.vault import Vault

runner = CliRunner()
GEN = {"generate": False, "password": "pw", "length": 16, "words": 5}


@pytest.fixture(autouse=True)
def redirect_config(tmp_path, monkeypatch):
    monkeypatch.setattr(real_config, "master_dir", tmp_path / ".credmgr")
    monkeypatch.setattr(real_config, "active_vault", "default")
    monkeypatch.setattr(auth_mod, "load_cached_dek", lambda config=None, vault_name=None: None)
    monkeypatch.setattr(auth_mod, "cache_session", lambda dek, config=None, vault_name=None: None)
    monkeypatch.setattr(cli_commands_mod, "safe_getpass", lambda prompt="": input(prompt))
    return real_config


def _make(config, name, schema, password, backend, populate=None):
    vault = Vault(config, name=name)
    dek = vault.create(backend, password, schema)
    if populate:
        doc = vault.unlock_with_dek(dek)
        populate(doc)
        vault.save(doc, dek)


def _load(config, name, password):
    return Vault(config, name=name).unlock(password)[1]


@pytest.fixture
def cred_vaults(redirect_config, available_backend_name):
    cfg = redirect_config
    s = CredentialsSchema()

    def src(doc):
        s.cmd_add(doc, ["github", "alice"], {**GEN, "password": "alice-pw", "notes": "work"}, cfg)
        s.cmd_add(doc, ["github", "bob"], {**GEN, "password": "bob-pw"}, cfg)
        s.cmd_add(doc, ["gitlab", "carol"], {**GEN, "password": "carol-pw"}, cfg)
        # Give alice a password history so we can check it survives the move.
        s.cmd_update(doc, ["github", "alice", "password"], {**GEN, "password": "alice-pw-2"}, cfg)

    _make(cfg, "a", "credentials", "pw-a", available_backend_name, src)
    _make(cfg, "b", "credentials", "pw-b", available_backend_name)
    return cfg


def _mgr(cfg):
    return CredentialManager(cfg)


# ---- manager: credentials ----

def test_move_single_account(cred_vaults):
    cfg = cred_vaults
    r = _mgr(cfg).transfer("a", "b", ["github", "alice"], src_password="pw-a", dst_password="pw-b")
    assert r.transferred == ["github/alice"] and not r.skipped and not r.copied

    a, b = _load(cfg, "a", "pw-a"), _load(cfg, "b", "pw-b")
    assert [x.userid for x in a.services["github"]] == ["bob"]
    assert [x.userid for x in b.services["github"]] == ["alice"]


def test_move_preserves_password_notes_history_and_timestamps(cred_vaults):
    cfg = cred_vaults
    before = _load(cfg, "a", "pw-a").services["github"][0]
    assert before.userid == "alice" and before.history  # sanity: history exists

    _mgr(cfg).transfer("a", "b", ["github", "alice"], src_password="pw-a", dst_password="pw-b")
    after = _load(cfg, "b", "pw-b").services["github"][0]
    assert after.to_dict() == before.to_dict()


def test_move_whole_service(cred_vaults):
    cfg = cred_vaults
    r = _mgr(cfg).transfer("a", "b", ["github"], src_password="pw-a", dst_password="pw-b")
    assert sorted(r.transferred) == ["github/alice", "github/bob"]
    a, b = _load(cfg, "a", "pw-a"), _load(cfg, "b", "pw-b")
    assert "github" not in a.services and "gitlab" in a.services  # emptied service removed
    assert len(b.services["github"]) == 2


def test_move_everything(cred_vaults):
    cfg = cred_vaults
    r = _mgr(cfg).transfer("a", "b", [], src_password="pw-a", dst_password="pw-b")
    assert len(r.transferred) == 3
    assert _load(cfg, "a", "pw-a").services == {}
    assert set(_load(cfg, "b", "pw-b").services) == {"github", "gitlab"}


def test_copy_leaves_source_untouched(cred_vaults):
    cfg = cred_vaults
    r = _mgr(cfg).transfer("a", "b", [], copy=True, src_password="pw-a", dst_password="pw-b")
    assert r.copied and len(r.transferred) == 3
    assert len(_load(cfg, "a", "pw-a").services) == 2
    assert len(_load(cfg, "b", "pw-b").services) == 2


def test_conflicts_are_skipped_and_stay_in_source(cred_vaults):
    cfg = cred_vaults
    s = CredentialsSchema()
    vault = Vault(cfg, name="b")
    dek, doc = vault.unlock("pw-b")
    s.cmd_add(doc, ["github", "alice"], {**GEN, "password": "DIFFERENT"}, cfg)
    vault.save(doc, dek)

    r = _mgr(cfg).transfer("a", "b", ["github"], src_password="pw-a", dst_password="pw-b")
    assert r.transferred == ["github/bob"] and r.skipped == ["github/alice"]

    a, b = _load(cfg, "a", "pw-a"), _load(cfg, "b", "pw-b")
    assert [x.userid for x in a.services["github"]] == ["alice"]          # still in source
    by_user = {x.userid: x.password for x in b.services["github"]}
    assert by_user == {"alice": "DIFFERENT", "bob": "bob-pw"}              # dest alice untouched


def test_overwrite_replaces_conflicts(cred_vaults):
    cfg = cred_vaults
    s = CredentialsSchema()
    vault = Vault(cfg, name="b")
    dek, doc = vault.unlock("pw-b")
    s.cmd_add(doc, ["github", "alice"], {**GEN, "password": "DIFFERENT"}, cfg)
    vault.save(doc, dek)

    r = _mgr(cfg).transfer("a", "b", ["github", "alice"], overwrite=True, src_password="pw-a", dst_password="pw-b")
    assert r.transferred == ["github/alice"] and not r.skipped
    [acc] = _load(cfg, "b", "pw-b").services["github"]
    assert acc.password == "alice-pw-2"
    assert [x.userid for x in _load(cfg, "a", "pw-a").services["github"]] == ["bob"]


def test_nothing_moves_if_selection_matches_nothing(cred_vaults):
    cfg = cred_vaults
    with pytest.raises(SchemaError):
        _mgr(cfg).transfer("a", "b", ["nosuchservice"], src_password="pw-a", dst_password="pw-b")
    assert len(_load(cfg, "a", "pw-a").services) == 2


def test_schema_mismatch_is_rejected_before_unlocking(cred_vaults, available_backend_name):
    cfg = cred_vaults
    _make(cfg, "e", "env", "pw-e", available_backend_name)
    with pytest.raises(VaultError, match="Schema mismatch"):
        _mgr(cfg).transfer("a", "e", [])  # no passwords given: must fail before asking for any


def test_same_source_and_destination_rejected(cred_vaults):
    with pytest.raises(VaultError):
        _mgr(cred_vaults).transfer("a", "a", [])


def test_missing_vault_rejected(cred_vaults):
    from credmgr.core import VaultNotFound
    with pytest.raises(VaultNotFound):
        _mgr(cred_vaults).transfer("a", "ghost", [])


def test_password_required_names_the_vault_that_needs_it(cred_vaults):
    mgr = _mgr(cred_vaults)
    with pytest.raises(PasswordRequired) as e:
        mgr.transfer("a", "b", [])
    assert e.value.vault_name == "a"
    with pytest.raises(PasswordRequired) as e:
        mgr.transfer("a", "b", [], src_password="pw-a")
    assert e.value.vault_name == "b"


def test_wrong_destination_password_leaves_both_vaults_unchanged(cred_vaults):
    from credmgr.core import AuthenticationError
    cfg = cred_vaults
    with pytest.raises(AuthenticationError):
        _mgr(cfg).transfer("a", "b", [], src_password="pw-a", dst_password="nope")
    assert len(_load(cfg, "a", "pw-a").services) == 2
    assert _load(cfg, "b", "pw-b").services == {}


def test_works_across_different_backends(redirect_config):
    from credmgr.crypto.registry import available_backends
    backends = sorted(available_backends())
    if len(backends) < 2:
        pytest.skip("needs two crypto backends installed")
    cfg = redirect_config
    _make(cfg, "x", "env", "pw-x", backends[0], lambda d: EnvSchema().cmd_add(d, ["K", "v"], {}, cfg))
    _make(cfg, "y", "env", "pw-y", backends[1])
    _mgr(cfg).transfer("x", "y", ["K"], src_password="pw-x", dst_password="pw-y")
    assert _load(cfg, "y", "pw-y").get("K") == "v"


def test_transfer_writes_no_search_index(cred_vaults):
    cfg = cred_vaults
    _mgr(cfg).transfer("a", "b", [], src_password="pw-a", dst_password="pw-b")
    assert not (cfg.master_dir / "index.json").exists()


# ---- manager: env ----

@pytest.fixture
def env_vaults(redirect_config, available_backend_name):
    cfg = redirect_config

    def src(doc):
        s = EnvSchema()
        s.cmd_add(doc, ["API_KEY", "k1"], {}, cfg)
        s.cmd_add(doc, ["DB_URL", "postgres://x"], {}, cfg)

    _make(cfg, "e1", "env", "pw1", available_backend_name, src)
    _make(cfg, "e2", "env", "pw2", available_backend_name,
          lambda d: EnvSchema().cmd_add(d, ["DB_URL", "existing"], {}, cfg))
    return cfg


def test_env_move_one_key(env_vaults):
    cfg = env_vaults
    r = _mgr(cfg).transfer("e1", "e2", ["API_KEY"], src_password="pw1", dst_password="pw2")
    assert r.transferred == ["API_KEY"]
    assert _load(cfg, "e1", "pw1").get("API_KEY") is None
    assert _load(cfg, "e2", "pw2").get("API_KEY") == "k1"


def test_env_conflict_skipped_then_overwritten(env_vaults):
    cfg = env_vaults
    r = _mgr(cfg).transfer("e1", "e2", [], src_password="pw1", dst_password="pw2")
    assert r.transferred == ["API_KEY"] and r.skipped == ["DB_URL"]
    assert _load(cfg, "e2", "pw2").get("DB_URL") == "existing"
    assert _load(cfg, "e1", "pw1").get("DB_URL") == "postgres://x"

    r = _mgr(cfg).transfer("e1", "e2", ["DB_URL"], overwrite=True, src_password="pw1", dst_password="pw2")
    assert r.transferred == ["DB_URL"]
    assert _load(cfg, "e2", "pw2").get("DB_URL") == "postgres://x"
    assert _load(cfg, "e1", "pw1").entries == []


def test_text_schema_does_not_support_transfer(redirect_config, available_backend_name):
    cfg = redirect_config
    _make(cfg, "t1", "text", "p1", available_backend_name)
    _make(cfg, "t2", "text", "p2", available_backend_name)
    with pytest.raises(SchemaError):
        _mgr(cfg).transfer("t1", "t2", [], src_password="p1", dst_password="p2")


# ---- CLI ----

def test_cli_move(cred_vaults):
    result = runner.invoke(app, ["transfer", "a", "b", "github", "alice"], input="pw-a\npw-b\n")
    assert result.exit_code == 0, result.output
    assert "Moved 1 entry from 'a' to 'b'" in result.output
    assert "github/alice" in result.output
    assert [x.userid for x in _load(cred_vaults, "b", "pw-b").services["github"]] == ["alice"]


def test_cli_copy_all(cred_vaults):
    result = runner.invoke(app, ["transfer", "a", "b", "--all", "--copy"], input="pw-a\npw-b\n")
    assert result.exit_code == 0, result.output
    assert "Copied 3 entries" in result.output
    assert len(_load(cred_vaults, "a", "pw-a").services) == 2


def test_cli_requires_selection_or_all(cred_vaults):
    result = runner.invoke(app, ["transfer", "a", "b"])
    assert result.exit_code != 0
    assert "--all" in result.output


def test_cli_rejects_all_with_entry_args(cred_vaults):
    result = runner.invoke(app, ["transfer", "a", "b", "github", "--all"])
    assert result.exit_code != 0


def test_cli_reports_skipped(env_vaults):
    result = runner.invoke(app, ["transfer", "e1", "e2", "--all"], input="pw1\npw2\n")
    assert result.exit_code == 0, result.output
    assert "Skipped 1 already present" in result.output
    assert "DB_URL" in result.output


def test_cli_schema_mismatch_message(cred_vaults, available_backend_name):
    _make(cred_vaults, "e", "env", "pw-e", available_backend_name)
    result = runner.invoke(app, ["transfer", "a", "e", "--all"])
    assert result.exit_code != 0
    assert "same schema" in result.output
