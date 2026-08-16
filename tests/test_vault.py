"""Vault-level tests: envelope encryption round trips, backend migration,
and consistent authentication-failure behavior regardless of which
backend is in use.
"""

from __future__ import annotations

import json

import pytest

from credmgr.crypto.registry import available_backends
from credmgr.models import Account, Credentials
from credmgr.vault import AuthenticationError, Vault, VaultError

BACKEND_NAMES = available_backends()

@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_create_and_unlock_round_trip(config, backend_name):
    vault = Vault(config)
    vault.create(backend_name, "hunter2")

    dek, creds = vault.unlock("hunter2")
    assert isinstance(creds, Credentials)
    assert creds.services == {}

@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_save_and_reload_preserves_data(config, backend_name):
    vault = Vault(config)
    vault.create(backend_name, "hunter2")
    dek, creds = vault.unlock("hunter2")

    creds.services["netflix"] = [Account(userid="alice", password="s3cr3t", notes="n")]
    vault.save(creds, dek)

    _, reloaded = vault.unlock("hunter2")
    assert reloaded.services["netflix"][0].userid == "alice"
    assert reloaded.services["netflix"][0].password == "s3cr3t"

@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_wrong_password_raises_authentication_error(config, backend_name):
    vault = Vault(config)
    vault.create(backend_name, "correct-password")

    with pytest.raises(AuthenticationError):
        vault.unlock("wrong-password")

def test_wrong_password_raises_same_exception_type_across_backends(config):
    """The whole point of the plugin abstraction: callers should never need
    to know or care which backend raised the failure."""
    exception_types = set()
    for backend_name in BACKEND_NAMES:
        cfg = config
        cfg.master_dir = config.master_dir.parent / f"vault_{backend_name}"
        vault = Vault(cfg)
        vault.create(backend_name, "correct-password")
        try:
            vault.unlock("wrong-password")
        except Exception as e:  # noqa: BLE001 -- deliberately broad, checking the type
            exception_types.add(type(e))

    assert exception_types == {AuthenticationError}

@pytest.mark.skipif(len(BACKEND_NAMES) < 2, reason="need at least two backends installed")
def test_migrate_backend_preserves_data(config):
    source, target = BACKEND_NAMES[0], BACKEND_NAMES[1]
    vault = Vault(config)
    vault.create(source, "hunter2")
    dek, creds = vault.unlock("hunter2")
    creds.services["github"] = [Account(userid="bob", password="p4ss", notes="work account")]
    vault.save(creds, dek)

    vault.migrate_backend("hunter2", target)

    raw = json.loads(config.vault_file.read_text())
    assert raw["backend"] == target
    assert raw["version"] == 1

    _, reloaded = vault.unlock("hunter2")
    assert reloaded.services["github"][0].userid == "bob"
    assert reloaded.services["github"][0].password == "p4ss"

@pytest.mark.skipif(len(BACKEND_NAMES) < 2, reason="need at least two backends installed")
def test_migrate_backend_wrong_password_raises_authentication_error(config):
    source, target = BACKEND_NAMES[0], BACKEND_NAMES[1]
    vault = Vault(config)
    vault.create(source, "hunter2")

    with pytest.raises(AuthenticationError):
        vault.migrate_backend("wrong-password", target)

    # Vault must be untouched -- still readable with the original password and backend.
    raw = json.loads(config.vault_file.read_text())
    assert raw["backend"] == source

def test_migrate_backend_to_same_backend_is_a_no_op(config):
    backend_name = BACKEND_NAMES[0]
    vault = Vault(config)
    vault.create(backend_name, "hunter2")
    before = config.vault_file.read_text()

    vault.migrate_backend("hunter2", backend_name)

    after = config.vault_file.read_text()
    assert before == after