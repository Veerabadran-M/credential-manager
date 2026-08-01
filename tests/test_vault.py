"""Vault-level tests: envelope encryption round trips, backend migration,
legacy version migration, and consistent authentication-failure behavior
regardless of which backend is in use.
"""

from __future__ import annotations

import base64
import json
import os

import pytest

from credmgr.crypto.registry import available_backends
from credmgr.models import Account, Credentials
from credmgr.vault import AuthenticationError, Vault, VaultError

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

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
    assert raw["version"] == 2

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

def test_v1_vault_is_migrated_to_v2_on_read(config):
    """Hand-construct a pre-plugin-architecture (v1) vault on disk and
    confirm it's transparently upgraded to the v2 layout, without needing
    to touch the ciphertext bytes (a pure structural transform)."""
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    password = "legacy-password"
    kek = hash_secret_raw(secret=password.encode(), salt=salt, time_cost=3, 
                    memory_cost=65536, parallelism=2, hash_len=32, type=Type.ID)
    dek = AESGCM.generate_key(bit_length=256)

    nonce1 = os.urandom(12)
    wrapped_key_ct = AESGCM(kek).encrypt(nonce1, dek, b"credmgr-dek")

    vault_plaintext = json.dumps({}).encode("utf-8")
    nonce2 = os.urandom(12)
    vault_ct = AESGCM(dek).encrypt(nonce2, vault_plaintext, b"credmgr-vault")

    raw_v1 = {
        "version": 1,
        "kdf": {
            "algorithm": "argon2id", "time_cost": 3, "memory_cost": 65536,
            "parallelism": 2, "hash_len": 32, "salt": _b64e(salt),
        },
        "cipher": "aes256gcm",
        "encrypted_key": {"nonce": _b64e(nonce1), "ciphertext": _b64e(wrapped_key_ct)},
        "vault": {"nonce": _b64e(nonce2), "ciphertext": _b64e(vault_ct)},
    }

    config.vault_file.parent.mkdir(parents=True, exist_ok=True)
    config.vault_file.write_text(json.dumps(raw_v1))

    vault = Vault(config)
    dek_out, creds = vault.unlock(password)

    assert creds.services == {}

    # Persist once (e.g. via save()) and confirm the on-disk layout is v2.
    vault.save(creds, dek_out)
    raw_v2 = json.loads(config.vault_file.read_text())
    assert raw_v2["version"] == 2
    assert raw_v2["backend"] == "aesgcm-cryptography"
    assert "cipher" not in raw_v2
    assert "nonce" not in raw_v2["vault"]  # combined into a single ciphertext blob