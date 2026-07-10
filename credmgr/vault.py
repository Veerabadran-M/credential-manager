"""Versioned, envelope-encrypted vault storage.

On-disk layout:

    {
        "version": 1,
        "kdf": {...},
        "cipher": "aes256gcm",
        "encrypted_key": {"nonce": "...", "ciphertext": "..."},
        "vault": {"nonce": "...", "ciphertext": "..."}
    }

"encrypted_key" is the random Data Encryption Key (DEK), wrapped by a key
derived (via Argon2id) from the master password. "vault" is the entire
credentials tree -- services, accounts, passwords, notes, history --
serialized to JSON and encrypted as one blob under the DEK.

`version` exists so future releases can change this layout without
breaking existing vaults: add an entry to MIGRATIONS and bump
CURRENT_VERSION; `_migrate()` walks old vaults forward automatically.
"""

from __future__ import annotations

import json
import os
import shutil

from .crypto.envelope import (KDFParams, decrypt_blob, derive_kek, encrypt_blob, 
                                generate_dek, unwrap_dek, wrap_dek)
from .models import Credentials

CURRENT_VERSION = 1

class VaultError(Exception):
    pass

class AuthenticationError(VaultError):
    pass

# old_version -> function(raw_dict) -> raw_dict (upgraded to old_version + 1)
# Example for a future v1 -> v2 migration:
#     def _migrate_v1_to_v2(raw: dict) -> dict:
#         raw["version"] = 2
#         ...
#         return raw
#     MIGRATIONS = {1: _migrate_v1_to_v2}
MIGRATIONS: dict = {}

def _migrate(raw: dict) -> dict:
    version = raw.get("version", 1)
    while version in MIGRATIONS:
        raw = MIGRATIONS[version](raw)
        version = raw["version"]

    if version != CURRENT_VERSION:
        raise VaultError(
            f"Vault version {version} is newer than the version this build of "
            f"credmgr supports ({CURRENT_VERSION}). Please upgrade credmgr."
        )
    return raw

class Vault:
    def __init__(self, config):
        self.config = config

    # ---- lifecycle ----

    def exists(self) -> bool:
        return self.config.vault_file.exists()

    def create(self, cipher: str, master_password: str) -> bytes:
        """Initialize a brand-new, empty vault. Returns the DEK."""
        if self.exists():
            raise VaultError("Vault already exists.")

        params = KDFParams(
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.argon2_hash_len
        )
        kek = derive_kek(master_password, params)
        dek = generate_dek(cipher)

        raw = {
            "version": CURRENT_VERSION,
            "kdf": params.to_dict(),
            "cipher": cipher,
            "encrypted_key": wrap_dek(dek, kek, cipher),
            "vault": encrypt_blob(
                dek, json.dumps(Credentials().to_dict()).encode("utf-8"), cipher
            )
        }
        self._write_raw(raw)
        return dek

    def unlock(self, master_password: str):
        """Derive the KEK, unwrap the DEK, decrypt the vault. Returns (dek, Credentials)."""
        raw = self._read_raw()

        params = KDFParams.from_dict(raw["kdf"])
        cipher_name = raw["cipher"]
        kek = derive_kek(master_password, params)

        try:
            dek = unwrap_dek(raw["encrypted_key"], kek, cipher_name)
            plaintext = decrypt_blob(dek, raw["vault"], cipher_name)
        except Exception:
            raise AuthenticationError("Authentication failed.")

        try:
            creds = Credentials.from_dict(json.loads(plaintext.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as e:
            raise VaultError("Vault contents are corrupted or unreadable.") from e
        return dek, creds

    def unlock_with_dek(self, dek: bytes) -> Credentials:
        """Decrypt the vault using an already-known DEK (e.g. from the session cache)."""
        raw = self._read_raw()
        cipher_name = raw["cipher"]

        try:
            plaintext = decrypt_blob(dek, raw["vault"], cipher_name)
        except Exception:
            raise AuthenticationError("Session key is no longer valid. Please re-authenticate.")

        try:
            return Credentials.from_dict(json.loads(plaintext.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as e:
            raise VaultError("Vault contents are corrupted or unreadable.") from e

    def save(self, creds: Credentials, dek: bytes) -> None:
        """Re-encrypt and persist the whole vault under the existing DEK."""
        raw = self._read_raw()
        cipher_name = raw["cipher"]

        raw["version"] = CURRENT_VERSION
        raw["vault"] = encrypt_blob(dek, json.dumps(creds.to_dict()).encode("utf-8"), cipher_name)
        self._write_raw(raw)

    def rotate_master_password(self, old_password: str, new_password: str) -> None:
        """Re-wrap the DEK under a new master password. Vault contents untouched."""
        raw = self._read_raw()
        old_params = KDFParams.from_dict(raw["kdf"])
        cipher_name = raw["cipher"]

        old_kek = derive_kek(old_password, old_params)
        try:
            dek = unwrap_dek(raw["encrypted_key"], old_kek, cipher_name)
        except Exception:
            raise AuthenticationError("Authentication failed.")

        new_params = KDFParams(
            time_cost=old_params.time_cost,
            memory_cost=old_params.memory_cost,
            parallelism=old_params.parallelism,
            hash_len=old_params.hash_len
        )
        new_kek = derive_kek(new_password, new_params)

        raw["kdf"] = new_params.to_dict()
        raw["encrypted_key"] = wrap_dek(dek, new_kek, cipher_name)
        self._write_raw(raw)

    # ---- internal I/O ----

    def _read_raw(self) -> dict:
        if not self.exists():
            raise VaultError("Vault not found. Run 'credmgr init' first.")

        try:
            with self.config.vault_file.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except OSError as e:
            raise VaultError("Unable to read vault file.") from e
        except json.JSONDecodeError:
            if not self.config.vault_bak_file.exists():
                raise VaultError("Vault file is corrupted and no backup exists.")
            try:
                with self.config.vault_bak_file.open("r", encoding="utf-8") as f:
                    raw = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                raise VaultError("Vault file and backup are corrupted or unreadable.") from e
            shutil.copy2(self.config.vault_bak_file, self.config.vault_file)
            self.config.vault_file.chmod(0o600)

        return _migrate(raw)

    def _write_raw(self, raw: dict) -> None:
        self.config.master_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.config.master_dir.chmod(0o700)
        except OSError:
            pass

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.config.vault_temp_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        self.config.vault_temp_file.chmod(0o600)

        if self.config.vault_file.exists():
            shutil.copy2(self.config.vault_file, self.config.vault_bak_file)
            self.config.vault_bak_file.chmod(0o600)

        self.config.vault_temp_file.replace(self.config.vault_file)
        self.config.vault_file.chmod(0o600)
