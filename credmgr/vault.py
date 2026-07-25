"""Versioned, envelope-encrypted vault storage.

On-disk layout:

    {
        "version": 2,
        "kdf": {...},
        "backend": "aesgcm-cryptography",
        "algorithm": "AES-256-GCM",
        "encrypted_key": {"ciphertext": "..."},
        "vault": {"ciphertext": "..."}
    }

"backend" names the registered crypto plugin (see credmgr/crypto/) that
encrypted this vault; "algorithm" is purely informational (human-readable
label, e.g. for `credmgr config show`). This module never imports a crypto
library itself -- it looks the backend up by name through the registry, so
the correct plugin is selected automatically regardless of which one is
actually installed.

"encrypted_key" is the random Data Encryption Key (DEK), wrapped by a key
derived (via Argon2id) from the master password. "vault" is the entire
credentials tree -- services, accounts, passwords, notes, history --
serialized to JSON and encrypted as one blob under the DEK.

`version` exists so future releases can change this layout without
breaking existing vaults: add an entry to MIGRATIONS and bump
CURRENT_VERSION; `_migrate()` walks old vaults forward automatically.
Changing which *backend* encrypts an existing vault's contents is a
different, explicit operation -- see `migrate_backend()` -- since it
requires the master password to actually re-encrypt data, not just
reshape metadata.
"""

from __future__ import annotations

import json
import os
import shutil

from .crypto import BackendUnavailableError, CryptoError, get_backend
from .crypto.envelope import (KDFParams, b64d, b64e, decrypt_blob, derive_kek,
                                encrypt_blob, generate_dek, unwrap_dek, wrap_dek)
from .models import Credentials

CURRENT_VERSION = 2

class VaultError(Exception):
    pass

class AuthenticationError(VaultError):
    pass

# Pre-plugin-architecture (v1) vaults identified the cipher by these short
# names instead of a registered backend name, and stored each blob as a
# separate {"nonce": ..., "ciphertext": ...} pair instead of one combined
# ciphertext. Both are purely structural differences -- no decryption is
# needed to move a vault from v1 to v2.
_V1_CIPHER_TO_BACKEND = {
    "aes256gcm": "aesgcm-cryptography",
    "xchacha20poly1305": "xchacha-pynacl"
}

def _combine_blob(blob: dict) -> dict:
    """v1 stored nonce and ciphertext separately; v2 backends return (and
    expect) a single concatenated blob. Concatenating bytes is not a crypto
    operation, so this needs no key and can't fail authentication."""
    nonce = b64d(blob["nonce"])
    ciphertext = b64d(blob["ciphertext"])
    return {"ciphertext": b64e(nonce + ciphertext)}

def _migrate_v1_to_v2(raw: dict) -> dict:
    old_cipher = raw["cipher"]
    backend_name = _V1_CIPHER_TO_BACKEND.get(old_cipher, old_cipher)

    raw["version"] = 2
    raw["backend"] = backend_name
    try:
        raw["algorithm"] = get_backend(backend_name).algorithm
    except CryptoError:
        # Backend not installed right now -- still a valid v2 vault; the
        # algorithm label will be corrected the next time it's available.
        raw["algorithm"] = old_cipher
    raw["encrypted_key"] = _combine_blob(raw["encrypted_key"])
    raw["vault"] = _combine_blob(raw["vault"])
    del raw["cipher"]
    return raw

# old_version -> function(raw_dict) -> raw_dict (upgraded to old_version + 1)
MIGRATIONS: dict = {1: _migrate_v1_to_v2}

def _migrate(raw: dict) -> dict:
    version = raw.get("version", 1)
    while version in MIGRATIONS:
        raw = MIGRATIONS[version](raw)
        version = raw["version"]

    if version != CURRENT_VERSION:
        raise VaultError(
            f"Vault version {version} is newer than the version this build of credmgr supports ({CURRENT_VERSION}). Please upgrade credmgr.")
    return raw

class Vault:
    def __init__(self, config):
        self.config = config

    # ---- lifecycle ----

    def exists(self) -> bool:
        return self.config.vault_file.exists()

    def create(self, backend_name: str, master_password: str) -> bytes:
        """Initialize a brand-new, empty vault. Returns the DEK."""
        if self.exists():
            raise VaultError("Vault already exists.")

        backend = self._require_backend(backend_name)

        params = KDFParams(
            time_cost=self.config.argon2_time_cost,
            memory_cost=self.config.argon2_memory_cost,
            parallelism=self.config.argon2_parallelism,
            hash_len=self.config.argon2_hash_len
        )
        kek = derive_kek(master_password, params)
        dek = generate_dek(backend_name)

        raw = {
            "version": CURRENT_VERSION,
            "kdf": params.to_dict(),
            "backend": backend_name,
            "algorithm": backend.algorithm,
            "encrypted_key": wrap_dek(dek, kek, backend_name),
            "vault": encrypt_blob(
                dek, json.dumps(Credentials().to_dict()).encode("utf-8"), backend_name
            )
        }
        self._write_raw(raw)
        return dek

    def unlock(self, master_password: str):
        """Derive the KEK, unwrap the DEK, decrypt the vault. Returns (dek, Credentials)."""
        raw = self._read_raw()

        params = KDFParams.from_dict(raw["kdf"])
        backend_name = raw["backend"]
        self._require_backend(backend_name)
        kek = derive_kek(master_password, params)

        try:
            dek = unwrap_dek(raw["encrypted_key"], kek, backend_name)
            plaintext = decrypt_blob(dek, raw["vault"], backend_name)
        except BackendUnavailableError:
            raise
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
        backend_name = raw["backend"]
        self._require_backend(backend_name)

        try:
            plaintext = decrypt_blob(dek, raw["vault"], backend_name)
        except BackendUnavailableError:
            raise
        except Exception:
            raise AuthenticationError("Session key is no longer valid. Please re-authenticate.")

        try:
            return Credentials.from_dict(json.loads(plaintext.decode("utf-8")))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as e:
            raise VaultError("Vault contents are corrupted or unreadable.") from e

    def save(self, creds: Credentials, dek: bytes) -> None:
        """Re-encrypt and persist the whole vault under the existing DEK."""
        raw = self._read_raw()
        backend_name = raw["backend"]
        self._require_backend(backend_name)

        raw["version"] = CURRENT_VERSION
        raw["vault"] = encrypt_blob(dek, json.dumps(creds.to_dict()).encode("utf-8"), backend_name)
        self._write_raw(raw)

    def rotate_master_password(self, old_password: str, new_password: str) -> None:
        """Re-wrap the DEK under a new master password. Vault contents untouched."""
        raw = self._read_raw()
        old_params = KDFParams.from_dict(raw["kdf"])
        backend_name = raw["backend"]
        self._require_backend(backend_name)

        old_kek = derive_kek(old_password, old_params)
        try:
            dek = unwrap_dek(raw["encrypted_key"], old_kek, backend_name)
        except BackendUnavailableError:
            raise
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
        raw["encrypted_key"] = wrap_dek(dek, new_kek, backend_name)
        self._write_raw(raw)

    def migrate_backend(self, master_password: str, new_backend_name: str) -> None:
        """Re-encrypt the vault under a different crypto backend.

        Decrypts everything with the *current* backend, generates a fresh
        DEK sized for the *new* backend, and re-encrypts both the DEK
        (wrapped under the existing KEK -- the master password is
        unchanged) and the vault contents under the new backend. Plaintext
        only ever exists in memory; it's never written to disk mid-migration.
        """
        raw = self._read_raw()
        old_backend_name = raw["backend"]
        self._require_backend(old_backend_name)
        new_backend = self._require_backend(new_backend_name)

        params = KDFParams.from_dict(raw["kdf"])
        kek = derive_kek(master_password, params)

        try:
            old_dek = unwrap_dek(raw["encrypted_key"], kek, old_backend_name)
            plaintext = decrypt_blob(old_dek, raw["vault"], old_backend_name)
        except BackendUnavailableError:
            raise
        except Exception:
            raise AuthenticationError("Authentication failed.")

        if new_backend_name == old_backend_name:
            return  # nothing to do

        new_dek = generate_dek(new_backend_name)

        raw["version"] = CURRENT_VERSION
        raw["backend"] = new_backend_name
        raw["algorithm"] = new_backend.algorithm
        raw["encrypted_key"] = wrap_dek(new_dek, kek, new_backend_name)
        raw["vault"] = encrypt_blob(new_dek, plaintext, new_backend_name)
        self._write_raw(raw)

    # ---- internal helpers ----

    def _require_backend(self, backend_name: str):
        """Look up a backend, translating a missing dependency into the
        actionable message from the requirements doc rather than letting an
        ImportError (or an opaque registry error) bubble up raw."""
        try:
            return get_backend(backend_name)
        except BackendUnavailableError:
            raise
        except CryptoError as e:
            raise VaultError(str(e)) from e

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