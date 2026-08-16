"""CredentialManager: the application layer's single entry point.

Everything here used to live inline in credmgr/cli.py's command
functions. It's been pulled out so any frontend -- the bundled Typer
CLI, a future REPL/TUI/GUI/REST API, or a test harness -- can drive
credmgr without going through argument parsing or a terminal.

Design notes:
  * Every method takes plain values in and returns plain data out
    (dataclasses, primitives, or a schema CommandResult); none of them
    print, prompt, or otherwise touch a terminal.
  * Anything that needs the vault's master password accepts an optional
    `password` argument. If it's needed and not supplied (and no valid
    cached session key covers it), the method raises PasswordRequired
    instead of prompting -- the frontend obtains the password however
    fits it, then retries the same call with `password=`.
  * Authentication/authorization failures, validation failures, and
    "not found" conditions are all raised as exceptions (the same ones
    the underlying modules already define: VaultError,
    AuthenticationError, SchemaError, VaultManagerError, ...) rather
    than being swallowed and printed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import auth as auth_mod
from .. import datasources, globalindex, vaultmgr
from ..config import Configuration
from ..config import config as _default_config
from ..crypto.registry import get_backend, resolve_backend
from ..datasources import FetchResult
from ..generator import generate_passphrase, generate_password
from ..schemas import CommandResult, get_schema
from ..schemas.base import Schema
from ..vault import Vault, VaultError

class PasswordRequired(Exception):
    """Raised when an operation needs the vault's master password and no
    valid cached session key is available. `vault_name` and `prompt`
    give a frontend everything it needs to ask the user and retry."""

    def __init__(self, vault_name: str, prompt: str | None = None):
        self.vault_name = vault_name
        self.prompt = prompt or f"Master password for vault '{vault_name}': "
        super().__init__(self.prompt)

class VaultNotFound(Exception):
    """Raised when an operation targets a vault that doesn't exist on
    disk yet (as opposed to an authentication failure)."""

    def __init__(self, vault_name: str):
        self.vault_name = vault_name
        super().__init__(f"Vault '{vault_name}' not found.")

class VaultManagerActiveVaultError(VaultError):
    """Raised by vault_delete() when asked to delete the active vault."""

    def __init__(self, name: str):
        super().__init__(f"Cannot delete the active vault '{name}'. Switch to another vault first.")

@dataclass
class UnlockedVault:
    dek: bytes
    document: Any
    vault: Vault
    schema: Schema

@dataclass
class InitResult:
    argon2_time_cost: int
    argon2_memory_cost: int
    argon2_parallelism: int
    argon2_hash_len: int
    fetch_results: list[FetchResult] | None  # None when data fetching was skipped

@dataclass
class VaultSummary:
    name: str
    schema: str
    active: bool

class CredentialManager:
    """The application-layer facade. One instance per Configuration;
    frontends typically keep one around per process (or per test)."""

    def __init__(self, config: Configuration | None = None):
        self.config = config or _default_config

    # ================================================================
    # Setup
    # ================================================================

    def vault_exists(self, name: str | None = None) -> bool:
        return Vault(self.config, name=name).exists()

    def init_vault(
        self,
        master_password: str,
        backend_name: str,
        *,
        argon2_time_cost: int | None = None,
        argon2_memory_cost: int | None = None,
        argon2_parallelism: int | None = None,
        skip_data_fetch: bool = False,
    ) -> InitResult:
        """Create the active ("default" on a fresh install) vault."""
        vault = Vault(self.config)
        if vault.exists():
            raise VaultError("Vault already initialized.")

        self.config.backend = backend_name
        if argon2_time_cost is not None:
            self.config.argon2_time_cost = argon2_time_cost
        if argon2_memory_cost is not None:
            self.config.argon2_memory_cost = argon2_memory_cost
        if argon2_parallelism is not None:
            self.config.argon2_parallelism = argon2_parallelism

        fetch_results = None if skip_data_fetch else self.fetch_data()

        vault.create(backend_name, master_password, "credentials")
        globalindex.update_vault(self.config, vault.name, "credentials", get_schema("credentials").new_document())
        self.config.save()

        return InitResult(
            argon2_time_cost=self.config.argon2_time_cost,
            argon2_memory_cost=self.config.argon2_memory_cost,
            argon2_parallelism=self.config.argon2_parallelism,
            argon2_hash_len=self.config.argon2_hash_len,
            fetch_results=fetch_results,
        )

    def fetch_data(self) -> list[FetchResult]:
        """(Re-)download the wordlist/common-passwords/sequences/breach
        datasets into <master_dir>/data/. Safe to re-run any time."""
        return datasources.fetch_all(self.config)

    def change_password(self, old_password: str, new_password: str) -> None:
        """Rotate the active vault's master password."""
        vault = Vault(self.config)
        if not vault.exists():
            raise VaultNotFound(self.config.active_vault)
        vault.rotate_master_password(old_password, new_password)

    def migrate_backend(self, master_password: str, new_backend: str | None = None) -> str:
        """Re-encrypt the active vault under a different crypto backend.
        Returns the resolved backend name that was migrated to."""
        vault = Vault(self.config)
        if not vault.exists():
            raise VaultNotFound(self.config.active_vault)

        target = resolve_backend(cli_value=new_backend, config_value=self.config.backend)
        get_backend(target)  # fail fast, before touching the vault

        vault.migrate_backend(master_password, target)

        if self.config.backend != target:
            self.config.backend = target
            self.config.save()

        # The DEK changed, so any cached session key is now stale.
        auth_mod.delete_cache(auth_mod.session_cache_paths(self.config))

        return target

    def config_show(self) -> dict:
        return self.config.as_dict()

    def config_set(self, key: str, value: str) -> None:
        if key in self.config.immutable_parameters and vaultmgr.list_vault_names(self.config):
            raise ValueError(
                f"'{key}' is fixed once a vault exists. To use a different "
                "backend, migrate the vault to it instead. To change the "
                "Argon2 work factor, create a new vault and import data into it."
            )
        self.config.set_value(key, value)
        self.config.save()

    def config_reset(self) -> None:
        if self.config.settings_file.exists():
            self.config.settings_file.unlink()

    def generate_secret(self, *, passphrase: bool, length: int, words: int) -> str:
        if length < 8:
            raise ValueError("Password length must be at least 8.")
        if length > 256:
            raise ValueError("Password length must be 256 characters or fewer.")
        if words < 3 or words > 12:
            raise ValueError("Passphrase word count must be between 3 and 12.")

        if passphrase:
            return generate_passphrase(words, self.config)
        return generate_password(length)

    # ================================================================
    # Vault management
    # ================================================================

    def vault_names(self) -> list[str]:
        return vaultmgr.list_vault_names(self.config)

    def peek_schema(self, name: str) -> str:
        return vaultmgr.peek_schema(self.config, name)

    def vault_create(self, name: str, schema_name: str, backend_name: str, master_password: str) -> None:
        vaultmgr.validate_vault_name(name)
        get_schema(schema_name)  # raises UnknownSchemaError if unknown

        vault = Vault(self.config, name=name)
        if vault.exists():
            raise VaultError(f"Vault '{name}' already exists.")

        get_backend(backend_name)  # fail fast, before touching disk

        vault.create(backend_name, master_password, schema_name)
        globalindex.update_vault(self.config, name, schema_name, get_schema(schema_name).new_document())

    def vault_list(self) -> list[VaultSummary]:
        return [
            VaultSummary(name=name, schema=self.peek_schema(name), active=(name == self.config.active_vault))
            for name in self.vault_names()
        ]

    def vault_current(self) -> str:
        return self.config.active_vault

    def vault_use(self, name: str) -> None:
        if not vaultmgr.vault_exists(self.config, name):
            raise VaultNotFound(name)
        self.config.active_vault = name
        self.config.save()

    def vault_delete(self, name: str) -> None:
        if not vaultmgr.vault_exists(self.config, name):
            raise VaultNotFound(name)
        if name == self.config.active_vault:
            raise VaultManagerActiveVaultError(name)
        vaultmgr.delete_vault(self.config, name)
        globalindex.remove_vault(self.config, name)

    # ================================================================
    # Authentication
    # ================================================================

    def unlock(
        self,
        *,
        vault_name: str | None = None,
        password: str | None = None,
        fresh: bool = False,
        prompt: str | None = None,
    ) -> UnlockedVault:
        """Resolve (dek, document, vault, schema) for `vault_name` (the
        active vault, by default). Tries the session cache first unless
        `fresh`; raises PasswordRequired if a password is needed and
        wasn't supplied; raises VaultNotFound if there's no vault there
        at all."""
        probe = Vault(self.config, name=vault_name)
        if not probe.exists():
            raise VaultNotFound(vault_name or self.config.active_vault)

        if not fresh:
            cached = auth_mod.try_cached_session(self.config, vault_name)
            if cached is not None:
                dek, document, vault = cached
                return UnlockedVault(dek, document, vault, get_schema(vault.schema_name))

        if password is None:
            raise PasswordRequired(vault_name or self.config.active_vault, prompt)

        dek, document, vault = auth_mod.authenticate(password, self.config, vault_name, remember=not fresh)
        return UnlockedVault(dek, document, vault, get_schema(vault.schema_name))

    def _save(self, unlocked: UnlockedVault) -> None:
        unlocked.vault.save(unlocked.document, unlocked.dek)
        # The document just saved is already decrypted in memory, so the
        # cross-vault search index can be kept in sync for free -- no
        # extra unlock, no extra vault read.
        globalindex.update_vault(self.config, unlocked.vault.name, unlocked.vault.schema_name, unlocked.document)

    # ================================================================
    # Read/write operations on the active (or a named) vault
    # ================================================================

    def list_entries(self, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        return u.schema.cmd_list(u.document, [], self.config)

    def list_all_for_vault(self, vault_name: str, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(vault_name=vault_name, password=password, fresh=fresh,
                         prompt=f"Master password for vault '{vault_name}': ")
        return u.schema.cmd_list_all(u.document, self.config)

    def get(self, args: list, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        return u.schema.cmd_get(u.document, args, self.config)

    def search(self, query: str, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        return u.schema.cmd_search(u.document, query, self.config)

    def copy(self, args: list, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        return u.schema.cmd_copy(u.document, args, self.config)

    def history(self, args: list, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        return u.schema.cmd_history(u.document, args, self.config)

    def audit(self, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        return u.schema.cmd_audit(u.document, self.config)

    def add(self, args: list, opts: dict, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        result = u.schema.cmd_add(u.document, args, opts, self.config)
        if result.mutated:
            self._save(u)
        return result

    def update(self, args: list, opts: dict, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        result = u.schema.cmd_update(u.document, args, opts, self.config)
        if result.mutated:
            self._save(u)
        return result

    def delete(self, args: list, *, password: str | None = None, fresh: bool = False, confirmed: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        result = u.schema.cmd_delete(u.document, args, self.config, confirmed=confirmed)
        if result.mutated:
            self._save(u)
        return result

    def import_entries(self, filepath: str, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(password=password, fresh=fresh)
        result = u.schema.cmd_import(u.document, filepath, self.config)
        if result.mutated:
            self._save(u)
        return result

    def export(self, *, password: str | None = None) -> CommandResult:
        # Always re-authenticate for export, regardless of any cached
        # session, and never cache the result.
        u = self.unlock(password=password, fresh=True)
        return u.schema.cmd_export(u.document, self.config)

    # ================================================================
    # Cross-vault ("global") search
    # ================================================================

    def stale_index_vaults(self) -> list[str]:
        """Prune index entries for vaults no longer on disk, then return
        the (possibly still-present) vault names whose index entries are
        out of date and need `refresh_vault_index()` before a `global`
        search can trust them."""
        names = self.vault_names()
        globalindex.prune_removed_vaults(self.config, names)
        return globalindex.stale_vault_names(self.config, names)

    def refresh_vault_index(self, vault_name: str, *, password: str | None = None, fresh: bool = False) -> None:
        u = self.unlock(vault_name=vault_name, password=password, fresh=fresh,
                         prompt=f"Master password for vault '{vault_name}' (index refresh): ")
        globalindex.update_vault(self.config, vault_name, u.vault.schema_name, u.document)

    def index_search(self, query: str) -> list[dict]:
        return globalindex.search(self.config, query)

    def get_from_vault(self, vault_name: str, args: list, *, password: str | None = None, fresh: bool = False) -> CommandResult:
        u = self.unlock(vault_name=vault_name, password=password, fresh=fresh,
                         prompt=f"Password for vault \"{vault_name}\": ")
        return u.schema.cmd_get(u.document, args, self.config)
