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
from .. import datasources, globalsearch, vaultmgr
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
class TransferResult:
    src: str
    dst: str
    schema: str
    copied: bool                 # True = copy (source untouched), False = move
    transferred: list[str]       # labels of entries written to the destination
    skipped: list[str]           # labels left alone: already present in the destination

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

    def generate_secret(self, *, passphrase: bool, length: int, words: int, special_chars: str | None = None) -> str:
        if length < 8:
            raise ValueError("Password length must be at least 8.")
        if length > 256:
            raise ValueError("Password length must be 256 characters or fewer.")
        if words < 3 or words > 12:
            raise ValueError("Passphrase word count must be between 3 and 12.")

        if passphrase:
            if special_chars is not None:
                raise ValueError("-spl/--special-chars only applies to passwords, not passphrases.")
            return generate_passphrase(words, self.config)
        return generate_password(length, special_chars)

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
        remember: bool | None = None,
    ) -> UnlockedVault:
        """Resolve (dek, document, vault, schema) for `vault_name` (the
        active vault, by default). Tries the session cache first unless
        `fresh`; raises PasswordRequired if a password is needed and
        wasn't supplied; raises VaultNotFound if there's no vault there
        at all. After a password unlock the DEK is written to the
        session cache unless `fresh` or `remember=False` (a cache that
        already exists is still read either way)."""
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

        if remember is None:
            remember = not fresh
        dek, document, vault = auth_mod.authenticate(password, self.config, vault_name, remember=remember)
        return UnlockedVault(dek, document, vault, get_schema(vault.schema_name))

    def _save(self, unlocked: UnlockedVault) -> None:
        unlocked.vault.save(unlocked.document, unlocked.dek)
        # Older versions kept a plaintext search index; get rid of it
        # the first time we write anything.
        globalsearch.purge_legacy_index(self.config)

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
    # Cross-vault ("global") search -- in memory only, nothing persisted
    # ================================================================

    def global_search_session(self, query: str) -> globalsearch.GlobalSearchSession:
        """Start a cross-vault search. The caller drives it vault by
        vault (see globalsearch.GlobalSearchSession) so it can prompt
        for each master password as needed."""
        globalsearch.purge_legacy_index(self.config)
        return globalsearch.GlobalSearchSession(self, query)

    # ================================================================
    # Moving entries between vaults
    # ================================================================

    def transfer(
        self,
        src_name: str,
        dst_name: str,
        args: list,
        *,
        copy: bool = False,
        overwrite: bool = False,
        src_password: str | None = None,
        dst_password: str | None = None,
    ) -> TransferResult:
        """Move (or, with `copy=True`, copy) entries from one vault to
        another vault *of the same schema*. `args` selects entries the
        same way that schema's `get`/`delete` do; an empty list means
        every entry. Entries keep all their data (history, timestamps).

        Ordering is chosen so a failure can only ever leave an entry in
        both vaults, never in neither: the destination is saved first,
        and only entries actually written there are removed from the
        source. Entries that already exist in the destination are left
        in place in the source (reported as skipped) unless `overwrite`.
        Raises PasswordRequired(vault_name) for whichever vault still
        needs a password.
        """
        if src_name == dst_name:
            raise VaultError("Source and destination vaults must be different.")
        for name in (src_name, dst_name):
            if not vaultmgr.vault_exists(self.config, name):
                raise VaultNotFound(name)

        src_schema_name = self.peek_schema(src_name)
        dst_schema_name = self.peek_schema(dst_name)
        if src_schema_name != dst_schema_name:
            raise VaultError(
                f"Schema mismatch: '{src_name}' is '{src_schema_name}' but '{dst_name}' is "
                f"'{dst_schema_name}'. Entries can only be moved between vaults of the same schema."
            )

        src = self.unlock(vault_name=src_name, password=src_password,
                          prompt=f"Master password for source vault '{src_name}': ")
        dst = self.unlock(vault_name=dst_name, password=dst_password,
                          prompt=f"Master password for destination vault '{dst_name}': ")

        schema = src.schema
        items = schema.transfer_select(src.document, args)
        inserted, skipped = schema.transfer_insert(dst.document, items, overwrite=overwrite)

        if inserted:
            self._save(dst)          # 1. destination first ...
        if inserted and not copy:
            schema.transfer_remove(src.document, inserted)
            self._save(src)          # 2. ... then drop from the source

        return TransferResult(
            src=src_name, dst=dst_name, schema=src_schema_name, copied=copy,
            transferred=[schema.transfer_label(i) for i in inserted],
            skipped=[schema.transfer_label(i) for i in skipped],
        )
