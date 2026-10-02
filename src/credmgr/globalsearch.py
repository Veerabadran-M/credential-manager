"""Cross-vault search, powering `credmgr global <query>`.

Nothing is stored. There is no search index, catalogue, or cache of
identifiers on disk: each search unlocks every searchable vault (using
a still-valid session key if one exists, otherwise the vault's master
password), builds its searchable rows in memory from the decrypted
document (see `Schema.search_entries`), matches them against the
query, and drops everything that didn't match. Only the vaults that
produced at least one hit stay unlocked in memory, until the user picks
a result (or the session object is closed), so retrieving the chosen
secret needs no second password prompt and no new on-disk session
cache. Trading speed for it: cost grows with the number of vaults
(each needs its own Argon2 derivation unless a session key is cached).

This module is core application code: it never prompts or prints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .schemas import CommandResult, get_schema
from .schemas.base import SchemaError

if TYPE_CHECKING:  # pragma: no cover
    from .core.manager import CredentialManager, UnlockedVault

@dataclass
class GlobalMatch:
    vault: str
    schema: str
    summary: list  # list[tuple[label, value]]
    args: list

@dataclass
class GlobalSearchSession:
    """One `global` run. Call `search_vault()` for each vault (it
    raises PasswordRequired exactly like every other unlock path), then
    `get()` for whichever match the user selects, then `close()`."""
    manager: "CredentialManager"
    query: str
    _held: dict = field(default_factory=dict)  # vault name -> UnlockedVault, hit vaults only

    def __post_init__(self):
        self.query = (self.query or "").strip()
        if not self.query:
            raise SchemaError("Usage: credmgr global <query>")

    def search_vault(self, vault_name: str, *, password: str | None = None) -> list:
        """Search one vault. Returns [] without unlocking anything if
        the vault's schema doesn't support global search."""
        schema_name = self.manager.peek_schema(name=vault_name)
        schema = get_schema(schema_name)  # UnknownSchemaError for unreadable/unknown schemas
        if not schema.supports_global_search():
            return []

        unlocked = self.manager.unlock(
            vault_name=vault_name, password=password, remember=False,
            prompt=f"Master password for vault '{vault_name}': ",
        )
        matches = match_document(vault_name, schema_name, unlocked.schema, unlocked.document, self.query)
        if matches:
            self._held[vault_name] = unlocked
        # else: `unlocked` goes out of scope here -- nothing is kept for a vault with no hits.
        return matches

    def get(self, match: GlobalMatch) -> CommandResult:
        unlocked = self._held[match.vault]
        return unlocked.schema.cmd_get(unlocked.document, match.args, self.manager.config)

    def close(self) -> None:
        self._held.clear()

def match_document(vault_name: str, schema_name: str, schema, document, query: str) -> list:
    """Case-insensitive, partial-match search across every searchable
    field of every entry in one already-unlocked document."""
    q = query.strip().lower()
    results = []
    for entry in schema.search_entries(document):
        if any(q in str(value).lower() for value in entry.fields.values()):
            results.append(GlobalMatch(
                vault=vault_name,
                schema=schema_name,
                summary=[tuple(pair) for pair in entry.summary],
                args=list(entry.args),
            ))
    return results

def purge_legacy_index(config) -> bool:
    """Delete the plaintext `index.json` that earlier credmgr versions
    kept in the master directory (it listed every service/userid/key
    name unencrypted). Returns True if a file was removed."""
    removed = False
    base = config.master_dir / "index.json"
    for path in (base, base.with_suffix(".tmp")):
        try:
            Path(path).unlink()
            removed = True
        except FileNotFoundError:
            pass
        except OSError:
            pass
    return removed
