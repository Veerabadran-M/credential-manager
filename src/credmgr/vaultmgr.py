"""Multi-vault directory management.

Owns the filesystem layout of named vaults under
<master_dir>/vaults/<name>/ (create/list/delete). Never touches
encryption or vault contents -- see vault.py, instantiated per named
vault via Vault(config, name=...).
"""

from __future__ import annotations

import json
import re
import shutil

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

class VaultManagerError(Exception):
    pass

def validate_vault_name(name: str) -> str:
    if not name or not _NAME_RE.match(name):
        raise VaultManagerError(
            "Vault name must be 1-64 characters long and contain only "
            "letters, digits, '-', and '_'."
        )
    return name

def vault_exists(config, name: str) -> bool:
    return (config.vault_dir(name) / "vault.json").exists()

def list_vault_names(config) -> list:
    """All vault names with a vault.json on disk, sorted alphabetically."""
    if not config.vaults_dir.exists():
        return []
    names = []
    for entry in sorted(config.vaults_dir.iterdir(), key=lambda p: p.name):
        if entry.is_dir() and (entry / "vault.json").exists():
            names.append(entry.name)
    return names

def peek_schema(config, name: str) -> str:
    """Read the (plaintext) "schema" field straight off disk, without
    unlocking anything -- the schema name is stored alongside the KDF
    parameters and ciphertext, never inside the encrypted payload."""
    vault_file = config.vault_dir(name) / "vault.json"
    try:
        with vault_file.open("r", encoding="utf-8") as f:
            raw = json.load(f)
        return raw.get("schema", "credentials")
    except (OSError, json.JSONDecodeError, AttributeError):
        return "?"

def delete_vault(config, name: str) -> None:
    vault_dir = config.vault_dir(name)
    if not (vault_dir / "vault.json").exists():
        raise VaultManagerError(f"Vault '{name}' does not exist.")
    shutil.rmtree(vault_dir)
