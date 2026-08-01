"""Multi-vault directory management.

Owns the filesystem layout of named vaults under
<master_dir>/vaults/<name>/ (create/list/delete) and the one-time
migration of a pre-multi-vault install into that layout. Never touches
encryption or vault contents -- see vault.py, instantiated per named
vault via Vault(config, name=...).
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

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

def migrate_legacy_layout(config) -> None:
    """Upgrade a pre-multi-vault install in place.

    Old layout:
        ~/.credmgr/vault.json
        ~/.credmgr/vault.bak

    New layout:
        ~/.credmgr/vaults/default/vault.json
        ~/.credmgr/vaults/default/vault.bak

    Runs only once: if <master_dir>/vaults/ already exists, this is a
    no-op (already migrated, or a fresh multi-vault install that never had
    a legacy vault to begin with). Never overwrites an existing vault.
    """
    legacy_vault = config.master_dir / "vault.json"
    legacy_bak = config.master_dir / "vault.bak"

    if config.vaults_dir.exists() or not legacy_vault.exists():
        return

    default_dir = config.vault_dir("default")
    if (default_dir / "vault.json").exists():
        return  # never overwrite an existing vault

    default_dir.mkdir(parents=True, exist_ok=True)
    try:
        default_dir.chmod(0o700)
    except OSError:
        pass

    shutil.move(str(legacy_vault), str(default_dir / "vault.json"))
    if legacy_bak.exists():
        shutil.move(str(legacy_bak), str(default_dir / "vault.bak"))

    # Legacy (pre-schema) vaults were always credential vaults. Stamp the
    # schema field explicitly so peek_schema()/dispatch never has to guess.
    for filename in ("vault.json", "vault.bak"):
        path = default_dir / filename
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if "schema" not in raw:
            raw["schema"] = "credentials"
            path.write_text(json.dumps(raw, indent=4), encoding="utf-8")
        path.chmod(0o600)

    config.active_vault = "default"
    config.save()
