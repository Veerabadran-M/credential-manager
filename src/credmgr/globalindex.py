"""Cross-vault metadata search index, powering `credmgr global <query>`.

The index (`<master_dir>/index.json`, see `config.index_file`) is a
plain-JSON search catalogue: for every vault, its schema name and the
list of `IndexEntry` values (see `credmgr/schemas/base.py`) its schema
produced from the last document that vault saved. It contains only
searchable identifiers -- never passwords, encrypted blobs, decrypted
secrets, or master keys -- so it's safe to read without unlocking
anything.

Freshness model: every mutating CLI command that saves a vault already
has that vault's decrypted document in hand, so it calls `update_vault()`
right after `Vault.save()` -- the index is derived, not maintained by
hand. `vault create`/`vault delete` call `update_vault()`/`remove_vault()`
too. Nothing needs to "rebuild the whole index" during normal use.

For the case where the index doesn't reflect reality anyway (a fresh
install, a manually deleted/edited index.json, a vault touched by
another tool or an older credmgr build, ...), `stale_vault_names()`
compares each vault's recorded mtime/schema against what's actually on
disk -- no decryption needed for that check -- so the CLI layer knows
exactly which (if any) vaults must be unlocked and re-indexed before a
search, instead of unlocking all of them on every run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

INDEX_VERSION = 1

def _empty_index() -> dict:
    return {"version": INDEX_VERSION, "vaults": {}}

def _read_index(config) -> dict:
    """Return the on-disk index, or a fresh empty skeleton if it's
    missing, corrupt, or from an incompatible future version. Never
    raises -- a bad index is just treated as "everything is stale"."""
    path = config.index_file
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return _empty_index()

    if not isinstance(data, dict) or not isinstance(data.get("vaults"), dict):
        return _empty_index()
    if data.get("version") != INDEX_VERSION:
        return _empty_index()

    return data

def _write_index(config, data: dict) -> None:
    """Atomic write, same pattern as vault.py's _write_raw: write to a
    temp file, fsync, then rename over the target."""
    path = config.index_file
    config.master_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        config.master_dir.chmod(0o700)
    except OSError:
        pass

    tmp = path.with_suffix(".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
        f.flush()
        os.fsync(f.fileno())
    tmp.chmod(0o600)
    tmp.replace(path)
    path.chmod(0o600)

def _entry_to_raw(entry) -> dict:
    return {
        "fields": dict(entry.fields),
        "summary": [[label, value] for label, value in entry.summary],
        "args": list(entry.args),
    }

def _vault_mtime(config, vault_name: str):
    vault_file = config.vault_dir(vault_name) / "vault.json"
    try:
        return vault_file.stat().st_mtime
    except OSError:
        return None

def update_vault(config, vault_name: str, schema_name: str, document: Any) -> None:
    """Recompute and persist the index entries for one vault from an
    already-decrypted in-memory document. Call this right after any
    command saves that vault (add/update/delete/import/vault create/...)
    so the index never drifts out of sync during normal operation.

    Never raises: a schema that doesn't support indexing (or a plugin
    that errors while doing so) just contributes zero entries for that
    vault rather than breaking the mutating command that triggered this.
    """
    from .schemas import get_schema  # local import: avoids a circular import at load time

    try:
        schema = get_schema(schema_name)
        raw_entries = [_entry_to_raw(e) for e in schema.index_entries(document)]
    except Exception:
        raw_entries = []

    data = _read_index(config)
    data["vaults"][vault_name] = {
        "schema": schema_name,
        "mtime": _vault_mtime(config, vault_name),
        "entries": raw_entries,
    }
    _write_index(config, data)

def remove_vault(config, vault_name: str) -> None:
    """Drop one vault's entries from the index (e.g. after `vault delete`)."""
    data = _read_index(config)
    if data["vaults"].pop(vault_name, None) is not None:
        _write_index(config, data)

def prune_removed_vaults(config, known_names: list) -> None:
    """Drop index entries for any vault no longer present on disk --
    belt-and-braces cleanup in case a vault directory was removed
    outside of `credmgr vault delete` (manually, or by an older build)."""
    data = _read_index(config)
    stale_keys = [name for name in data["vaults"] if name not in known_names]
    if not stale_keys:
        return
    for name in stale_keys:
        del data["vaults"][name]
    _write_index(config, data)

def stale_vault_names(config, known_names: list) -> list:
    """Names (subset of `known_names`) that need re-indexing before a
    `global` search can trust the index: missing from the index
    entirely, their vault.json has changed since it was last indexed
    (mtime mismatch), or their recorded schema no longer matches what's
    on disk (e.g. hand-edited vault.json). Purely file-metadata checks
    -- no vault is unlocked here."""
    from . import vaultmgr  # local import: avoids a circular import at load time

    data = _read_index(config)
    stale = []
    for name in known_names:
        entry = data["vaults"].get(name)
        if entry is None:
            stale.append(name)
            continue

        mtime = _vault_mtime(config, name)
        if mtime is None or entry.get("mtime") != mtime:
            stale.append(name)
            continue

        if entry.get("schema") != vaultmgr.peek_schema(config, name):
            stale.append(name)

    return stale

def search(config, query: str) -> list:
    """Case-insensitive, partial-match search across every indexed
    field of every vault currently in the index. Returns a list of
    {"vault", "schema", "summary", "args"} dicts, in vault-name order.
    Callers should make sure the index is fresh first -- see
    `stale_vault_names()` -- but a stale index degrades to stale
    *results*, never to leaked secrets, since it never contains any."""
    data = _read_index(config)
    q = query.strip().lower()

    results = []
    for vault_name, vault_data in sorted(data["vaults"].items()):
        schema_name = vault_data.get("schema", "?")
        for entry in vault_data.get("entries", []):
            fields = entry.get("fields", {})
            if any(q in str(value).lower() for value in fields.values()):
                results.append({
                    "vault": vault_name,
                    "schema": schema_name,
                    "summary": [tuple(pair) for pair in entry.get("summary", [])],
                    "args": list(entry.get("args", [])),
                })

    return results
