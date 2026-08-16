"""Master-password authentication and short-lived session caching.

Security: only the DEK -- never the master password or KEK -- is cached,
in the session cache directory (RAM-backed /dev/shm when available) for
config.auth_timeout, scoped to the current terminal session. This avoids
re-running Argon2id on every command while keeping the cached secret out
of persistent storage.

This module is core application code: it never prompts for input and
never prints. It only ever *unwraps* a vault given a password the
caller already has in hand (see credmgr/core/manager.py for the "ask
the user, then retry" orchestration frontends drive).
"""

from __future__ import annotations

import json
import os
import time

from .config import config as _default_config
from .vault import AuthenticationError, Vault

def get_session_id() -> int:
    return os.getsid(0)

def session_cache_paths(config=None, vault_name: str | None = None):
    # Scoped by vault name too: each vault has its own DEK, so a cached
    # key from one vault must never be reused for another. Defaults to
    # the active vault, but an explicit name lets callers (e.g. `list-all`,
    # which walks every vault) cache/reuse a DEK for a non-active vault too.
    config = config or _default_config
    name = vault_name if vault_name is not None else config.active_vault
    key_path = config.session_cache_dir / f".credmgr_{get_session_id()}_{name}"
    meta_path = key_path.parent / f"{key_path.name}.meta"
    return key_path, meta_path

def delete_cache(cache_files) -> None:
    for file in cache_files:
        try:
            file.unlink()
        except FileNotFoundError:
            pass

def cache_cleaner(key_file, meta_file, sid, created_at, auth_timeout) -> None:
    cache_files = (key_file, meta_file)
    while True:
        now = int(time.time())

        if now - created_at >= auth_timeout:
            delete_cache(cache_files)
            return

        try:
            if os.getsid(sid) != sid:
                delete_cache(cache_files)
                return
        except ProcessLookupError:
            delete_cache(cache_files)
            return

        time.sleep(10)

def deploy_cache_cleaner(key_file, meta_file, sid, created_time, auth_timeout) -> None:
    pid = os.fork()
    if pid == 0:  # child process
        try:
            cache_cleaner(key_file, meta_file, sid, created_time, auth_timeout)
        finally:
            os._exit(0)

def load_cached_dek(config=None, vault_name: str | None = None):
    config = config or _default_config
    key_path, meta_path = session_cache_paths(config, vault_name)
    if not key_path.exists() or not meta_path.exists():
        return None

    try:
        with meta_path.open("r") as f:
            meta = json.load(f)
        if meta["session"] == get_session_id() and time.time() - meta["timestamp"] < config.auth_timeout:
            return key_path.read_bytes()
    except Exception:
        pass

    return None

def cache_session(dek: bytes, config=None, vault_name: str | None = None) -> None:
    config = config or _default_config
    key_path, meta_path = session_cache_paths(config, vault_name)

    key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(key_path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(dek)
    key_path.chmod(0o600)

    created_time = int(time.time())
    sid = get_session_id()

    fd = os.open(meta_path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"timestamp": created_time, "session": sid}, f)
    meta_path.chmod(0o600)

    deploy_cache_cleaner(key_path, meta_path, sid, created_time, config.auth_timeout)

def try_cached_session(config=None, vault_name: str | None = None):
    """Return (dek, document, vault) from a valid cached session key, or
    None if there isn't one (missing, expired, or the vault no longer
    unlocks with it). Never prompts, never raises for a plain cache miss
    -- callers fall back to `authenticate()` with a password they've
    obtained some other way."""
    config = config or _default_config
    cached_dek = load_cached_dek(config, vault_name)
    if cached_dek is None:
        return None

    vault = Vault(config, name=vault_name)
    try:
        document = vault.unlock_with_dek(cached_dek)
    except AuthenticationError:
        return None  # stale/invalid cache entry -- caller falls through to a fresh unlock
    return cached_dek, document, vault

def authenticate(password: str, config=None, vault_name: str | None = None, remember: bool = True):
    """Unlock a vault with an already-known master password. Returns
    (dek, document, vault); raises AuthenticationError or
    BackendUnavailableError on failure. `vault.schema_name` tells the
    caller which schema parsed `document` -- see credmgr/schemas/.

    Never prompts for the password itself -- that's a frontend's job
    (see credmgr/core/manager.py). Caches the resulting session key
    unless `remember` is False (used for commands like `export` that
    intentionally always re-authenticate)."""
    config = config or _default_config
    vault = Vault(config, name=vault_name)
    dek, document = vault.unlock(password)

    if remember:
        cache_session(dek, config, vault_name)

    return dek, document, vault
