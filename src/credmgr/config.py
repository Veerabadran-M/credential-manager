"""Application configuration.

Defaults live on the dataclass; user overrides from `credmgr config set`
persist to ~/.credmgr/config.json and are merged on top at startup.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field, fields
from pathlib import Path

from .crypto.registry import all_backends

ARGON2_MIN_TIME_COST = 2
ARGON2_MIN_MEMORY_COST = 19 * 1024  # KiB; OWASP minimum for Argon2id.
ARGON2_MIN_PARALLELISM = 1
ARGON2_MIN_HASH_LEN = 16
ARGON2_MAX_MEMORY_COST = 1024 * 1024  # KiB; guard against accidental lockouts.
CONFIG_VALUE_LIMITS = {
    "argon2_time_cost": (ARGON2_MIN_TIME_COST, 20),
    "argon2_memory_cost": (ARGON2_MIN_MEMORY_COST, ARGON2_MAX_MEMORY_COST),
    "argon2_parallelism": (ARGON2_MIN_PARALLELISM, 16),
    "argon2_hash_len": (ARGON2_MIN_HASH_LEN, 64),
    "auth_timeout": (0, 24 * 60 * 60),
    "fuzzy_threshold": (0.0, 1.0),
    "password_length": (8, 256),
    "passphrase_num_word": (3, 12),
    "clipboard_timeout": (0, 60 * 60),
    "password_max_age_days": (1, 3650),
    "password_history_limit": (0, 1000)
}

@dataclass
class Configuration:
    master_dir: Path = Path.home() / ".credmgr"

    # Name of the vault (under <master_dir>/vaults/<name>/) that generic
    # commands operate on when no --vault override is given. Managed via
    # `credmgr vault use <name>`, not `credmgr config set`.
    active_vault: str = "default"

    # Argon2id KDF parameters. Defaults exceed OWASP's current minimums
    # (time_cost >= 2, memory_cost >= 19 MiB, parallelism >= 1).
    argon2_time_cost: int = 3          # iterations
    argon2_memory_cost: int = 65536    # KiB
    argon2_parallelism: int = 2        # threads
    argon2_hash_len: int = 32          # bytes

    # Crypto plugin backend used for envelope encryption (see credmgr/crypto/).
    backend: str = "xchacha-pynacl"

    # Session auth cache lifetime
    auth_timeout: int = 300  # seconds

    # Fuzzy name search
    fuzzy_threshold: float = 0.75

    # Password generation
    password_length: int = 20
    passphrase_num_word: int = 5

    # Password copy-to-clipboard auto-clear
    clipboard_timeout: int = 30  # seconds

    # Password audit
    password_max_age_days: int = 90
    password_history_limit: int = 10

    # External text editor used by `add`/`update` (text schema only) when
    # invoked with no content argument. Falls back through $VISUAL/$EDITOR,
    # then a sane platform default, so it works out of the box; override
    # with `credmgr config set editor <command>`.
    editor: str = field(default_factory=lambda: os.environ.get("VISUAL") or os.environ.get("EDITOR") or ("notepad" if os.name == "nt" else "nano"))

    # ---- derived paths ----

    @property
    def vaults_dir(self) -> Path:
        """Parent directory of all named vaults (see vault_dir())."""
        return self.master_dir / "vaults"

    def vault_dir(self, name: str) -> Path:
        """Self-contained directory for the named vault: vault.json, vault.bak,
        and any future vault-specific files all live here."""
        return self.vaults_dir / name

    @property
    def vault_file(self) -> Path:
        """Convenience accessor for the *active* vault's file. Prefer
        constructing Vault(config, name=...) directly when working with a
        specific (possibly non-active) vault."""
        return self.vault_dir(self.active_vault) / "vault.json"

    @property
    def vault_bak_file(self) -> Path:
        return self.vault_file.with_suffix(".bak")

    @property
    def vault_temp_file(self) -> Path:
        return self.vault_file.with_suffix(".tmp")

    @property
    def settings_file(self) -> Path:
        return self.master_dir / "config.json"

    @property
    def index_file(self) -> Path:
        """Cross-vault metadata search index for `credmgr global` (see
        globalindex.py). Contains only searchable identifiers -- vault
        names, schema names, and the fields each schema's IndexEntry
        exposes -- never passwords, encrypted blobs, decrypted secrets,
        or master keys."""
        return self.master_dir / "index.json"

    @property
    def data_dir(self) -> Path:
        """Local cache of fetched security datasets (wordlist, common
        passwords, keyboard-sequence patterns, breached-password hashes)."""
        return self.master_dir / "data"
    
    @property
    def breach_db_file(self) -> Path:
        return self.data_dir / "breached_hash.txt"

    @property
    def wordlist_file(self) -> Path:
        return self.data_dir / "wordlist.txt"

    @property
    def common_passwords_file(self) -> Path:
        return self.data_dir / "common_passwords.txt"

    @property
    def sequences_file(self) -> Path:
        return self.data_dir / "sequences.txt"

    @property
    def session_cache_dir(self) -> Path:
        """Directory used to cache the session DEK.

        Prefers /dev/shm (RAM-backed tmpfs) when available, as on most
        Linux systems. Falls back to a dedicated subdirectory under the
        platform temp directory on systems where /dev/shm doesn't exist
        (e.g. Android/Termux).
        """
        shm_path = Path("/dev/shm")
        if shm_path.is_dir():
            path = shm_path
        else:
            path = Path(tempfile.gettempdir()) / "credmgr"
            path.mkdir(mode=0o700, parents=True, exist_ok=True)

        return path
    
    @property
    def mutable_parameters(self) -> list:
        return ["auth_timeout", "fuzzy_threshold", "password_length", 
                "passphrase_num_word", "clipboard_timeout", "password_max_age_days", 
                "password_history_limit", "editor"]
    
    @property
    def immutable_parameters(self) -> list:
        return ["master_dir", "argon2_time_cost", "argon2_memory_cost", 
                "argon2_parallelism", "argon2_hash_len", "backend"]

    @property
    def hidden_parameters(self) -> list:
        """Fields excluded from generic `config set`/`config show` mutation
        rules because they have their own dedicated commands."""
        return ["active_vault"]

    # ---- persistence ----

    def load(self) -> "Configuration":
        """Merge persisted overrides on top of the defaults, in place."""
        if not self.settings_file.exists():
            return self

        try:
            with self.settings_file.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Configuration file is not valid JSON: {self.settings_file}. Fix or remove it, then run credmgr again.") from e
        except OSError as e:
            raise ValueError(f"Unable to read configuration file: {self.settings_file}") from e

        if not isinstance(raw, dict):
            raise ValueError(f"Configuration file must contain a JSON object: {self.settings_file}")

        try:
            self._apply_raw_values(raw)
        except (TypeError, ValueError) as e:
            raise ValueError(f"Invalid configuration in {self.settings_file}: {e}") from e

        return self

    def _apply_raw_values(self, raw: dict) -> None:
        for f_ in fields(self):
            if f_.name == "master_dir" or f_.name not in raw:
                continue
            setattr(self, f_.name, self._parse_value(f_.name, raw[f_.name]))

    def _parse_value(self, key: str, raw_value):
        current = getattr(self, key)

        if isinstance(current, bool):
            if isinstance(raw_value, bool):
                parsed = raw_value
            elif isinstance(raw_value, str):
                value = raw_value.strip().lower()
                if value in ("1", "true", "yes", "on"):
                    parsed = True
                elif value in ("0", "false", "no", "off"):
                    parsed = False
                else:
                    raise ValueError(f"{key} must be a boolean value")
            else:
                raise ValueError(f"{key} must be a boolean value")
        elif isinstance(current, int):
            if isinstance(raw_value, bool):
                raise ValueError(f"{key} must be an integer")
            parsed = int(raw_value)
        elif isinstance(current, float):
            if isinstance(raw_value, bool):
                raise ValueError(f"{key} must be a number")
            parsed = float(raw_value)
        elif isinstance(current, Path):
            parsed = Path(raw_value).expanduser()
        else:
            parsed = str(raw_value)

        self._validate_value(key, parsed)
        return parsed

    def _validate_value(self, key: str, value) -> None:
        if key == "backend":
            known = all_backends()
            if known and value not in known:
                raise ValueError(f"backend must be one of: {', '.join(sorted(known))}")

        limits = CONFIG_VALUE_LIMITS.get(key)
        if limits is None:
            return

        min_value, max_value = limits
        if value < min_value or value > max_value:
            raise ValueError(f"{key} must be between {min_value} and {max_value}")

    def _secure_directory(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except OSError:
            pass

    def save(self) -> None:
        self._secure_directory(self.master_dir)

        data = {}
        for f_ in fields(self):
            if f_.name == "master_dir":
                continue
            value = getattr(self, f_.name)
            data[f_.name] = str(value) if isinstance(value, Path) else value

        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self.settings_file, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        self.settings_file.chmod(0o600)

    def as_dict(self) -> dict:
        data = {}
        for f_ in fields(self):
            value = getattr(self, f_.name)
            data[f_.name] = str(value) if isinstance(value, Path) else value
        return data

    def set_value(self, key: str, raw_value: str) -> None:
        """Parse `raw_value` to match the existing field's type and set it."""
        valid_keys = {f_.name for f_ in fields(self)}
        if key not in valid_keys or key == "master_dir" or key in self.hidden_parameters:
            raise KeyError(f"Unknown or read-only config key: '{key}'")

        setattr(self, key, self._parse_value(key, raw_value))

try:
    config = Configuration().load()
except ValueError as e:
    print(f"credmgr: {e}", file=sys.stderr)
    raise SystemExit(1) from e