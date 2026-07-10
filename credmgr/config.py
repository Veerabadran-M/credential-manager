"""Application configuration.

Defaults live on the dataclass. Anything the user changes via
`credmgr config set ...` is persisted to ~/.credmgr/config.json and merged
on top of the defaults at startup.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, fields
from pathlib import Path

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
    "password_history_limit": (0, 1000),
}

@dataclass
class Configuration:
    master_dir: Path = Path.home() / ".credmgr"

    # Argon2id KDF parameters. Defaults exceed OWASP's current minimums
    # (time_cost >= 2, memory_cost >= 19 MiB, parallelism >= 1).
    argon2_time_cost: int = 3          # iterations
    argon2_memory_cost: int = 65536    # KiB
    argon2_parallelism: int = 2        # threads
    argon2_hash_len: int = 32          # bytes

    # Cipher used for envelope encryption: "aes256gcm" or "xchacha20poly1305".
    # Only takes effect for newly-created vaults (credmgr init).
    cipher: str = "aes256gcm"

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

    # ---- derived paths ----

    @property
    def vault_file(self) -> Path:
        return self.master_dir / "vault.json"

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
    def shm_dir(self) -> Path:
        return Path("/dev/shm")
    
    @property
    def mutable_parameters(self) -> list:
        return ["auth_timeout", "fuzzy_threshold", "password_length", 
                "passphrase_num_word", "clipboard_timeout", "password_max_age_days", 
                "password_history_limit"]
    
    @property
    def immutable_parameters(self) -> list:
        return ["master_dir", "argon2_time_cost", "argon2_memory_cost", 
                "argon2_parallelism", "argon2_hash_len", "cipher"]

    # ---- persistence ----

    def load(self) -> "Configuration":
        """Merge persisted overrides on top of the defaults, in place."""
        if not self.settings_file.exists():
            return self

        try:
            with self.settings_file.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Configuration file is not valid JSON: {self.settings_file}. "
                "Fix or remove it, then run credmgr again."
            ) from e
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
        if key == "cipher" and value not in ("aes256gcm", "xchacha20poly1305"):
            raise ValueError("cipher must be 'aes256gcm' or 'xchacha20poly1305'")

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
        if key not in valid_keys or key == "master_dir":
            raise KeyError(f"Unknown or read-only config key: '{key}'")

        setattr(self, key, self._parse_value(key, raw_value))

try:
    config = Configuration().load()
except ValueError as e:
    print(f"credmgr: {e}", file=sys.stderr)
    raise SystemExit(1) from e
