# credential-manager / credmgr

A CLI password manager that stores all credentials in a single, envelope-encrypted vault file on your own machine — no cloud sync, server, or telemetry.

- **Version:** 3.0.0 
- **License:** MIT
- **Requires:** Python ≥ 3.10

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [How the Vault Is Encrypted](#how-the-vault-is-encrypted)
4. [Plugin Architecture](#plugin-architecture)
5. [Backend Selection](#backend-selection)
6. [Migrating Between Backends](#migrating-between-backends)
7. [Writing a Custom Crypto Plugin](#writing-a-custom-crypto-plugin)
8. [On-Disk Layout](#on-disk-layout)
9. [Installation](#installation)
10. [Getting Started](#getting-started)
11. [Command Reference](#command-reference)
12. [Session Caching](#session-caching)
13. [Password Generation & Audit](#password-generation--audit)
14. [Configuration](#configuration)
15. [Project Structure](#project-structure)
16. [Limitations & Threat Model](#limitations--threat-model)
17. [Testing](#testing)
18. [Design Rationale](#design-rationale)

---

## Overview

`credmgr` keeps every service, account, password, and note in one JSON file (`~/.credmgr/vault.json`), encrypted as a single blob via **envelope encryption**. Unlock with a master password; everything else operates on decrypted data only in memory, for the duration of a command or a short cached session.

Encryption itself is performed by a **crypto backend plugin** — an interchangeable module wrapping one third-party library. The core application (vault storage, CLI, search, audit) never imports `cryptography`, `PyNaCl`, or `pycryptodome` directly; it only talks to an abstract `EncryptionBackend` interface and asks a plugin registry for whichever backend a vault says it uses. Consequences:

- Install only the crypto library your chosen backend needs.
- Adding a new library/algorithm never touches vault, CLI, or config code — just drop in a plugin file.
- A vault can be losslessly migrated from one backend to another with `credmgr migrate`.

---

## Features

| Area | Capability |
|---|---|
| **Storage** | Single encrypted vault file, versioned for safe migrations |
| **Encryption** | Pluggable backends — AES-256-GCM (`cryptography` or `pycryptodome`) and XChaCha20-Poly1305 (`PyNaCl`); keys derived via Argon2id |
| **Accounts** | Add, update (userid/password/notes), delete, list, multiple accounts per service |
| **Password history** | Every password change preserved per account |
| **Search** | Exact, substring, and fuzzy matching across services, userids, notes |
| **Generation** | Cryptographically secure random passwords or Diceware-style passphrases |
| **Clipboard** | Copy with automatic timed clearing |
| **Audit** | Detects weak, duplicate, reused, stale, and breached passwords |
| **Session cache** | Optional short-lived in-RAM key cache to avoid re-typing the master password |
| **Import/Export** | Plain-JSON import/export for migration and backups |
| **Master password rotation** | `credmgr passwd` — never re-encrypts the whole vault |
| **Backend migration** | `credmgr migrate` — re-encrypts vault contents under a new backend without ever writing plaintext to disk |
| **Configurable** | Argon2 cost, backend choice, timeouts, audit thresholds |

---

## How the Vault Is Encrypted

Envelope encryption separates "the key that protects your data" from "the key derived from your password" — the same pattern used by most cloud KMS designs:

```
Master Password ──Argon2id──► Key-Encryption Key (KEK)
DEK (random 256-bit) ──AEAD encrypt, AAD="credmgr-dek"──► encrypted_key (wrapped DEK)   [key: KEK]
Vault JSON (services/accounts/passwords/history) ──AEAD encrypt, AAD="credmgr-vault"──► vault ciphertext   [key: DEK]
```

1. **Key derivation (KEK).** The master password + a random 16-byte salt go through **Argon2id** (OWASP's recommended password-hashing KDF), producing a 256-bit KEK. Deliberately slow and memory-hard, to make offline brute-force expensive.
2. **DEK generation.** A random 256-bit **Data-Encryption Key** is generated once, at vault creation — this is what actually encrypts your data.
3. **Key wrapping.** The DEK is AEAD-encrypted under the KEK and stored as `encrypted_key`.
4. **Data encryption.** The entire credentials tree is serialized to JSON and AEAD-encrypted **as one blob** under the DEK, stored as `vault`.
5. **Unlocking.** Re-derive the KEK, unwrap the DEK, decrypt the vault blob. Tampering or a wrong password fails AEAD authentication — `credmgr` reports "Authentication failed" rather than returning corrupted plaintext.

**Why envelope encryption:** changing your master password (`credmgr passwd`) only re-derives the KEK and re-wraps the small, fixed-size DEK. Vault contents are never re-encrypted, so rotation is instant regardless of vault size.

### AEAD and bundled backends

Every backend is an **AEAD** (Authenticated Encryption with Associated Data) construction — it detects any tampering on decrypt rather than silently returning garbage. Every `EncryptionBackend.decrypt()` raises the same `DecryptionError` on auth failure, regardless of which library raised its own internally.

| Backend name | Algorithm | Key/nonce | Library | Notes |
|---|---|---|---|---|
| `xchacha-pynacl` **(default)** | XChaCha20-Poly1305 | 256/192-bit | `PyNaCl` | Extended nonce further reduces nonce-reuse risk |
| `aesgcm-pycryptodome` | AES-256-GCM | 256/96-bit | `pycryptodome` | Same algorithm; pure-C dependency, no Rust toolchain needed |
| `aesgcm-cryptography` | AES-256-GCM | 256/96-bit | `cryptography` | Hardware-accelerated (AES-NI) on most CPUs |

Each operation also binds a fixed AAD string (`"credmgr-dek"` or `"credmgr-vault"`), domain-separating the two contexts so a wrapped-DEK ciphertext can never be replayed as vault ciphertext. Handled once, identically, in `crypto/envelope.py`.

### Argon2id parameters

Defaults (configurable at `init`, fixed for the life of a vault): `time_cost=3`, `memory_cost=65536 KiB`, `parallelism=2`, `hash_len=32 bytes` — all above OWASP's minimums (≥2, ≥19 MiB, ≥1). Higher values trade slower unlocking for more brute-force resistance.

> Argon2 parameters are fixed once a vault exists; to change them, create a new vault and `import` your exported data. The **backend** can be changed in place instead, via `credmgr migrate`.

---

## Plugin Architecture

The core never imports a crypto library directly. `credmgr/crypto/` defines the interface; each algorithm implementation is a self-contained plugin file:

```
credmgr/crypto/
    base.py         EncryptionBackend — abstract interface every plugin implements
    registry.py     Discovery, lookup, selection logic
    exceptions.py   Shared exception types (CryptoError and subclasses)
    envelope.py     KDF + DEK wrap/unwrap, built only on the interface above
    plugins/
        aesgcm_cryptography.py     AES-256-GCM via 'cryptography'
        xchacha_pynacl.py          XChaCha20-Poly1305 via PyNaCl
        aesgcm_pycryptodome.py     AES-256-GCM via pycryptodome
```

**Interface:**

```python
class EncryptionBackend(ABC):
    name: str          # stable identifier stored in vault metadata, e.g. "aesgcm-cryptography"
    algorithm: str     # human-readable label, e.g. "AES-256-GCM"
    key_size: int
    nonce_size: int
    pip_extra: str     # pyproject.toml extra that installs this backend's dependency

    def is_available(cls) -> bool: ...
    def generate_key(cls) -> bytes: ...
    def encrypt(key, plaintext, aad=None) -> bytes: ...   # returns one opaque blob (nonce+ciphertext)
    def decrypt(key, ciphertext, aad=None) -> bytes: ...  # consumes that same blob
```

Callers never handle the nonce separately — one less thing for `vault.py` to get wrong.

**Discovery (`registry.py`)** walks `crypto/plugins/` via `pkgutil.iter_modules` and registers any `EncryptionBackend` subclass found. Two properties make this safe:

1. **Importing a plugin never fails**, even without its dependency — each plugin defers `import cryptography`/`nacl`/`Crypto` to inside `is_available()` and `encrypt`/`decrypt`, never at module scope. A plugin whose import genuinely raises (e.g. a syntax error) is simply skipped by the discovery loop's `try/except` — one broken plugin can't take down the app.
2. **Registered-but-unavailable is distinguishable from unregistered.** `all_backends()` lists every plugin found on disk; `available_backends()` filters to those whose `is_available()` is currently `True`. This lets `credmgr init`'s menu only offer usable backends, while `get_backend()` can still tell you exactly which `pip install` fixes an unavailable one.

Adding `aesgcm-pycryptodome` required one new file and no edits elsewhere — the Open/Closed Principle in practice.

---

## Backend Selection

Three places need "which backend?", each a different scope:

| Scope | How it's chosen |
|---|---|
| A new vault (`credmgr init`) | Interactive menu from `available_backends()`, or `--backend NAME` to skip it |
| `credmgr migrate`'s target | Priority chain below |
| An existing vault, every other command | Always read from the vault's own `"backend"` metadata — never configurable |

Priority chain for the first two:

```
CLI option (--backend) > environment (CREDMGR_BACKEND) > config file (backend) > built-in default
```

- **Built-in default**: first available backend in preference order (`xchacha-pynacl`, `aesgcm-pycryptodome`, `aesgcm-cryptography`).
- Set via config with `credmgr config set backend xchacha-pynacl` (persisted to `~/.credmgr/config.json`).

This logic lives in one place, `crypto/registry.resolve_backend()`, so no command re-implements the priority order itself.

---

## Migrating Between Backends

```bash
credmgr migrate --backend xchacha-pynacl
```

1. Prompts for the **master password** (never uses the cached session key — this is security-sensitive).
2. Derives the KEK, decrypts the current DEK and vault contents with the *current* backend, in memory.
3. Generates a **fresh DEK**, re-encrypts vault contents under the **new** backend.
4. Re-wraps the fresh DEK under the same KEK (master password unchanged) using the new backend.
5. Atomically writes the vault (same crash-safe temp-file + `.bak` procedure as any write).
6. Invalidates any cached session key, since the DEK changed.

**No plaintext ever touches disk** — decrypted contents exist only as an in-memory `bytes` object between steps 2 and 5.

Migrating to a backend whose dependency isn't installed fails fast, *before* prompting for a password:

```
$ credmgr migrate --backend xchacha-pynacl
The credential database uses backend 'xchacha-pynacl', but its dependency is not installed.
Install it using:
  pip install credmgr[pynacl]
```

---

## Writing a Custom Crypto Plugin

A new backend needs exactly one new file in `credmgr/crypto/plugins/` — nothing else changes.

```python
# credmgr/crypto/plugins/my_backend.py
from __future__ import annotations
import os
from ..base import EncryptionBackend
from ..exceptions import BackendUnavailableError, DecryptionError, EncryptionError

class MyBackend(EncryptionBackend):
    name = "my-backend"          # stable ID; never rename once a vault uses it
    algorithm = "My-Algorithm"
    key_size = 32
    nonce_size = 12
    pip_extra = "my-backend"     # must match an extra in pyproject.toml

    @classmethod
    def is_available(cls) -> bool:
        try:
            import my_crypto_library  # noqa: F401 -- lazy import, never at module scope
        except ImportError:
            return False
        return True

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.key_size)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        try:
            import my_crypto_library as lib
        except ImportError as e:
            raise BackendUnavailableError("...pip install credmgr[my-backend]...") from e
        nonce = os.urandom(MyBackend.nonce_size)
        try:
            ciphertext = lib.encrypt(key, nonce, plaintext, aad)
        except Exception as e:
            raise EncryptionError(str(e)) from e
        return nonce + ciphertext  # blob layout is up to you

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        try:
            import my_crypto_library as lib
        except ImportError as e:
            raise BackendUnavailableError("...pip install credmgr[my-backend]...") from e
        nonce, actual_ct = ciphertext[:MyBackend.nonce_size], ciphertext[MyBackend.nonce_size:]
        try:
            return lib.decrypt(key, nonce, actual_ct, aad)
        except Exception as e:
            raise DecryptionError("Decryption failed (authentication error).") from e
```

Checklist:

- [ ] `name` is unique and, once released, never changes (existing vaults reference it verbatim).
- [ ] All library imports are inside methods, never at module scope.
- [ ] `encrypt`/`decrypt` translate library-specific exceptions into `EncryptionError`/`DecryptionError`.
- [ ] Add the extra to `pyproject.toml`'s `[project.optional-dependencies]`.
- [ ] Add a test module mirroring `tests/test_backend_contract.py` (picked up automatically via `available_backends()`).

No changes needed to `registry.py`, `vault.py`, `cli.py`, or `config.py` — `pkgutil`-based discovery finds the new file on next run.

---

## On-Disk Layout

```json
{
    "version": 2,
    "kdf": {
        "algorithm": "argon2id",
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 2,
        "hash_len": 32,
        "salt": "<base64>"
    },
    "backend": "xchacha-pynacl",
    "algorithm": "XChaCha20-Poly1305",
    "encrypted_key": { "ciphertext": "<base64>" },
    "vault": { "ciphertext": "<base64>" }
}
```

- `version` — schema version, for automatic forward migration.
- `kdf` — Argon2id parameters and salt used for this vault.
- `backend` — registered plugin name that encrypted this vault; looked up via the registry on every unlock.
- `algorithm` — human-readable label for `backend`; purely informational, never used to select the plugin.
- `encrypted_key` — the DEK, wrapped under the KEK. `ciphertext` is a single base64 blob (nonce + ciphertext concatenated).
- `vault` — the entire credentials tree, encrypted under the DEK, same layout.

Vaults from before the plugin architecture (`"version": 1`, a `"cipher"` field, separate `"nonce"`/`"ciphertext"` pairs) are transparently upgraded to this layout on next unlock (`vault._migrate_v1_to_v2()`) — a pure structural transform (concatenating existing bytes, mapping the old cipher name to a backend name) that needs no decryption and can't fail authentication.

Writes are crash-safe: write to a temp file, `fsync`, copy the previous vault to `.bak`, then atomically replace. Vault files are `0600`; `~/.credmgr/` is `0700`.

---

## Installation

**Install as a package:**
```bash
git clone https://github.com/Veerabadran-M/credential-manager.git
cd credential-manager
pip install .
```

**Or run without installing:**
```bash
pip install -r requirements.txt
python credmgr.py <command>        # or: python -m credmgr <command>
```

**Crypto backend (required — pick at least one):**
```bash
pip install credmgr[pynacl]           # XChaCha20-Poly1305 (recommended default)
pip install credmgr[pycryptodome]     # AES-256-GCM via pycryptodome
pip install credmgr[cryptography]     # AES-256-GCM via cryptography
pip install credmgr[all]              # every bundled backend
```
Equivalently: `pip install PyNaCl>=1.5` / `pycryptodome>=3.20` / `cryptography>=42`.

`credmgr`'s core has no crypto dependency at all. `init`'s menu, `config show`, and `migrate` only ever offer installed backends; requesting an uninstalled one produces the actionable `pip install credmgr[...]` message shown above, never a raw `ImportError`.

| Package | Purpose | Required? |
|---|---|---|
| `argon2-cffi` | Argon2id key derivation | Always |
| `rich` | Terminal formatting/tables | Always |
| `pyperclip` | Clipboard copy support | Always |
| `cryptography` | `aesgcm-cryptography` backend | Optional (`credmgr[cryptography]`) |
| `PyNaCl` | `xchacha-pynacl` backend | Optional (`credmgr[pynacl]`) |
| `pycryptodome` | `aesgcm-pycryptodome` backend | Optional (`credmgr[pycryptodome]`) |

---

## Getting Started

```bash
credmgr init                        # choose backend, Argon2 params, set master password
credmgr add netflix alice           # add a credential
credmgr add netflix alice --generate  # ...or with a generated password
credmgr get netflix alice           # retrieve it
credmgr copy netflix alice           # copy the password to clipboard instead
credmgr search netflix               # search across everything
credmgr audit                        # check password health
```

`init` also offers to download three optional datasets (word list, common-passwords list, breach-hash database) into `~/.credmgr/data/` — see [Password Generation & Audit](#password-generation--audit). Requires internet; skip with `--skip-data-fetch` or run later with `credmgr fetch-data`. `credmgr` stays fully functional offline either way, falling back to small built-in defaults.

---

## Command Reference

| Command | Description |
|---|---|
| `credmgr init [--skip-data-fetch] [--backend NAME]` | Initialize a new vault |
| `credmgr fetch-data` | (Re-)download the wordlist / common-passwords / sequences / breach-hash datasets |
| `credmgr list` | List all stored services and account userids |
| `credmgr get <service> [userid]` | Display credentials in a table |
| `credmgr search <query>` | Fuzzy search across services, userids, notes |
| `credmgr copy <service> [userid]` | Copy a password to the clipboard (auto-clears) |
| `credmgr add <service> <userid> [--generate] [--passphrase] [--notes "..."]` | Add an account |
| `credmgr update <service> <userid> userid <new_userid>` | Rename an account's userid |
| `credmgr update <service> <userid> password [--generate] [--passphrase]` | Change password (old one kept in history) |
| `credmgr update <service> <userid> notes "<text>"` | Update notes |
| `credmgr history <service> <userid>` | Show password history for an account |
| `credmgr delete <service> [userid]` | Delete an account, or a whole service if no userid given |
| `credmgr generate [--passphrase] [--length N] [--words N]` | Generate a password/passphrase without storing it |
| `credmgr audit` | Run the password health audit |
| `credmgr passwd` | Change the master password (re-wraps the DEK only) |
| `credmgr migrate [--backend NAME]` | Re-encrypt the vault under a different backend |
| `credmgr export` | Print the entire vault as plaintext JSON (always re-prompts) |
| `credmgr import <filepath>` | Import accounts from plaintext JSON (skips duplicates/invalid entries) |
| `credmgr config show / set <key> <value> / reset` | View or change configuration |

Service/userid lookups (`get`, `copy`, `update`, `delete`, `history`) use progressively looser matching: exact → case-insensitive substring → fuzzy (`difflib`, configurable threshold). Ambiguous matches list candidates instead of guessing.

Run `credmgr --help` or `credmgr <command> --help` for full usage.

---

## Session Caching

Typing the master password on every command would be tedious. `credmgr` caches the **DEK only** (never the master password or KEK) for up to `auth_timeout` seconds (default 300s), in `/dev/shm` (RAM-backed tmpfs) when available, otherwise a temp-dir fallback.

- Scoped to the current terminal session ID — unusable from unrelated sessions.
- A background watcher deletes the cached key on timeout or session end.
- `credmgr export` always forces a fresh prompt, bypassing the cache.
- RAM-backed, so it never survives a reboot or touches persistent storage.

Set `auth_timeout` to `0` to disable caching entirely.

---

## Password Generation & Audit

**Generation** (`--generate`/`--passphrase` on `add`/`update`, or standalone `credmgr generate`):
- **Random password** (default): via `secrets`, guaranteed at least one lowercase, uppercase, digit, and punctuation character. Length configurable (`password_length`, default 20, range 8–256).
- **Passphrase** (`--passphrase`): Diceware-style, hyphen-joined random words (e.g. `avocado-cluster-ember-falcon-tulip`). Word count configurable (`passphrase_num_word`, default 5, range 3–12). Uses a large fetched word list (Google's 10,000 common words, filtered) or a small bundled fallback if unavailable.

**Audit** (`credmgr audit`):

| Check | Description |
|---|---|
| Duplicates | Same password reused across accounts |
| Weak | Length <12 (<8 = "too short"), common-password match, <3 of {lower/upper/digit/punct} classes, 3+ repeated chars, or a keyboard/numeric sequence |
| Reused | Current password matches one of the account's own history entries |
| Old | Not changed within `password_max_age_days` (default 90) |
| Breached | SHA-1 hash matches a local, offline breach-hash database |

The common-passwords list, sequence patterns, and breach-hash database are the same optional datasets from `init`/`fetch-data`; each check degrades to a small built-in fallback if absent. Breach checking is entirely offline — nothing is sent to any third-party API.

---

## Configuration

`~/.credmgr/config.json`, layered on built-in defaults, edited via `credmgr config`.

| Key | Default | Mutable after vault creation? | Description |
|---|---|---|---|
| `backend` | `xchacha-pynacl` | ❌ (use `credmgr migrate`) | Crypto backend; overridable per-invocation via `--backend` or `CREDMGR_BACKEND` |
| `argon2_time_cost` | `3` | ❌ | Argon2id iterations |
| `argon2_memory_cost` | `65536` (KiB) | ❌ | Argon2id memory usage |
| `argon2_parallelism` | `2` | ❌ | Argon2id threads |
| `argon2_hash_len` | `32` | ❌ | Derived key length (bytes) |
| `auth_timeout` | `300` (sec) | ✅ | Session DEK cache lifetime; `0` disables |
| `fuzzy_threshold` | `0.75` | ✅ | Minimum similarity (0–1) for fuzzy matches |
| `password_length` | `20` | ✅ | Default generated password length |
| `passphrase_num_word` | `5` | ✅ | Default passphrase word count |
| `clipboard_timeout` | `30` (sec) | ✅ | Seconds before clipboard auto-clears |
| `password_max_age_days` | `90` | ✅ | "Old password" audit threshold |
| `password_history_limit` | `10` | ✅ | Max past passwords retained per account |

Fields marked ❌ need a fresh vault + `import` to change — except `backend`, which `credmgr migrate` changes in place.

```bash
credmgr config show
credmgr config set password_max_age_days 60
credmgr config reset
```

---

## Project Structure

```
credential-manager/
├── credmgr.py                # Standalone entry point (run without installing)
├── pyproject.toml            # Packaging metadata, dependencies, console-script entry point
├── requirements.txt          # Plain pip requirements
├── tests/                    # pytest suite (backend contract, registry, vault/migration)
└── credmgr/
    ├── __init__.py           # Package docstring / version
    ├── __main__.py           # `python -m credmgr` entry point
    ├── cli.py                # Argument parsing and command dispatch
    ├── models.py              # Account / Credentials / PasswordHistoryEntry
    ├── config.py              # Runtime configuration
    ├── vault.py                # Versioned, encrypted vault file I/O + migrations
    ├── auth.py                # Master-password auth + session DEK caching
    ├── crypto/
    │   ├── base.py            # EncryptionBackend interface
    │   ├── registry.py         # Plugin discovery, lookup, CLI/env/config selection
    │   ├── exceptions.py       # CryptoError and subclasses
    │   ├── envelope.py         # KDF, DEK wrap/unwrap
    │   └── plugins/
    │       ├── aesgcm_cryptography.py
    │       ├── xchacha_pynacl.py
    │       └── aesgcm_pycryptodome.py
    ├── generator.py           # Password / passphrase generation
    ├── wordlist.py             # Bundled fallback word list
    ├── datasources.py          # Downloads optional datasets
    ├── search.py               # Fuzzy + global search
    ├── audit.py                # Password health audit
    ├── clipboard.py            # Clipboard copy with auto-clear
    └── ui.py                   # Terminal rendering (rich)
```

**Extension points:** new crypto backend → file in `crypto/plugins/` (see above); new vault version → bump `vault.CURRENT_VERSION` + entry in `vault.MIGRATIONS`; new audit check → `find_*` function in `audit.py`, wired into `run_audit()`; new CLI command → `cmd_*` function + subparser in `cli.py`.

---

## Limitations & Threat Model

- **Single-user, single-machine.** No sync, sharing, or team support. Moving vaults is manual (copy the file, or `export`/`import`).
- **No 2FA/MFA storage** — passwords and notes only.
- **Master password is the single point of failure.** No backdoor, recovery key, or reset mechanism by design.
- **Metadata isn't separately hidden**, but it does sit inside the same encrypted blob as passwords — no plaintext metadata in the file itself. Shell history and terminal scrollback can still leak service/userid names, though.
- **`export` produces plaintext.** Treat exported output like your master password.
- **Local breach database only** — a curated ~100k-password subset, not the full HIBP corpus, and no online k-anonymity lookup.
- **Depends on OS-level protections** (file permissions, `/dev/shm`) against other unprivileged users — not against a compromised account, root access, or malware running as you.
- **Clipboard exposure window** until `clipboard_timeout` elapses (default 30s).
- **POSIX-only** (`os.fork()`-based session cleaner and clipboard auto-clear) — requires Linux/macOS; no native Windows (WSL should work).
- **No rate limiting** on password attempts beyond Argon2id's inherent per-attempt cost.
- **Security depends on the chosen backend's library** (`cryptography`, `PyNaCl`, `pycryptodome`) — keep them updated, and use `credmgr migrate` if one is ever deprecated or found weak.

---

## Testing

| File | Covers |
|---|---|
| `test_backend_contract.py` | Every installed backend, parametrized: round-trip encrypt/decrypt (with/without AAD), tamper/wrong-key/AAD-mismatch rejection — all raising the same `DecryptionError` |
| `test_registry.py` | Discovery finds bundled plugins; unknown names raise `UnknownBackendError`; unavailable backends excluded from `available_backends()` but visible in `all_backends()`; a broken plugin module never crashes discovery; CLI/env/config/default selection priority |
| `test_vault.py` | Create/unlock/save round trips per backend; wrong password raises the same `AuthenticationError` regardless of backend; `migrate_backend()` preserves data and rejects wrong passwords without touching the on-disk vault; legacy v1 vaults upgrade transparently to v2 |

```bash
pip install pytest
pip install credmgr[all]   # tests parametrize over whichever backends are installed
pytest tests/ -v
```

Backend-parametrized tests are built from `available_backends()`, not a hardcoded list — a new plugin's tests run automatically once its file exists and its dependency is installed.

---

## Design Rationale

- **Abstract `EncryptionBackend` interface, not a `cipher: str` threaded through the app.** `vault.py`/`cli.py` depend on one interface, not literal cipher names — Dependency Inversion in practice.
- **Plugins as separate files, discovered via `pkgutil`, not a hardcoded dict.** A shared dict means every new backend is a diff to one file, with shared blast radius. Filesystem discovery makes a new backend purely additive — Open/Closed.
- **Lazy imports inside plugin methods, never at module scope.** Lets "ignore plugins whose dependencies are unavailable" be a plain `False` return from `is_available()`, not exception handling at every call site — `credmgr` never crashes on startup for a missing crypto library.
- **One shared exception hierarchy (`CryptoError` and subclasses), not each library's native exceptions.** `cryptography` raises `InvalidTag`, PyNaCl raises `nacl.exceptions.CryptoError`, pycryptodome raises `ValueError` — normalizing all of them to `DecryptionError` means `vault.py` catches exactly one thing, with one predictable message, no matter which backend is involved.
- **`BackendUnavailableError` kept distinct from `AuthenticationError`.** "Wrong password" and "missing dependency" need different fixes; conflating them (e.g. via a masquerading `ImportError`) would send users chasing the wrong one. Kept separate, `credmgr migrate` can also fail fast — before even prompting for a password — when the target backend isn't installed.
- **Backend name stored in vault metadata, resolved at unlock time.** Makes the vault self-describing: no external config needed to know how to decrypt it, and copying a vault to a machine with different installed backends fails with a clear, actionable error instead of silently trying the wrong algorithm.
- **Backend migration as a separate operation from schema/version migration.** Bumping the on-disk version is a metadata reshape needing no key material; changing the encrypting algorithm needs the master password and a full re-encryption pass. Kept as separate code paths (`_migrate()` vs. `Vault.migrate_backend()`) so each stays simple to reason about and test alone.
- **One centralized `resolve_backend()`, not ad hoc priority logic per command.** CLI > env > config > default is implemented once; every command calls the same function with its own `cli_value`/`config_value`, instead of re-deriving (and potentially drifting from) the same order independently.

---

## Disclaimer

Provided as-is. Follows established cryptographic best practices (Argon2id, AEAD ciphers) but has not undergone formal third-party security audit. Use at your own discretion, and keep independent backups of your vault file.