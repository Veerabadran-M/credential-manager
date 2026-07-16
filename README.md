# credential-manager / credmgr

`credmgr` is a command-line password manager that stores all of your credentials in a single, envelope-encrypted vault file on your own machine. There is no cloud sync, no server, and no telemetry — the vault never leaves your disk unless you explicitly export it.

- **Version:** 2.0.0
- **License:** MIT
- **Requires:** Python ≥ 3.10

---

## Table of Contents

1. [Overview](#overview)
2. [Feature Summary](#feature-summary)
3. [How the Vault Is Encrypted](#how-the-vault-is-encrypted)
4. [On-Disk Layout](#on-disk-layout)
5. [Installation](#installation)
6. [Getting Started](#getting-started)
7. [Command Reference](#command-reference)
8. [Session Caching (Auth Timeout)](#session-caching-auth-timeout)
9. [Password Generation](#password-generation)
10. [Password Health Audit](#password-health-audit)
11. [Configuration](#configuration)
12. [Project Structure](#project-structure)
13. [Advantages](#advantages)
14. [Limitations & Threat Model](#limitations--threat-model)
15. [Extending credmgr](#extending-credmgr)

---

## Overview

`credmgr` keeps every service, account, password, and note in one JSON file (`~/.credmgr/vault.json`) that is encrypted as a single blob using **envelope encryption**. You unlock the vault with a master password; everything else — generation, search, clipboard copy, health auditing — operates on the decrypted data only in memory, for the duration of the command (or a short cached session).

It is designed for people who want a fast, scriptable, offline password manager without trusting a third-party server with their secrets.

---

## Feature Summary

| Area | Capability |
|---|---|
| **Storage** | Single encrypted vault file, versioned for safe future migrations |
| **Encryption** | Envelope encryption with a choice of AES-256-GCM or XChaCha20-Poly1305, keys derived via Argon2id |
| **Accounts** | Add, update (userid/password/notes), delete, list, and view multiple accounts per service |
| **Password history** | Every password change is preserved in a per-account history log |
| **Search** | Exact, substring, and fuzzy matching across services, userids, and notes |
| **Generation** | Cryptographically secure random passwords or Diceware-style passphrases |
| **Clipboard** | Copy a password to the clipboard with automatic timed clearing |
| **Password audit** | Detects weak, duplicate, reused, stale, and breached passwords |
| **Session cache** | Optional short-lived in-RAM key cache so you aren't re-typing your master password on every command |
| **Import/Export** | Plain-JSON import/export for migration and backups |
| **Master password rotation** | Change your master password without re-encrypting the whole vault |
| **Configurable** | Argon2 cost parameters, cipher choice, timeouts, and audit thresholds are all tunable |

---

## How the Vault Is Encrypted

`credmgr` uses **envelope encryption**, a two-layer scheme that separates *"the key that protects your data"* from *"the key derived from your password."* This is the same general pattern used by most serious secret-management systems (e.g. cloud KMS designs).

```
                 Argon2id (slow, memory-hard KDF)
Master Password ───────────────────────────────► Key-Encryption Key (KEK)

                    AEAD encrypt (AES-256-GCM or
                    XChaCha20-Poly1305), AAD="credmgr-dek"
Data-Encryption Key ──────────────────────────────► encrypted_key (wrapped DEK)
   (DEK, random 256-bit)          KEK

                    AEAD encrypt, AAD="credmgr-vault"
Vault JSON (all services/ ───────────────────────────► vault (ciphertext blob)
 accounts/passwords/history)        DEK
```

Step by step:

1. **Key derivation (KEK).** Your master password is run through **Argon2id** (the winner of the Password Hashing Competition, and OWASP's current recommended password-hashing/KDF algorithm) together with a random 16-byte salt. This produces a 256-bit **Key-Encryption Key (KEK)**. Argon2id is deliberately slow and memory-hard, which makes offline brute-force / GPU-cracking attacks on the master password expensive.
2. **Data key generation (DEK).** A separate, random 256-bit **Data-Encryption Key (DEK)** is generated once, when the vault is created. This is the key that actually encrypts your data.
3. **Key wrapping.** The DEK is encrypted ("wrapped") using the KEK, via an AEAD cipher, and stored as `encrypted_key` in the vault file.
4. **Data encryption.** The entire credentials tree (every service, account, password, and history entry) is serialized to JSON and encrypted **as one blob** under the DEK, stored as `vault` in the vault file.
5. **Unlocking.** To open the vault, `credmgr` re-derives the KEK from your master password + stored salt/parameters, uses it to unwrap the DEK, and uses the DEK to decrypt the vault blob. Any tampering or wrong password causes AEAD authentication to fail, and `credmgr` reports "Authentication failed" rather than returning corrupted plaintext.

### Why the two-layer (envelope) design?

The key benefit is **fast, cheap master-password rotation**: changing your master password (`credmgr passwd`) only needs to re-derive the KEK and re-wrap the (small, fixed-size) DEK. The actual vault contents — which could be large — are **never re-encrypted**, so rotating your master password is instant regardless of vault size.

### Authenticated Encryption (AEAD)

Both supported ciphers are **AEAD** (Authenticated Encryption with Associated Data) constructions, meaning they provide both confidentiality *and* integrity/authenticity — any bit-flip or tampering in the ciphertext is detected and rejected on decrypt, rather than silently producing garbage plaintext.

| Cipher | Key size | Nonce size | Notes |
|---|---|---|---|
| **AES-256-GCM** (default) | 256-bit | 96-bit | Hardware-accelerated on most modern CPUs (AES-NI); no extra dependency |
| **XChaCha20-Poly1305** (optional) | 256-bit | 192-bit | Extended nonce reduces nonce-reuse risk; requires the optional `pynacl` package |

Each encryption operation also binds a fixed **Associated Data (AAD)** string — `"credmgr-dek"` when wrapping the DEK, `"credmgr-vault"` when encrypting vault contents — which cryptographically domain-separates the two encryption contexts so a wrapped-DEK ciphertext can never be replayed as vault ciphertext or vice-versa.

### Argon2id parameters

Defaults (all configurable at `init` time, fixed for the life of a vault afterward):

| Parameter | Default | Meaning |
|---|---|---|
| `time_cost` | 3 | Number of iterations |
| `memory_cost` | 65536 KiB (64 MiB) | Memory used during hashing |
| `parallelism` | 2 | Number of parallel threads |
| `hash_len` | 32 bytes | Output key length |

These defaults exceed OWASP's current minimum recommendations (time cost ≥ 2, memory ≥ 19 MiB, parallelism ≥ 1). Higher values increase resistance to brute-force attacks at the cost of slower unlocking.

> **Note:** the cipher choice and Argon2 parameters are fixed once a vault is created. To change them, create a new vault (`credmgr init` in a fresh `master_dir`) and `import` your exported data.

---

## On-Disk Layout

The vault file (`~/.credmgr/vault.json`) looks like this:

```json
{
    "version": 1,
    "kdf": {
        "algorithm": "argon2id",
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 2,
        "hash_len": 32,
        "salt": "<base64>"
    },
    "cipher": "aes256gcm",
    "encrypted_key": { "nonce": "<base64>", "ciphertext": "<base64>" },
    "vault": { "nonce": "<base64>", "ciphertext": "<base64>" }
}
```

- `version` — schema version, allowing automatic forward migration of older vault files.
- `kdf` — the exact Argon2id parameters and salt used for this vault (needed to re-derive the KEK).
- `encrypted_key` — the DEK, wrapped under the KEK.
- `vault` — the entire credentials tree, encrypted under the DEK.

Writes are crash-safe: `credmgr` writes to a temporary file, `fsync`s it, copies the previous vault to a `.bak` file, and only then atomically replaces the live vault file. All vault-related files are created with `0600` permissions (owner read/write only), and `~/.credmgr/` itself is `0700`.

---

## Installation

### Option 1 — Install as a package (recommended)

```bash
git clone https://github.com/Veerabadran-M/credential-manager.git
cd credential-manager
pip install .
```

This installs the `credmgr` command onto your `PATH` (via the `[project.scripts]` entry point).

### Option 2 — Run without installing

```bash
pip install -r requirements.txt
python credmgr.py <command>
```

or, using the package's module entry point:

```bash
python -m credmgr <command>
```

### Optional dependency: XChaCha20-Poly1305 support

The default cipher (AES-256-GCM) requires no extra packages. If you want the option to choose **XChaCha20-Poly1305** during `credmgr init`, install the optional extra:

```bash
pip install .[xchacha20]
# or
pip install pynacl>=1.5.0
```

### Dependencies

| Package | Purpose |
|---|---|
| `argon2-cffi` | Argon2id key derivation |
| `cryptography` | AES-256-GCM AEAD implementation |
| `rich` | Terminal formatting/tables |
| `pyperclip` | Clipboard copy support |
| `pynacl` *(optional)* | XChaCha20-Poly1305 AEAD implementation |

---

## Getting Started

```bash
# 1. Initialize a new vault (choose cipher, Argon2 parameters, set master password)
credmgr init

# 2. Add your first credential
credmgr add netflix alice

# 3. Or add one with a generated password
credmgr add netflix alice --generate

# 4. Retrieve it
credmgr get netflix alice

# 5. Copy the password to your clipboard instead of displaying it
credmgr copy netflix alice

# 6. Search across everything
credmgr search netflix

# 7. Check the health of your stored passwords
credmgr audit
```

During `init`, `credmgr` also offers to download three security datasets (a word list for passphrases, a common-passwords list, and a breached-password hash database) into `~/.credmgr/data/` — see [Password Generation](#password-generation) and [Password Health Audit](#password-health-audit). This step requires internet access and can be skipped with `credmgr init --skip-data-fetch`, or run later/again at any time with `credmgr fetch-data`. `credmgr` remains fully functional offline either way, falling back to small built-in defaults.

---

## Command Reference

| Command | Description |
|---|---|
| `credmgr init [--skip-data-fetch]` | Initialize a new vault: choose cipher, Argon2 parameters, set the master password |
| `credmgr fetch-data` | (Re-)download the wordlist / common-passwords / sequences / breach-hash datasets |
| `credmgr list` | List all stored services and their account userids |
| `credmgr get <service> [userid]` | Display credentials (service, userid, password, notes) in a table |
| `credmgr search <query>` | Free-text fuzzy search across services, userids, and notes |
| `credmgr copy <service> [userid]` | Copy a password to the clipboard (auto-clears after a timeout) |
| `credmgr add <service> <userid> [--generate] [--passphrase] [--notes "..."]` | Add a new account |
| `credmgr update <service> <userid> userid <new_userid>` | Rename an account's userid |
| `credmgr update <service> <userid> password [--generate] [--passphrase]` | Change an account's password (pushes old password to history) |
| `credmgr update <service> <userid> notes "<text>"` | Update an account's notes |
| `credmgr history <service> <userid>` | Show the password history for an account |
| `credmgr delete <service> [userid]` | Delete a single account, or an entire service if no userid is given |
| `credmgr generate [--passphrase] [--length N] [--words N]` | Generate a password/passphrase without storing it |
| `credmgr audit` | Run a full password health audit (weak / duplicate / reused / old / breached) |
| `credmgr passwd` | Change the master password (re-wraps the DEK only) |
| `credmgr export` | Print the entire vault as plaintext JSON (always re-prompts for the master password) |
| `credmgr import <filepath>` | Import accounts from a plaintext JSON file (skips duplicates/invalid entries) |
| `credmgr config show` | Display current configuration |
| `credmgr config set <key> <value>` | Change a mutable configuration value |
| `credmgr config reset` | Reset configuration to defaults |

Service and userid lookups (`get`, `copy`, `update`, `delete`, `history`) use progressively looser matching: **exact match → case-insensitive substring → fuzzy match** (via `difflib`, threshold configurable). If a lookup matches more than one service or account, `credmgr` lists the candidates and asks you to be more specific instead of guessing.

Run `credmgr --help` or `credmgr <command> --help` at any time for full usage and examples.

---

## Session Caching (Auth Timeout)

Typing your master password (and paying the Argon2 cost) on every single command would be tedious. To avoid this without persisting the master password or DEK to disk, `credmgr` caches the **DEK only** (never the master password, never the KEK) in **`/dev/shm`** — Linux's RAM-backed tmpfs — for up to `auth_timeout` seconds (default: 300s / 5 minutes).

- The cache is scoped to your current terminal **session ID**, so it is not usable from unrelated sessions.
- A background watcher process automatically deletes the cached key when the timeout expires or the owning session ends.
- Sensitive commands — notably `credmgr export` — always force a **fresh** prompt (`fresh=True`) and bypass the cache, regardless of `auth_timeout`.
- Because the cache lives in RAM-backed storage rather than a real disk, it does not survive a reboot and is not written to persistent storage.

Set `auth_timeout` to `0` to disable session caching entirely and require the master password on every command.

---

## Password Generation

Two generation modes, available via `--generate` on `add`/`update`, or standalone via `credmgr generate`:

- **Random password** (default): built from `secrets` (a cryptographically secure RNG), guaranteed to include at least one lowercase letter, one uppercase letter, one digit, and one punctuation character. Length is configurable (`password_length`, default 20, range 8–256).
- **Passphrase** (`--passphrase`): a Diceware-style passphrase of hyphen-joined random words (e.g. `avocado-cluster-ember-falcon-tulip`), drawn from a word list via `secrets.choice`. Word count is configurable (`passphrase_num_word`, default 5, range 3–12).

The word list used for passphrases is, by default, a large real-world list (Google's 10,000 most common English words, filtered to 4–8 letter alphabetic words) fetched during `init`/`fetch-data` into `~/.credmgr/data/wordlist.txt`. If that file is unavailable (e.g. offline, first run without fetching), `credmgr` falls back to a small built-in word list bundled in the source.

---

## Password Health Audit

`credmgr audit` inspects every stored password and reports:

| Check | Description |
|---|---|
| **Duplicates** | The same password reused across two or more different accounts |
| **Weak** | Flagged for: length under 12 (or under 8 = "too short"), matching a common-password list, fewer than 3 of {lowercase, uppercase, digit, punctuation} character classes, 3+ repeated characters in a row, or a keyboard/numeric sequence (e.g. `qwerty`, `123456`) |
| **Reused** | The account's *current* password matches one of its own previously recorded history entries |
| **Old** | Not changed within `password_max_age_days` (default: 90 days) |
| **Breached** | The SHA-1 hash of the password matches an entry in a local, offline breach-hash database |

The common-passwords list, sequence patterns, and breach-hash database are the same optional datasets fetched during `init`/`fetch-data` (see above); each check gracefully degrades to a small built-in fallback if its dataset isn't present. If no breach database exists at all, the breach check is skipped and `credmgr` tells you how to populate one (`credmgr fetch-data`, or your own file of one SHA-1 hash per line at `~/.credmgr/data/breached_hash.txt`).

Breach checking is **entirely offline** — passwords are hashed locally and compared against a local file. Nothing is ever sent to a third-party API (such as Have I Been Pwned's online service), preserving the local-first design.

---

## Configuration

Configuration lives at `~/.credmgr/config.json`, layered on top of built-in defaults, and is edited via `credmgr config`.

| Key | Default | Mutable after vault creation? | Description |
|---|---|---|---|
| `cipher` | `aes256gcm` | ❌ | `aes256gcm` or `xchacha20poly1305` |
| `argon2_time_cost` | `3` | ❌ | Argon2id iterations |
| `argon2_memory_cost` | `65536` (KiB) | ❌ | Argon2id memory usage |
| `argon2_parallelism` | `2` | ❌ | Argon2id threads |
| `argon2_hash_len` | `32` | ❌ | Derived key length (bytes) |
| `auth_timeout` | `300` (sec) | ✅ | Session DEK cache lifetime; `0` disables caching |
| `fuzzy_threshold` | `0.75` | ✅ | Minimum similarity ratio (0–1) for fuzzy search matches |
| `password_length` | `20` | ✅ | Default generated password length |
| `passphrase_num_word` | `5` | ✅ | Default number of words in a generated passphrase |
| `clipboard_timeout` | `30` (sec) | ✅ | Seconds before a copied password is cleared from the clipboard |
| `password_max_age_days` | `90` | ✅ | Age threshold for the "old password" audit check |
| `password_history_limit` | `10` | ✅ | Max number of past passwords retained per account |

Fields marked ❌ are **fixed once a vault exists**, since changing them would require re-deriving the KEK and/or re-encrypting the whole vault. To change them, create a fresh vault and `import` your exported credentials.

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
└── credmgr/
    ├── __init__.py           # Package docstring / version
    ├── __main__.py           # `python -m credmgr` entry point
    ├── cli.py                # Argument parsing and command dispatch (the "controller")
    ├── models.py             # Account / Credentials / PasswordHistoryEntry data models
    ├── config.py             # Runtime configuration (defaults + persisted overrides)
    ├── vault.py              # Versioned, encrypted vault file I/O + migrations
    ├── auth.py               # Master-password authentication + session DEK caching
    ├── crypto/
    │   ├── ciphers.py        # AEAD cipher backends (AES-256-GCM, XChaCha20-Poly1305)
    │   └── envelope.py       # Envelope-encryption primitives (KDF, DEK wrap/unwrap)
    ├── generator.py          # Password / passphrase generation
    ├── wordlist.py           # Bundled fallback word list for passphrases
    ├── datasources.py        # Downloads wordlist / common-passwords / breach-hash datasets
    ├── search.py             # Fuzzy + global search across the vault
    ├── audit.py              # Password health audit logic
    ├── clipboard.py          # Clipboard copy with auto-clear
    └── ui.py                 # Terminal rendering helpers (rich)
```

---

## Advantages

- **Local-first and offline-capable.** No account, no cloud service, no network dependency for core operation — everything after `init` works fully offline.
- **Strong, modern cryptography.** Argon2id for key derivation plus AEAD ciphers (AES-256-GCM / XChaCha20-Poly1305) for encryption, both industry-recommended primitives.
- **Cheap password rotation.** Envelope encryption means changing your master password never requires re-encrypting the (potentially large) vault contents.
- **Tamper detection.** AEAD authentication means any corruption or tampering of the vault file is detected on unlock rather than silently accepted.
- **Crash-safe writes.** Atomic write-then-replace with automatic `.bak` backups protects against partial writes/power loss.
- **No plaintext secrets at rest.** Session caching stores only the DEK (never the master password) in RAM-backed storage, never on persistent disk.
- **Transparent format.** The vault is a readable, versioned JSON structure — easy to inspect, back up, or migrate.
- **Extensible by design.** New ciphers, vault versions/migrations, audit checks, and CLI commands each have a clearly documented extension point.
- **Useful built-in tooling.** Password generation, fuzzy search, password history, and an offline security audit are included out of the box.

## Limitations & Threat Model

- **Single-user, single-machine.** There is no multi-device sync, sharing, or team/organization support. Moving vaults between machines is manual (copy the vault file, or `export`/`import`).
- **No 2FA/MFA storage.** `credmgr` stores passwords and notes only; it does not generate or store TOTP/2FA codes.
- **Master password is the single point of failure.** If you forget it, your data is unrecoverable — there is no backdoor, recovery key, or password-reset mechanism by design.
- **Metadata is not hidden.** Service names and userids sit inside the same encrypted blob as passwords, so no metadata is visible in the file — but note that `list`/`search` output, shell history, and terminal scrollback can still leak service/userid names if your terminal or shell history isn't otherwise secured.
- **`export` produces plaintext.** `credmgr export` intentionally prints your entire vault as unencrypted JSON to stdout; treat exported files/output with the same care as your master password.
- **Local breach database only.** The offline breach-hash check is limited to whatever dataset you've fetched (a curated ~100k-password subset, not the full multi-hundred-million-entry HIBP corpus), so it will miss many real-world breached passwords. It also does not perform any online k-anonymity lookup.
- **Depends on OS-level protections.** File permissions (`0600`/`0700`) and `/dev/shm` protect against other unprivileged users on the same machine, but not against a compromised account, a user with root access, or malware running as you. `credmgr` does not defend against a compromised host.
- **Clipboard exposure window.** Copied passwords remain on the system clipboard until `clipboard_timeout` elapses (default 30s) or something else overwrites the clipboard; other applications with clipboard access during that window could read it.
- **`fork()`-based background helpers.** The session-cache cleaner and clipboard auto-clear use `os.fork()`, which is POSIX-only — **credmgr requires a Unix-like OS (Linux/macOS) and does not support native Windows** (WSL should work).
- **No rate limiting on password attempts.** There's no lockout after repeated failed master-password attempts beyond Argon2id's inherent per-attempt cost.

---

## Extending credmgr

The codebase documents its own extension points:

- **New cipher:** add a class to `crypto/ciphers.py` implementing `generate_key` / `encrypt` / `decrypt`, and register it in the `CIPHERS` dict.
- **New vault version:** bump `vault.CURRENT_VERSION` and add an entry to `vault.MIGRATIONS`; `_migrate()` walks old vaults forward automatically.
- **New audit check:** add a `find_*` function to `audit.py` and wire it into `run_audit()` / `AuditReport`.
- **New CLI command:** add a `cmd_*` function and a subparser in `cli.py`.

---

## Disclaimer

This tool is provided as-is. While it follows established cryptographic best practices (Argon2id, AEAD ciphers), it has not undergone formal third-party security audit. Use it at your own discretion for securing sensitive credentials, and always keep independent backups of your vault file.