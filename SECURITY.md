# Security Policy

## Supported versions

`credmgr` is currently in beta (pre-1.0 releases). Security fixes are
made against the latest released version on the `main` branch; there are no
long-term-support branches at this time. Once the project reaches a 1.0
release, this policy will be updated with an explicit support window.

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security
vulnerabilities. Instead:

1. Email the maintainer at **veerabadranm1@gmail.com** with a
   description of the issue, steps to reproduce, and its potential
   impact.
2. Include the `credmgr` version, Python version, OS, and which crypto
   backend/schema (if relevant) you were using.
3. If possible, suggest a fix or mitigation.

You should expect an acknowledgment within a reasonable timeframe. Please
give the maintainer a reasonable opportunity to investigate and address a
report before any public disclosure.

This is a community-maintained, unfunded open-source project — there is
no bug bounty program.

## Security philosophy

- **Local-first, no hidden network calls.** The only network activity
  `credmgr` ever performs is the explicit, optional dataset download in
  `credmgr init` / `credmgr fetch-data` (wordlist, common-passwords, and
  breach-hash datasets, fetched from public GitHub-hosted sources over
  HTTPS). Every other command is fully offline.
- **Fail closed, fail loud.** Authentication failures, tampered vaults,
  and missing dependencies raise distinct, typed exceptions and clear
  messages — never silently return corrupted or partial data.
- **AEAD everywhere.** Every supported crypto backend is an Authenticated
  Encryption with Associated Data construction, so tampering is always
  detected on decrypt, not just encrypted-but-unauthenticated.
- **Minimize what's re-encrypted.** Envelope encryption means rotating
  the master password never touches vault contents, and switching crypto
  backends never touches the KDF or the master password — each operation
  re-encrypts the smallest amount of data necessary. See
  [docs/crypto.md](docs/crypto.md).
- **No plaintext at rest, and minimal plaintext in memory.** Decrypted
  vault contents exist only in memory for the life of a single command
  (or a short, RAM-backed session cache of the *key*, never the
  password or plaintext contents).
- **Follow established primitives, not custom cryptography.** Argon2id
  for key derivation and well-reviewed AEAD ciphers (AES-256-GCM,
  XChaCha20-Poly1305) via established libraries (`cryptography`,
  `PyNaCl`, `pycryptodome`) — `credmgr` implements no cryptographic
  primitives of its own.

`credmgr` has **not** undergone a formal third-party security audit.
Use it with that in mind, and keep independent backups of your vault
files.

## Threat model

### In scope / defended against

- **Offline brute-force of a stolen vault file.** Mitigated by Argon2id
  (memory-hard, tunable cost) deriving the key-encryption key.
- **Tampering with the vault file.** Detected by AEAD authentication on
  every decrypt; a tampered or corrupted file fails to unlock rather than
  returning partial or corrupted plaintext.
- **Other unprivileged local users on the same machine.** Vault files
  (`0600`) and directories (`0700`) restrict access at the filesystem
  level; the session-cache DEK is written under the same restrictive
  permissions, in `/dev/shm` when available.
- **Crash during a write.** Vault writes are atomic (temp file + fsync +
  rename) with an automatic `.bak` fallback if the primary file is
  corrupted.
- **Accidental data loss during backend/schema migration.** Migrations
  operate on data fully decrypted in memory and only write the new,
  complete vault once re-encryption succeeds — no partial-write states.

### Explicitly out of scope

- **A compromised user account, root access, or malware running as
  you.** `credmgr` relies on OS-level file permissions; it cannot defend
  against an attacker who already has your OS user's privileges (e.g. a
  malicious process that can read process memory or `/dev/shm`).
- **Multi-user sync, sharing, or team access.** `credmgr` is
  single-user, single-machine by design. There is no built-in mechanism
  for safely sharing a vault between people or devices.
- **Loss of the master password.** There is no backdoor, recovery key,
  or reset mechanism. If you forget your master password, the vault is
  unrecoverable by design.
- **Shell history / terminal scrollback leakage of metadata.** Service
  names, userids, and keys typed as CLI arguments may be visible in shell
  history or terminal buffers even though the vault file itself never
  stores anything in plaintext.
- **Clipboard exposure.** A copied password remains on the system
  clipboard until `clipboard_timeout` elapses (default 30s) or another
  application checks/overwrites it.
- **Malicious or compromised crypto/schema plugins.** `credmgr` trusts
  whatever is importable from `credmgr/crypto/plugins/` and
  `credmgr/schemas/plugins/`; it does not sandbox plugin code. Only
  install plugins you trust.
- **Non-POSIX platforms.** Session caching and clipboard auto-clear rely
  on `os.fork()`; native Windows is not supported (WSL is expected to
  work, as it's POSIX-compatible).
- **The completeness of the offline breach database.** The bundled
  breach check uses a curated subset of known-breached passwords, not
  the full Have I Been Pwned corpus, and performs no online k-anonymity
  lookup.

For the full list of known limitations, see the README's
[Limitations & threat model](README.md#limitations--threat-model-short-version)
summary.
