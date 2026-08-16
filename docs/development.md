# Development Guide

This document covers day-to-day development workflows, including
contribution policy (PR process, coding conventions summary). For
architectural background, start with [architecture.md](architecture.md).

## Setting up a development environment

```bash
git clone https://github.com/Veerabadran-M/credential-manager.git
cd credential-manager
python -m venv .venv
source .venv/bin/activate

pip install -e .[all]           # editable install with every crypto backend
pip install pytest
```

`credmgr` is developed and tested on Linux. Native Windows is not
supported (the codebase relies on POSIX-only facilities such as
`os.chmod` permission bits and `/dev/shm`); running under WSL is
untested but expected to work, since it provides a POSIX-compatible
environment. macOS and other BSD-derived systems are untested.

`credmgr`'s core has no *backend-specific* AEAD dependency of its own — installing `[all]`
pulls in `cryptography`, `PyNaCl`, and `pycryptodome` so every backend's
tests can run locally. See [Installation](../README.md#installation) if
you only need one backend.

## Running the app locally

```bash
credmgr --help                  # if installed with `pip install -e .`
python credmgr.py --help        # or, without installing
python -m credmgr --help        # equivalent
```

There's no dedicated environment variable for pointing `credmgr` at a
scratch directory. If you don't want to touch your real `~/.credmgr`
while developing, the simplest approach is to temporarily set `HOME` to
a throwaway directory, or use the `tmp_path`-based fixtures the test
suite already relies on.

## Running tests

```bash
pytest tests/ -v
```

| File | Covers |
|---|---|
| `test_backend_contract.py` | Every installed crypto backend, parametrized: round-trip encrypt/decrypt (with/without AAD), tamper/wrong-key/AAD-mismatch rejection — all raising the same `DecryptionError` |
| `test_registry.py` | Crypto plugin discovery, unknown/unavailable backend handling, broken-plugin resilience, and CLI/env/config/default selection priority |
| `test_vault.py` | Create/unlock/save round trips per backend, wrong-password handling, and `migrate_backend()` correctness |

Backend-parametrized tests are built from `available_backends()`, not a
hardcoded list — a new plugin's tests run automatically once its file
exists and its dependency is installed. Tests use a fresh
`Configuration` pointed at a temp directory (see `tests/conftest.py`), so
they never touch a real `~/.credmgr` or interfere with the session cache.

Run a single test file or test:

```bash
pytest tests/test_vault.py -v
pytest tests/test_vault.py::test_migrate_backend_preserves_data -v
```

## Code style

The codebase follows a small set of consistent conventions rather than an
enforced formatter/linter today:

- Standard library `dataclasses` for plain data (`Account`, `Credentials`,
  `KDFParams`, `AuditReport`, …).
- `from __future__ import annotations` at the top of every module, with
  `X | None`-style type hints.
- Docstrings at module level explain *why*, not just *what* — new modules
  should follow that pattern.
- Third-party crypto libraries are **never** imported at module scope
  outside `crypto/plugins/*.py` — see [plugin-system.md](plugin-system.md).
- Exceptions form small, purpose-specific hierarchies (`CryptoError`,
  `VaultError`, `SchemaError`, `VaultManagerError`) rather than reusing
  built-in exception types for domain errors.

If you introduce a formatter or linter, propose it via an issue first so
the whole codebase can be reformatted in one pass rather than drifting
file by file.

## Extension points

| To add a... | Do this |
|---|---|
| New crypto backend | Add a file to `crypto/plugins/` implementing `EncryptionBackend` (see [plugin-system.md](plugin-system.md)) |
| New vault schema | Add a file to `schemas/plugins/` implementing `Schema` (see [plugin-system.md](plugin-system.md)) |
| New vault format version | Bump `vault.CURRENT_VERSION` and add explicit version-migration handling in `vault.py` (see [migration.md](migration.md)) |
| New audit check | Add a `find_*` function to `audit.py`, wired into `run_audit()` |
| New CLI command | Add a `CredentialManager` method in `core/manager.py` (application logic, no printing/prompting) plus a `cmd_*` function and an `@app.command()` in `cli/commands.py` (argument parsing + rendering only; use `@config_app.command()` / `@vault_app.command()` for a subcommand) |

## Project layout reference

See [architecture.md](architecture.md#package-layout) for the full
annotated directory tree.
