"""credmgr.core: the application layer.

CredentialManager (see manager.py) is the single entry point every
frontend (currently just credmgr/cli/) should use. It knows how to
create/open/manage vaults, dispatch CRUD to the active schema, keep the
cross-vault search index in sync, and drive session-key caching -- all
the orchestration that used to live directly in the CLI's command
functions.

This layer never imports Typer, Rich, or anything that reads from or
writes to a terminal. It returns plain data (dataclasses, schema
CommandResults, ...) and raises exceptions; a frontend decides how to
render or prompt for the rest. Where an operation needs a secret it
doesn't have (typically the master password), it raises
PasswordRequired instead of prompting -- callers obtain the secret
however is appropriate for them and retry with `password=`.

Named `core/`, not `backend/`, to keep this application layer distinct
from the *crypto* backends (`credmgr/crypto/plugins/`, and the
`--backend`/`config.backend` naming used throughout this codebase and
CLI) -- the two are unrelated concepts that happened to share a name.
"""

from __future__ import annotations

from ..crypto import BackendUnavailableError, UnknownBackendError
from ..schemas import ContentRequired, SchemaError, SecretRequired, UnknownSchemaError
from ..vault import AuthenticationError, VaultError
from .manager import (CredentialManager, PasswordRequired, UnlockedVault,
                       VaultNotFound)

__all__ = [
    "CredentialManager",
    "UnlockedVault",
    # Exceptions a frontend may want to catch. Re-exported here so a
    # frontend only needs to import from credmgr.core, never reaching
    # into credmgr.vault/credmgr.crypto/credmgr.schemas directly.
    "PasswordRequired",
    "VaultNotFound",
    "VaultError",
    "AuthenticationError",
    "BackendUnavailableError",
    "UnknownBackendError",
    "SchemaError",
    "SecretRequired",
    "ContentRequired",
    "UnknownSchemaError",
]
