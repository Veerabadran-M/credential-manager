"""credmgr.schemas: pluggable vault-content schema system.

vault.py stores an encrypted, opaque blob plus a plaintext schema name;
this package turns that blob's decrypted bytes into something the application layer can
operate on, and back. See base.py for the interface and registry.py for
discovery/lookup.

Bundled schemas: credentials (service/account/password/notes/history),
env (flat KEY=VALUE entries).
"""

from __future__ import annotations

from .base import CommandResult, IndexEntry, Line, Schema, SchemaError, SecretRequired, Table
from .registry import all_schemas, get_schema, register
from .registry import UnknownSchemaError

__all__ = [
    "Schema",
    "SchemaError",
    "SecretRequired",
    "UnknownSchemaError",
    "CommandResult",
    "Line",
    "Table",
    "IndexEntry",
    "get_schema",
    "all_schemas",
    "register",
]
