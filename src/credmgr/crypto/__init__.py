"""credmgr.crypto: pluggable AEAD encryption backend system.

The rest of the application should only import from this package's top
level or .envelope -- never reach into .plugins directly, and never
import cryptography/PyNaCl/PyCryptodome themselves. See base.py for the
plugin interface and registry.py for discovery/lookup.
"""

from __future__ import annotations

from .base import EncryptionBackend
from .exceptions import (BackendUnavailableError, CryptoError, DecryptionError, 
                         EncryptionError, UnknownBackendError)
from .registry import (all_backends, available_backends, default_backend, 
                       get_backend, register, resolve_backend)

__all__ = [
    "EncryptionBackend",
    "CryptoError",
    "UnknownBackendError",
    "BackendUnavailableError",
    "EncryptionError",
    "DecryptionError",
    "get_backend",
    "available_backends",
    "all_backends",
    "default_backend",
    "resolve_backend",
    "register"
]