"""Abstract encryption backend interface.

The only contract the rest of the application (vault.py, core/manager.py, ...) is
allowed to depend on: nothing outside credmgr/crypto/plugins/ should
import cryptography, PyNaCl, or PyCryptodome directly. To add a backend,
subclass EncryptionBackend and drop the file in crypto/plugins/ -- the
registry discovers it automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

class EncryptionBackend(ABC):
    """An interchangeable AEAD encryption backend.

    Class attributes (must be set by every subclass):
        name:       Stable, unique identifier stored in vault metadata
                     (e.g. "aesgcm-cryptography"). Never change this once
                     released -- existing vaults reference it by name.
        algorithm:  Human-readable algorithm name for display purposes
                     (e.g. "AES-256-GCM").
        key_size:   Symmetric key length in bytes.
        nonce_size: Nonce/IV length in bytes used by this backend.
        pip_extra:  The pyproject.toml optional-dependency group that
                     provides this backend's dependency (e.g. "pynacl"),
                     used to build the "pip install credmgr[...]" hint.
    """

    name: str
    algorithm: str
    key_size: int
    nonce_size: int
    pip_extra: str

    @classmethod
    @abstractmethod
    def is_available(cls) -> bool:
        """Return True if this backend's underlying dependency is importable.

        Must never raise -- a plugin whose dependency is missing should
        report unavailable, not crash the application.
        """

    @classmethod
    @abstractmethod
    def generate_key(cls) -> bytes:
        """Generate a new random symmetric key of `key_size` bytes."""

    @staticmethod
    @abstractmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        """Encrypt `plaintext` under `key`, authenticating `aad` if given.

        Returns a single opaque blob (nonce + ciphertext, backend-defined
        layout) that `decrypt` can consume unmodified. Callers must not
        assume anything about its internal structure.

        Raises EncryptionError on failure and BackendUnavailableError if the
        dependency is missing.
        """

    @staticmethod
    @abstractmethod
    def decrypt(key: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        """Decrypt a blob produced by `encrypt`. Raises DecryptionError on
        any authentication/format failure, and BackendUnavailableError if
        the dependency is missing.
        """