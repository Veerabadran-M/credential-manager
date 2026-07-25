"""The abstract encryption backend interface.

This is the *only* contract the rest of the application (vault.py, cli.py,
...) is allowed to depend on. Nothing outside credmgr/crypto/plugins/ should
ever import cryptography, PyNaCl, or PyCryptodome directly -- everything goes
through an EncryptionBackend subclass, looked up by name via the registry.

To add a new backend: subclass EncryptionBackend, implement every method
below, and drop the file in credmgr/crypto/plugins/. The registry discovers
it automatically -- no other file needs to change (Open/Closed Principle).
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