"""AES-256-GCM backend built on the 'cryptography' package.

The import of `cryptography` is lazy (deferred into methods) so that simply
*discovering* this plugin never fails when the package isn't installed --
only calling it does, and that failure is translated into a friendly
BackendUnavailableError rather than a raw ImportError.
"""

from __future__ import annotations

import os

from ..base import EncryptionBackend
from ..exceptions import BackendUnavailableError, DecryptionError, EncryptionError

_MISSING_DEP_MESSAGE = (
    "The 'aesgcm-cryptography' backend requires the 'cryptography' package.\n"
    "Install it using:\n  pip install credmgr[cryptography]"
)

class AESGCMCryptographyBackend(EncryptionBackend):
    name = "aesgcm-cryptography"
    algorithm = "AES-256-GCM"
    key_size = 32
    nonce_size = 12
    pip_extra = "cryptography"

    @classmethod
    def is_available(cls) -> bool:
        try:
            import cryptography  # noqa: F401
        except ImportError:
            return False
        return True

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.key_size)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:
            raise BackendUnavailableError(_MISSING_DEP_MESSAGE) from e

        nonce = os.urandom(AESGCMCryptographyBackend.nonce_size)
        try:
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        except Exception as e:
            raise EncryptionError(str(e)) from e
        return nonce + ciphertext

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:
            raise BackendUnavailableError(_MISSING_DEP_MESSAGE) from e

        nonce_size = AESGCMCryptographyBackend.nonce_size
        nonce, actual_ciphertext = ciphertext[:nonce_size], ciphertext[nonce_size:]
        try:
            return AESGCM(key).decrypt(nonce, actual_ciphertext, aad)
        except Exception as e:
            raise DecryptionError("Decryption failed (authentication error).") from e