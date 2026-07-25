"""XChaCha20-Poly1305 backend built on PyNaCl (libsodium bindings).

XChaCha20's 24-byte nonce makes random nonce generation safe for the
lifetime of a vault (unlike AES-GCM's 12-byte nonce), at the cost of
requiring the PyNaCl dependency.
"""

from __future__ import annotations

import os

from ..base import EncryptionBackend
from ..exceptions import BackendUnavailableError, DecryptionError, EncryptionError

_MISSING_DEP_MESSAGE = (
    "The 'xchacha-pynacl' backend requires the 'PyNaCl' package.\n"
    "Install it using:\n  pip install credmgr[pynacl]"
)

class XChaCha20Pynacl(EncryptionBackend):
    name = "xchacha-pynacl"
    algorithm = "XChaCha20-Poly1305"
    key_size = 32
    nonce_size = 24
    pip_extra = "pynacl"

    @classmethod
    def is_available(cls) -> bool:
        try:
            import nacl.bindings  # noqa: F401
        except ImportError:
            return False
        return True

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.key_size)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        try:
            import nacl.bindings as sodium
        except ImportError as e:
            raise BackendUnavailableError(_MISSING_DEP_MESSAGE) from e

        nonce = os.urandom(XChaCha20Pynacl.nonce_size)
        try:
            ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                plaintext, aad, nonce, key
            )
        except Exception as e:
            raise EncryptionError(str(e)) from e
        return nonce + ciphertext

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        try:
            import nacl.bindings as sodium
        except ImportError as e:
            raise BackendUnavailableError(_MISSING_DEP_MESSAGE) from e

        nonce_size = XChaCha20Pynacl.nonce_size
        nonce, actual_ciphertext = ciphertext[:nonce_size], ciphertext[nonce_size:]
        try:
            return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                actual_ciphertext, aad, nonce, key
            )
        except Exception as e:
            raise DecryptionError("Decryption failed (authentication error).") from e