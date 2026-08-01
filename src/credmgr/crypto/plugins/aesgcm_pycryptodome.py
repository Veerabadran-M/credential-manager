"""AES-256-GCM backend built on PyCryptodome.

A second AES-GCM implementation alongside aesgcm_cryptography.py, useful
on platforms where 'cryptography' is hard to build (it needs a Rust
toolchain) but a pure-C extension is easier.
"""

from __future__ import annotations

import os

from ..base import EncryptionBackend
from ..exceptions import BackendUnavailableError, DecryptionError, EncryptionError

_MISSING_DEP_MESSAGE = (
    "The 'aesgcm-pycryptodome' backend requires the 'pycryptodome' package.\n"
    "Install it using:\n  pip install credmgr[pycryptodome]"
)

class AESGCMPycryptodomeBackend(EncryptionBackend):
    name = "aesgcm-pycryptodome"
    algorithm = "AES-256-GCM"
    key_size = 32
    nonce_size = 12
    tag_size = 16
    pip_extra = "pycryptodome"

    @classmethod
    def is_available(cls) -> bool:
        try:
            import Crypto.Cipher.AES  # noqa: F401
        except ImportError:
            return False
        return True

    @classmethod
    def generate_key(cls) -> bytes:
        return os.urandom(cls.key_size)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
        try:
            from Crypto.Cipher import AES
        except ImportError as e:
            raise BackendUnavailableError(_MISSING_DEP_MESSAGE) from e

        nonce = os.urandom(AESGCMPycryptodomeBackend.nonce_size)
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if aad:
                cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        except Exception as e:
            raise EncryptionError(str(e)) from e
        # Layout: nonce || tag || ciphertext
        return nonce + tag + ciphertext

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        try:
            from Crypto.Cipher import AES
        except ImportError as e:
            raise BackendUnavailableError(_MISSING_DEP_MESSAGE) from e

        nonce_size = AESGCMPycryptodomeBackend.nonce_size
        tag_size = AESGCMPycryptodomeBackend.tag_size
        nonce = ciphertext[:nonce_size]
        tag = ciphertext[nonce_size:nonce_size + tag_size]
        actual_ciphertext = ciphertext[nonce_size + tag_size:]
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            if aad:
                cipher.update(aad)
            return cipher.decrypt_and_verify(actual_ciphertext, tag)
        except Exception as e:
            raise DecryptionError("Decryption failed (authentication error).") from e