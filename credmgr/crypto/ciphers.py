"""AEAD cipher backends for envelope encryption.

A small, uniform interface so the rest of the codebase never talks to a
specific crypto library directly. To add a new cipher: implement the same
four methods (generate_key/encrypt/decrypt + name/key_size/nonce_size) and
register the class in CIPHERS.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import nacl.bindings as _nacl_bindings
    HAVE_NACL = True
except ImportError:
    HAVE_NACL = False

class CipherError(Exception):
    pass

class AES256GCM:
    name = "aes256gcm"
    key_size = 32
    nonce_size = 12

    @staticmethod
    def generate_key() -> bytes:
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None):
        nonce = os.urandom(AES256GCM.nonce_size)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return nonce, ciphertext

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

class XChaCha20Poly1305:
    name = "xchacha20poly1305"
    key_size = 32
    nonce_size = 24

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None):
        if not HAVE_NACL:
            raise CipherError(
                "xchacha20poly1305 requires the optional 'pynacl' package "
                "(pip install pynacl)."
            )
        nonce = os.urandom(XChaCha20Poly1305.nonce_size)
        ciphertext = _nacl_bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key
        )
        return nonce, ciphertext

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
        if not HAVE_NACL:
            raise CipherError(
                "xchacha20poly1305 requires the optional 'pynacl' package "
                "(pip install pynacl)."
            )
        return _nacl_bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, aad, nonce, key
        )

CIPHERS = {
    AES256GCM.name: AES256GCM,
    XChaCha20Poly1305.name: XChaCha20Poly1305,
}

def get_cipher(name: str):
    try:
        return CIPHERS[name]
    except KeyError:
        raise CipherError(f"Unknown cipher '{name}'. Available: {', '.join(CIPHERS)}")
    
SUPPORTED_CIPHERS = {
    "1": ("aes256gcm", "AES-256-GCM"),
    "2": ("xchacha20poly1305", "XChaCha20-Poly1305")
}
