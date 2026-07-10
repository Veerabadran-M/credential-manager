"""Envelope encryption primitives.

    Master Password --Argon2id-->  Master Key (KEK)
    KEK encrypts a random Data Encryption Key (DEK)  -> encrypted_key
    DEK encrypts the vault contents                  -> ciphertext

Rotating the master password only re-wraps the DEK under a new KEK; it
never requires touching (or re-encrypting) the vault contents itself.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from argon2.low_level import Type, hash_secret_raw

from .ciphers import get_cipher

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))

@dataclass
class KDFParams:
    algorithm: str = "argon2id"
    time_cost: int = 3
    memory_cost: int = 65536
    parallelism: int = 2
    hash_len: int = 32
    salt: bytes = field(default_factory=lambda: os.urandom(16))

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "time_cost": self.time_cost,
            "memory_cost": self.memory_cost,
            "parallelism": self.parallelism,
            "hash_len": self.hash_len,
            "salt": b64e(self.salt)
        }

    @staticmethod
    def from_dict(d: dict) -> "KDFParams":
        return KDFParams(
            algorithm=d.get("algorithm", "argon2id"),
            time_cost=d["time_cost"],
            memory_cost=d["memory_cost"],
            parallelism=d["parallelism"],
            hash_len=d["hash_len"],
            salt=b64d(d["salt"])
        )

def derive_kek(master_password: str, params: KDFParams) -> bytes:
    if params.algorithm != "argon2id":
        raise ValueError(f"Unsupported KDF algorithm: {params.algorithm}")

    return hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=params.salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=params.hash_len,
        type=Type.ID,
    )

def generate_dek(cipher_name: str) -> bytes:
    return get_cipher(cipher_name).generate_key()

def wrap_dek(dek: bytes, kek: bytes, cipher_name: str) -> dict:
    cipher = get_cipher(cipher_name)
    nonce, ciphertext = cipher.encrypt(kek, dek, aad=b"credmgr-dek")
    return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

def unwrap_dek(wrapped: dict, kek: bytes, cipher_name: str) -> bytes:
    cipher = get_cipher(cipher_name)
    nonce = b64d(wrapped["nonce"])
    ciphertext = b64d(wrapped["ciphertext"])
    return cipher.decrypt(kek, nonce, ciphertext, aad=b"credmgr-dek")

def encrypt_blob(dek: bytes, plaintext: bytes, cipher_name: str) -> dict:
    cipher = get_cipher(cipher_name)
    nonce, ciphertext = cipher.encrypt(dek, plaintext, aad=b"credmgr-vault")
    return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

def decrypt_blob(dek: bytes, blob: dict, cipher_name: str) -> bytes:
    cipher = get_cipher(cipher_name)
    nonce = b64d(blob["nonce"])
    ciphertext = b64d(blob["ciphertext"])
    return cipher.decrypt(dek, nonce, ciphertext, aad=b"credmgr-vault")