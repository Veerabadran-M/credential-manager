"""Envelope encryption primitives.

    Master Password --Argon2id-->  Master Key (KEK)
    KEK encrypts a random Data Encryption Key (DEK)  -> encrypted_key
    DEK encrypts the vault contents                  -> ciphertext

Rotating the master password only re-wraps the DEK under a new KEK; it
never requires touching (or re-encrypting) the vault contents itself.
Switching backends (see vault.migrate_backend) re-wraps the DEK *and*
re-encrypts the vault contents, but never the master password/KDF.

Every function here takes a `backend` name (not a cipher object) and looks
it up through the registry, so this module -- like the rest of the
application -- never imports cryptography/PyNaCl/PyCryptodome directly.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field

from argon2.low_level import Type, hash_secret_raw

from .registry import get_backend

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
        type=Type.ID
    )

def generate_dek(backend_name: str) -> bytes:
    return get_backend(backend_name).generate_key()

def wrap_dek(dek: bytes, kek: bytes, backend_name: str) -> dict:
    backend = get_backend(backend_name)
    blob = backend.encrypt(kek, dek, aad=b"credmgr-dek")
    return {"ciphertext": b64e(blob)}

def unwrap_dek(wrapped: dict, kek: bytes, backend_name: str) -> bytes:
    backend = get_backend(backend_name)
    blob = b64d(wrapped["ciphertext"])
    return backend.decrypt(kek, blob, aad=b"credmgr-dek")

def encrypt_blob(dek: bytes, plaintext: bytes, backend_name: str) -> dict:
    backend = get_backend(backend_name)
    blob = backend.encrypt(dek, plaintext, aad=b"credmgr-vault")
    return {"ciphertext": b64e(blob)}

def decrypt_blob(dek: bytes, blob: dict, backend_name: str) -> bytes:
    backend = get_backend(backend_name)
    ciphertext = b64d(blob["ciphertext"])
    return backend.decrypt(dek, ciphertext, aad=b"credmgr-vault")