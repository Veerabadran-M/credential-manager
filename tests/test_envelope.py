"""Tests for envelope encryption primitives: KDF params serialization,
DEK generation/wrap/unwrap, and blob encrypt/decrypt.
"""

from __future__ import annotations

import pytest

from credmgr.crypto.envelope import (KDFParams, b64d, b64e, decrypt_blob,
                                      derive_kek, encrypt_blob, generate_dek,
                                      unwrap_dek, wrap_dek)
from credmgr.crypto.registry import available_backends

BACKEND_NAMES = available_backends()


def test_b64_round_trip():
    data = b"\x00\x01\xff\xfe hello"
    assert b64d(b64e(data)) == data


def test_kdf_params_to_dict_and_from_dict_round_trip():
    params = KDFParams(time_cost=4, memory_cost=32768, parallelism=1, hash_len=32, salt=b"0123456789abcdef")
    d = params.to_dict()
    restored = KDFParams.from_dict(d)

    assert restored.algorithm == params.algorithm
    assert restored.time_cost == params.time_cost
    assert restored.memory_cost == params.memory_cost
    assert restored.parallelism == params.parallelism
    assert restored.hash_len == params.hash_len
    assert restored.salt == params.salt


def test_kdf_params_default_salt_is_random():
    a = KDFParams()
    b = KDFParams()
    assert a.salt != b.salt


def test_derive_kek_is_deterministic_for_same_inputs():
    params = KDFParams(time_cost=2, memory_cost=19 * 1024, parallelism=1, hash_len=32, salt=b"fixedsaltfixed16")
    kek1 = derive_kek("password123", params)
    kek2 = derive_kek("password123", params)
    assert kek1 == kek2
    assert len(kek1) == 32


def test_derive_kek_differs_for_different_passwords():
    params = KDFParams(time_cost=2, memory_cost=19 * 1024, parallelism=1, hash_len=32, salt=b"fixedsaltfixed16")
    kek1 = derive_kek("password123", params)
    kek2 = derive_kek("different-pw", params)
    assert kek1 != kek2


def test_derive_kek_rejects_unsupported_algorithm():
    params = KDFParams(algorithm="scrypt")
    with pytest.raises(ValueError, match="Unsupported KDF algorithm"):
        derive_kek("password", params)


@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_generate_dek_has_correct_size(backend_name):
    from credmgr.crypto.registry import get_backend
    dek = generate_dek(backend_name)
    assert len(dek) == get_backend(backend_name).key_size


@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_wrap_and_unwrap_dek_round_trip(backend_name):
    kek = generate_dek(backend_name)  # any correctly-sized key works as a KEK too
    dek = generate_dek(backend_name)

    wrapped = wrap_dek(dek, kek, backend_name)
    assert "ciphertext" in wrapped

    unwrapped = unwrap_dek(wrapped, kek, backend_name)
    assert unwrapped == dek


@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_unwrap_dek_wrong_kek_fails(backend_name):
    from credmgr.crypto.exceptions import DecryptionError

    kek = generate_dek(backend_name)
    other_kek = generate_dek(backend_name)
    dek = generate_dek(backend_name)

    wrapped = wrap_dek(dek, kek, backend_name)
    with pytest.raises(DecryptionError):
        unwrap_dek(wrapped, other_kek, backend_name)


@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_encrypt_and_decrypt_blob_round_trip(backend_name):
    dek = generate_dek(backend_name)
    plaintext = b'{"services": {}}'

    blob = encrypt_blob(dek, plaintext, backend_name)
    assert "ciphertext" in blob

    recovered = decrypt_blob(dek, blob, backend_name)
    assert recovered == plaintext


@pytest.mark.parametrize("backend_name", BACKEND_NAMES)
def test_decrypt_blob_wrong_dek_fails(backend_name):
    from credmgr.crypto.exceptions import DecryptionError

    dek = generate_dek(backend_name)
    other_dek = generate_dek(backend_name)
    blob = encrypt_blob(dek, b"secret contents", backend_name)

    with pytest.raises(DecryptionError):
        decrypt_blob(other_dek, blob, backend_name)
