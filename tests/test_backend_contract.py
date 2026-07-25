"""Every backend plugin must satisfy the exact same contract: round-trip
encrypt/decrypt correctly, reject tampered ciphertext with the *same*
exception type regardless of which library implements it, and respect its
own declared key/nonce sizes.
"""

from __future__ import annotations

import pytest

from credmgr.crypto.exceptions import DecryptionError
from credmgr.crypto.registry import available_backends, get_backend

BACKEND_NAMES = available_backends()

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_round_trip(name):
    backend = get_backend(name)
    key = backend.generate_key()
    assert len(key) == backend.key_size

    plaintext = b"correct horse battery staple"
    aad = b"credmgr-vault"

    ciphertext = backend.encrypt(key, plaintext, aad)
    assert ciphertext != plaintext

    recovered = backend.decrypt(key, ciphertext, aad)
    assert recovered == plaintext

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_round_trip_without_aad(name):
    backend = get_backend(name)
    key = backend.generate_key()
    plaintext = b"no aad this time"

    ciphertext = backend.encrypt(key, plaintext, None)
    assert backend.decrypt(key, ciphertext, None) == plaintext

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_tampered_ciphertext_raises_decryption_error(name):
    backend = get_backend(name)
    key = backend.generate_key()
    ciphertext = bytearray(backend.encrypt(key, b"secret data", b"aad"))
    ciphertext[-1] ^= 0xFF  # flip a bit in the authentication tag/ciphertext

    with pytest.raises(DecryptionError):
        backend.decrypt(key, bytes(ciphertext), b"aad")

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_wrong_key_raises_decryption_error(name):
    backend = get_backend(name)
    key = backend.generate_key()
    other_key = backend.generate_key()
    ciphertext = backend.encrypt(key, b"secret data", b"aad")

    with pytest.raises(DecryptionError):
        backend.decrypt(other_key, ciphertext, b"aad")

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_mismatched_aad_raises_decryption_error(name):
    backend = get_backend(name)
    key = backend.generate_key()
    ciphertext = backend.encrypt(key, b"secret data", b"correct-aad")

    with pytest.raises(DecryptionError):
        backend.decrypt(key, ciphertext, b"wrong-aad")

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_backend_metadata_is_well_formed(name):
    backend = get_backend(name)
    assert backend.name == name
    assert isinstance(backend.algorithm, str) and backend.algorithm
    assert backend.key_size > 0
    assert backend.nonce_size > 0
    assert isinstance(backend.pip_extra, str) and backend.pip_extra
    assert backend.is_available() is True

@pytest.mark.parametrize("name", BACKEND_NAMES)
def test_generate_key_is_random(name):
    backend = get_backend(name)
    keys = {backend.generate_key() for _ in range(5)}
    assert len(keys) == 5  # vanishingly unlikely to collide if truly random