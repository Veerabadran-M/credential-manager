"""Exceptions shared by the crypto backend interface, the plugin registry,
and every plugin implementation.

Callers outside this package (vault.py, cli.py, ...) only ever need to catch
these -- never a library-specific exception -- because plugins are required
to translate whatever their underlying library raises into one of these.
"""

from __future__ import annotations

class CryptoError(Exception):
    """Base class for every exception raised by the crypto package."""

class UnknownBackendError(CryptoError):
    """Raised when a backend name doesn't match any registered plugin."""

class BackendUnavailableError(CryptoError):
    """Raised when a backend is registered but its dependency isn't installed.

    Carries a user-facing, actionable message (e.g. 'pip install credmgr[pynacl]')
    rather than a raw ImportError, so it's safe to print directly.
    """

class EncryptionError(CryptoError):
    """Raised when a backend fails to encrypt data."""

class DecryptionError(CryptoError):
    """Raised when a backend fails to decrypt/authenticate data.

    Every plugin normalizes its library's tag-mismatch/auth-failure exception
    (InvalidTag, CryptoError, ValueError, ...) to this single type, so the
    rest of the app can catch one exception regardless of which backend is
    in use.
    """