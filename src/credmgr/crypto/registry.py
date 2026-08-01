"""Plugin discovery and lookup for encryption backends.

The only module that walks crypto/plugins/. Everything else looks up a
backend by name (get_backend), lists usable backends
(available_backends), or gets the default (default_backend /
resolve_backend). Discovery is defensive: a plugin that fails to import
is skipped rather than crashing the app.
"""

from __future__ import annotations

import importlib
import os
import pkgutil

from .base import EncryptionBackend
from .exceptions import BackendUnavailableError, UnknownBackendError

# Preference order used by default_backend() when several backends are
# available and nothing more specific (CLI/env/config) picked one.
_PREFERENCE_ORDER = [
    "xchacha-pynacl",
    "aesgcm-pycryptodome",
    "aesgcm-cryptography"
]

ENV_VAR = "CREDMGR_BACKEND"

_registry: dict[str, type[EncryptionBackend]] = {}
_discovered = False

def register(backend_cls: type[EncryptionBackend]) -> None:
    """Register a backend class under its `.name`. Last registration for a
    given name wins, which lets tests inject fakes without ceremony."""
    _registry[backend_cls.name] = backend_cls

def _discover() -> None:
    """Import every module under credmgr.crypto.plugins and register any
    EncryptionBackend subclasses found in it. Safe to call repeatedly."""
    global _discovered
    if _discovered:
        return

    from . import plugins as plugins_pkg

    for _finder, module_name, _is_pkg in pkgutil.iter_modules(plugins_pkg.__path__):
        try:
            module = importlib.import_module(f"{plugins_pkg.__name__}.{module_name}")
        except Exception:
            # A broken/half-installed dependency, syntax error in a third-party plugin, etc. must never take down the app.
            continue

        for attr_value in vars(module).values():
            if (isinstance(attr_value, type)
                and issubclass(attr_value, EncryptionBackend)
                and attr_value is not EncryptionBackend):
                register(attr_value)

    _discovered = True

def all_backends() -> list[str]:
    """Every registered backend name, regardless of availability."""
    _discover()
    return list(_registry)

def available_backends() -> list[str]:
    """Registered backend names whose dependency is actually installed."""
    _discover()
    names = []
    for name, backend_cls in _registry.items():
        try:
            if backend_cls.is_available():
                names.append(name)
        except Exception:
            # A misbehaving is_available() must not be able to crash discovery.
            continue
    return names

def get_backend(name: str) -> type[EncryptionBackend]:
    """Look up a backend by name and verify it's actually usable.

    Raises UnknownBackendError if no plugin registers that name, or
    BackendUnavailableError (with a ready-to-run pip install hint) if the
    plugin is registered but its dependency isn't installed.
    """
    _discover()
    try:
        backend_cls = _registry[name]
    except KeyError:
        known = ", ".join(sorted(_registry)) or "(none registered)"
        raise UnknownBackendError(f"Unknown backend '{name}'. Known backends: {known}")

    if not backend_cls.is_available():
        raise BackendUnavailableError(
            f"The credential database uses backend '{name}', but its dependency "
            f"is not installed.\nInstall it using:\n"
            f"  pip install credmgr[{backend_cls.pip_extra}]"
        )
    return backend_cls

def default_backend() -> str:
    """The backend to use when nothing more specific was requested.

    Picks the first available backend in _PREFERENCE_ORDER, falling back to
    any other available backend if none of the preferred ones are usable.
    Raises BackendUnavailableError if no backend is available at all (e.g.
    a bare install with no optional crypto dependency).
    """
    available = set(available_backends())
    for name in _PREFERENCE_ORDER:
        if name in available:
            return name
    if available:
        return sorted(available)[0]

    raise BackendUnavailableError(
        "No cryptographic backend is available. Install at least one of:\n"
        "  pip install credmgr[cryptography]\n"
        "  pip install credmgr[pynacl]\n"
        "  pip install credmgr[pycryptodome]\n"
        "or simply:\n"
        "  pip install credmgr[all]"
    )

def resolve_backend(cli_value: str | None = None, config_value: str | None = None) -> str:
    """Resolve which backend name to use, honoring the documented priority:

        CLI option > environment variable > config file > built-in default

    `cli_value` and `config_value` are passed in by the caller (cli.py /
    config.py) so this module doesn't need to import either of them.
    """
    if cli_value:
        return cli_value

    env_value = os.environ.get(ENV_VAR)
    if env_value:
        return env_value

    if config_value:
        return config_value

    return default_backend()