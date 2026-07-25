"""Tests for plugin discovery, lookup, and selection priority."""

from __future__ import annotations

import pytest

from credmgr.crypto.base import EncryptionBackend
from credmgr.crypto.exceptions import BackendUnavailableError, UnknownBackendError
from credmgr.crypto import registry as registry_mod

def test_bundled_plugins_are_discovered():
    names = registry_mod.all_backends()
    assert "aesgcm-cryptography" in names
    assert "xchacha-pynacl" in names
    assert "aesgcm-pycryptodome" in names

def test_available_backends_are_a_subset_of_all_backends():
    assert set(registry_mod.available_backends()) <= set(registry_mod.all_backends())

def test_get_backend_returns_a_class_implementing_the_interface():
    for name in registry_mod.available_backends():
        backend = registry_mod.get_backend(name)
        assert issubclass(backend, EncryptionBackend)

def test_get_backend_unknown_name_raises_unknown_backend_error():
    with pytest.raises(UnknownBackendError):
        registry_mod.get_backend("not-a-real-backend")

def test_get_backend_unavailable_dependency_raises_friendly_error(monkeypatch):
    """A plugin that's registered but whose is_available() reports False must
    produce an actionable message, not a raw ImportError, and must never
    have crashed discovery in the first place."""
    from credmgr.crypto.plugins.xchacha_pynacl import XChaCha20Pynacl

    monkeypatch.setattr(XChaCha20Pynacl, "is_available", classmethod(lambda cls: False))

    with pytest.raises(BackendUnavailableError) as exc_info:
        registry_mod.get_backend("xchacha-pynacl")

    message = str(exc_info.value)
    assert "xchacha-pynacl" in message
    assert "pip install credmgr[pynacl]" in message

def test_unavailable_plugin_is_excluded_from_available_backends(monkeypatch):
    from credmgr.crypto.plugins.xchacha_pynacl import XChaCha20Pynacl

    monkeypatch.setattr(XChaCha20Pynacl, "is_available", classmethod(lambda cls: False))

    assert "xchacha-pynacl" not in registry_mod.available_backends()
    # ... but discovery still knows the plugin exists.
    assert "xchacha-pynacl" in registry_mod.all_backends()

def test_broken_plugin_module_does_not_crash_discovery(monkeypatch, tmp_path):
    """A plugin module that raises on import must be skipped, not propagate."""
    from credmgr.crypto import plugins as plugins_pkg

    broken_module_name = "totally_broken_plugin"
    broken_path = tmp_path / f"{broken_module_name}.py"
    broken_path.write_text("raise ImportError('boom, this plugin is broken')\n")

    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(plugins_pkg, "__path__", list(plugins_pkg.__path__) + [str(tmp_path)])

    # Force re-discovery so the broken module is actually walked.
    monkeypatch.setattr(registry_mod, "_discovered", False)
    monkeypatch.setattr(registry_mod, "_registry", dict(registry_mod._registry))

    # Must not raise.
    names = registry_mod.all_backends()
    assert "aesgcm-cryptography" in names

def test_default_backend_prefers_cryptography_when_available():
    if "aesgcm-cryptography" in registry_mod.available_backends():
        assert registry_mod.default_backend() == "aesgcm-cryptography"

def test_default_backend_raises_when_nothing_is_available(monkeypatch):
    monkeypatch.setattr(registry_mod, "available_backends", lambda: [])
    with pytest.raises(BackendUnavailableError):
        registry_mod.default_backend()

def test_resolve_backend_priority_cli_beats_env_beats_config(monkeypatch):
    monkeypatch.setenv(registry_mod.ENV_VAR, "env-backend")
    assert registry_mod.resolve_backend(cli_value="cli-backend", config_value="config-backend") == "cli-backend"

def test_resolve_backend_priority_env_beats_config(monkeypatch):
    monkeypatch.setenv(registry_mod.ENV_VAR, "env-backend")
    assert registry_mod.resolve_backend(cli_value=None, config_value="config-backend") == "env-backend"

def test_resolve_backend_priority_config_beats_default(monkeypatch):
    monkeypatch.delenv(registry_mod.ENV_VAR, raising=False)
    assert registry_mod.resolve_backend(cli_value=None, config_value="config-backend") == "config-backend"

def test_resolve_backend_falls_back_to_default(monkeypatch):
    monkeypatch.delenv(registry_mod.ENV_VAR, raising=False)
    result = registry_mod.resolve_backend(cli_value=None, config_value=None)
    assert result == registry_mod.default_backend()