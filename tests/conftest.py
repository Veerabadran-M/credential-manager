"""Shared fixtures.

Every test gets a fresh `Configuration` pointed at a throwaway temp
directory, so tests never touch a real ~/.credmgr or interfere with each
other via the session cache.
"""

from __future__ import annotations

import pytest

from credmgr.config import Configuration

@pytest.fixture
def config(tmp_path):
    cfg = Configuration()
    cfg.master_dir = tmp_path / ".credmgr"
    return cfg

@pytest.fixture
def available_backend_name():
    """The first backend name guaranteed to be installed in the test env."""
    from credmgr.crypto.registry import available_backends

    backends = available_backends()
    assert backends, "No crypto backend installed -- install at least one for testing"
    return sorted(backends)[0]