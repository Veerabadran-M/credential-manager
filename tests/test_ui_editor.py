"""Tests for credmgr.cli.ui.open_editor: the subprocess-spawning helper
behind the text schema's editor-based `add`/`update` flow. We never
actually launch a real editor here -- `subprocess.run` is monkeypatched
to simulate one writing to the temp file, or failing in various ways.
"""

from __future__ import annotations

import pytest

import credmgr.cli.ui as ui_mod


class _FakeCompleted:
    def __init__(self, returncode: int = 0):
        self.returncode = returncode


def test_open_editor_returns_edited_content(monkeypatch):
    def fake_run(command):
        path = command[-1]
        with open(path, "w", encoding="utf-8") as f:
            f.write("edited text\n")
        return _FakeCompleted(0)

    monkeypatch.setattr(ui_mod.subprocess, "run", fake_run)
    assert ui_mod.open_editor("fake-editor", "") == "edited text\n"


def test_open_editor_seeds_temp_file_with_initial_text(monkeypatch):
    seen = {}

    def fake_run(command):
        path = command[-1]
        with open(path, "r", encoding="utf-8") as f:
            seen["initial"] = f.read()
        return _FakeCompleted(0)

    monkeypatch.setattr(ui_mod.subprocess, "run", fake_run)
    ui_mod.open_editor("fake-editor", "starting content\n")
    assert seen["initial"] == "starting content\n"


def test_open_editor_removes_temp_file_afterwards(monkeypatch):
    captured_path = {}

    def fake_run(command):
        captured_path["path"] = command[-1]
        return _FakeCompleted(0)

    monkeypatch.setattr(ui_mod.subprocess, "run", fake_run)
    ui_mod.open_editor("fake-editor", "")

    import os
    assert not os.path.exists(captured_path["path"])


def test_open_editor_exits_when_editor_not_found(monkeypatch):
    def fake_run(command):
        raise FileNotFoundError()

    monkeypatch.setattr(ui_mod.subprocess, "run", fake_run)
    with pytest.raises(SystemExit):
        ui_mod.open_editor("does-not-exist", "")


def test_open_editor_exits_on_nonzero_exit_status(monkeypatch):
    monkeypatch.setattr(ui_mod.subprocess, "run", lambda command: _FakeCompleted(1))
    with pytest.raises(SystemExit):
        ui_mod.open_editor("fake-editor", "")


def test_open_editor_respects_multi_word_editor_command(monkeypatch):
    seen = {}

    def fake_run(command):
        seen["command"] = command
        return _FakeCompleted(0)

    monkeypatch.setattr(ui_mod.subprocess, "run", fake_run)
    ui_mod.open_editor("code --wait", "")
    assert seen["command"][:-1] == ["code", "--wait"]
