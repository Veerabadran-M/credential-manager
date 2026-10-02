"""`credmgr generate -spl <chars>` through the real Typer app."""

from __future__ import annotations

import re
import string

from typer.testing import CliRunner

from credmgr.cli import app

runner = CliRunner()

def _password(output: str) -> str:
    return re.search(r"Password:\s+(\S+)", output).group(1)

def test_spl_restricts_special_characters():
    for _ in range(25):
        result = runner.invoke(app, ["generate", "-spl", "!@#", "--length", "30"])
        assert result.exit_code == 0, result.output
        pwd = _password(result.output)
        assert len(pwd) == 30
        assert {c for c in pwd if c in string.punctuation} <= set("!@#")

def test_long_form_alias():
    result = runner.invoke(app, ["generate", "--special-chars", "$%"])
    assert result.exit_code == 0
    assert {c for c in _password(result.output) if c in string.punctuation} <= set("$%")

def test_spl_value_starting_with_dash():
    result = runner.invoke(app, ["generate", "-spl=-_", "--length", "24"])
    assert result.exit_code == 0
    assert {c for c in _password(result.output) if c in string.punctuation} <= set("-_")

def test_spl_empty_means_alphanumeric_only():
    result = runner.invoke(app, ["generate", "-spl", "", "--length", "24"])
    assert result.exit_code == 0
    assert _password(result.output).isalnum()

def test_spl_rejects_letters_and_digits():
    result = runner.invoke(app, ["generate", "-spl", "a1"])
    assert result.exit_code != 0
    assert "not allowed" in result.output

def test_spl_with_passphrase_is_an_error():
    result = runner.invoke(app, ["generate", "--passphrase", "-spl", "!"])
    assert result.exit_code != 0

def test_default_still_uses_all_punctuation_classes():
    result = runner.invoke(app, ["generate", "--length", "40"])
    pwd = _password(result.output)
    assert any(c in string.punctuation for c in pwd)
