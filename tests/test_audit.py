"""Tests for the password health audit: duplicate/weak/reused/old/breached
password detection.
"""

from __future__ import annotations

import hashlib
import time

import pytest

from credmgr.audit import (COMMON_PASSWORDS, find_breached, find_duplicates,
                            find_old, find_reused, load_breach_hashes,
                            load_common_passwords, load_sequences,
                            run_audit, weakness_reasons)
from credmgr.models import Account, Credentials, PasswordHistoryEntry


# ---- weakness_reasons ----

def test_weakness_reasons_flags_too_short_password():
    reasons = weakness_reasons("Ab1!")
    assert "too short (<8 characters)" in reasons


def test_weakness_reasons_flags_short_but_not_too_short():
    reasons = weakness_reasons("Abcdefg1!")  # 9 chars: short but not "too short"
    assert "short (<12 characters)" in reasons
    assert "too short (<8 characters)" not in reasons


def test_weakness_reasons_strong_password_has_no_reasons():
    reasons = weakness_reasons("Xk9#mQ2$vL7pW4z@")
    assert reasons == []


def test_weakness_reasons_flags_common_password():
    reasons = weakness_reasons("password")
    assert "common password" in reasons


def test_weakness_reasons_common_password_check_is_case_insensitive():
    reasons = weakness_reasons("PASSWORD")
    assert "common password" in reasons


def test_weakness_reasons_flags_low_character_diversity():
    reasons = weakness_reasons("alllowercaseletters")
    assert "low character diversity" in reasons


def test_weakness_reasons_flags_repeated_characters():
    reasons = weakness_reasons("Aaaa1111!!!!xyz")
    assert "repeated characters" in reasons


def test_weakness_reasons_flags_sequential_pattern():
    reasons = weakness_reasons("myPass1234word!")
    assert "sequential/keyboard pattern" in reasons


def test_weakness_reasons_respects_custom_common_passwords_and_sequences():
    reasons = weakness_reasons("Custom1!Weak", common_passwords={"custom1!weak"}, sequences=())
    assert "common password" in reasons


# ---- find_duplicates ----

def test_find_duplicates_detects_shared_password_across_accounts():
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="shared", notes="")]
    creds.services["b"] = [Account(userid="u2", password="shared", notes="")]
    creds.services["c"] = [Account(userid="u3", password="unique", notes="")]

    dupes = find_duplicates(creds)
    assert list(dupes.keys()) == ["shared"]
    locations = set(dupes["shared"])
    assert locations == {("a", "u1"), ("b", "u2")}


def test_find_duplicates_no_duplicates_returns_empty_dict():
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="one", notes="")]
    creds.services["b"] = [Account(userid="u2", password="two", notes="")]
    assert find_duplicates(creds) == {}


# ---- find_reused ----

def test_find_reused_detects_password_matching_history():
    creds = Credentials()
    acc = Account(userid="u1", password="old-pw", notes="")
    acc.history.append(PasswordHistoryEntry(password="old-pw", changed_at=time.time()))
    creds.services["a"] = [acc]

    assert find_reused(creds) == [("a", "u1")]


def test_find_reused_no_history_match_returns_empty():
    creds = Credentials()
    acc = Account(userid="u1", password="new-pw", notes="")
    acc.history.append(PasswordHistoryEntry(password="old-pw", changed_at=time.time()))
    creds.services["a"] = [acc]

    assert find_reused(creds) == []


# ---- find_old ----

def test_find_old_flags_password_older_than_max_age():
    creds = Credentials()
    old_time = time.time() - (100 * 86400)
    creds.services["a"] = [Account(userid="u1", password="p", notes="", updated_at=old_time)]

    old = find_old(creds, max_age_days=90)
    assert len(old) == 1
    assert old[0][0] == "a"
    assert old[0][1] == "u1"
    assert old[0][2] > 90


def test_find_old_does_not_flag_recent_password():
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="p", notes="", updated_at=time.time())]
    assert find_old(creds, max_age_days=90) == []


# ---- breach hashes ----

def test_load_breach_hashes_returns_none_for_missing_file(tmp_path):
    assert load_breach_hashes(tmp_path / "nonexistent.txt") is None


def test_load_breach_hashes_parses_plain_lines(tmp_path):
    path = tmp_path / "breach.txt"
    path.write_text("ABCDEF\nabcdef\n123456\n", encoding="utf-8")
    hashes = load_breach_hashes(path)
    assert hashes == {"ABCDEF", "123456"}


def test_load_breach_hashes_parses_hibp_style_lines(tmp_path):
    path = tmp_path / "breach.txt"
    path.write_text("ABCDEF:5\nGHIJKL:100\n", encoding="utf-8")
    hashes = load_breach_hashes(path)
    assert hashes == {"ABCDEF", "GHIJKL"}


def test_find_breached_detects_matching_hash():
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="leaked", notes="")]
    digest = hashlib.sha1(b"leaked").hexdigest().upper()

    assert find_breached(creds, {digest}) == [("a", "u1")]


def test_find_breached_no_match():
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="safe-password", notes="")]
    assert find_breached(creds, {"DEADBEEF"}) == []


# ---- load_common_passwords / load_sequences fallback ----

def test_load_common_passwords_falls_back_when_missing(config):
    assert load_common_passwords(config) == COMMON_PASSWORDS


def test_load_common_passwords_uses_fetched_file(config):
    config.data_dir.mkdir(parents=True, exist_ok=True)
    config.common_passwords_file.write_text("hunter2\nletme1n\n", encoding="utf-8")
    assert load_common_passwords(config) == {"hunter2", "letme1n"}


def test_load_sequences_falls_back_when_missing(config):
    from credmgr.audit import _SEQUENCES
    assert load_sequences(config) == _SEQUENCES


# ---- run_audit (integration of all checks) ----

def test_run_audit_without_breach_db_marks_unavailable(config):
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="Xk9#mQ2$vL7pW4z@", notes="")]

    report = run_audit(creds, config)
    assert report.breach_db_available is False
    assert report.breached == []


def test_run_audit_with_breach_db_flags_breached_password(config):
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="leaked-pw", notes="")]

    config.data_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha1(b"leaked-pw").hexdigest().upper()
    config.breach_db_file.write_text(digest + "\n", encoding="utf-8")

    report = run_audit(creds, config)
    assert report.breach_db_available is True
    assert ("a", "u1") in report.breached


def test_run_audit_aggregates_weak_passwords(config):
    creds = Credentials()
    creds.services["a"] = [Account(userid="u1", password="123", notes="")]

    report = run_audit(creds, config)
    assert len(report.weak) == 1
    assert report.weak[0][0] == "a"
    assert report.weak[0][1] == "u1"
    assert len(report.weak[0][2]) > 0
