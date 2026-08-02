"""Tests for password/passphrase generation and the offline word list
fallback used by it.
"""

from __future__ import annotations

import string

import pytest

from credmgr.generator import generate_passphrase, generate_password
from credmgr.wordlist import WORD_LIST, load_word_list


# ---- generate_password ----

@pytest.mark.parametrize("length", [8, 12, 20, 50])
def test_generate_password_has_requested_length(length):
    assert len(generate_password(length)) == length


def test_generate_password_contains_all_character_classes():
    pwd = generate_password(20)
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in string.punctuation for c in pwd)


def test_generate_password_uses_only_expected_alphabet():
    alphabet = set(string.ascii_letters + string.digits + string.punctuation)
    pwd = generate_password(30)
    assert set(pwd) <= alphabet


def test_generate_password_is_random_across_calls():
    passwords = {generate_password(20) for _ in range(10)}
    assert len(passwords) == 10


def test_generate_password_minimum_length_still_satisfies_all_classes():
    # Length 4 is the minimum where one of each class *can* be satisfied.
    pwd = generate_password(4)
    assert len(pwd) == 4
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in string.punctuation for c in pwd)


# ---- generate_passphrase ----

def test_generate_passphrase_word_count_and_separator():
    phrase = generate_passphrase(5)
    words = phrase.split("-")
    assert len(words) == 5


def test_generate_passphrase_words_come_from_fallback_word_list(config):
    phrase = generate_passphrase(6, config=config)
    for word in phrase.split("-"):
        assert word in WORD_LIST


def test_generate_passphrase_single_word_has_no_separator():
    phrase = generate_passphrase(1)
    assert "-" not in phrase


# ---- load_word_list ----

def test_load_word_list_falls_back_when_file_missing(config):
    words = load_word_list(config)
    assert words == WORD_LIST


def test_load_word_list_uses_fetched_file_when_present(config):
    config.data_dir.mkdir(parents=True, exist_ok=True)
    config.wordlist_file.write_text("alpha\nbravo\ncharlie\n", encoding="utf-8")

    words = load_word_list(config)
    assert words == ["alpha", "bravo", "charlie"]


def test_load_word_list_ignores_blank_lines():
    class FakePath:
        def read_text(self, encoding="utf-8"):
            return "alpha\n\n  \nbravo\n"

    class FakeConfig:
        wordlist_file = FakePath()

    assert load_word_list(FakeConfig()) == ["alpha", "bravo"]


def test_load_word_list_falls_back_when_file_is_empty(config):
    config.data_dir.mkdir(parents=True, exist_ok=True)
    config.wordlist_file.write_text("", encoding="utf-8")

    assert load_word_list(config) == WORD_LIST
