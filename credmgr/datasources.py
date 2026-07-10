"""Fetches the bundled security datasets -- wordlist, common passwords,
keyboard-sequence patterns, and breached-password hashes -- from public,
well-known sources and stores them under `<master_dir>/data/`.

Run automatically during `credmgr init`. Every consumer (wordlist.py,
audit.py) falls back to a small built-in default if a file is missing or
a download fails, so the tool stays fully usable offline / air-gapped --
fetching just upgrades those defaults to much larger, real-world datasets.

Sources used:
  - wordlist.txt:          Google's 10,000 most common English words
                            (first20hours/google-10000-english on GitHub),
                            filtered to 4-8 letter alphabetic words.
  - common_passwords.txt:  SecLists' "10k-most-common.txt" password list
                            (danielmiessler/SecLists on GitHub).
  - breached_hash.txt:     SHA-1 hashes computed locally from SecLists'
                            "Pwdb_top-100000.txt" -- a curated list of the
                            100,000 most common real-world breached
                            passwords. (The full HIBP corpus is hundreds of
                            millions of hashes / multiple gigabytes, so we
                            hash a sizeable, well-known subset instead of
                            downloading the entire dump.)
  - sequences.txt:         Common keyboard/numeric walk patterns (e.g.
                            "qwerty", "0123456789"). There's no canonical
                            public dataset for these, so they're bundled
                            directly rather than fetched, but still written
                            into data/ for a consistent layout.
"""

from __future__ import annotations

import hashlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

USER_AGENT = "credmgr-init/2.0"
TIMEOUT = 20

WORDLIST_URL = "https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt"
COMMON_PASSWORDS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
BREACH_SOURCE_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-100000.txt"

BUNDLED_SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "qazwsx", "1q2w3e4r")

@dataclass
class FetchResult:
    name: str
    ok: bool
    detail: str = ""

def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.read()

def _fetch_wordlist(dest: Path) -> FetchResult:
    try:
        raw = _http_get(WORDLIST_URL).decode("utf-8", errors="ignore")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return FetchResult("wordlist", False, str(e))

    seen = set()
    words = []
    for line in raw.splitlines():
        w = line.strip().lower()
        if 4 <= len(w) <= 8 and w.isalpha() and w not in seen:
            seen.add(w)
            words.append(w)

    if not words:
        return FetchResult("wordlist", False, "no usable words in response")

    dest.write_text("\n".join(words) + "\n", encoding="utf-8")
    return FetchResult("wordlist", True, f"{len(words)} words")

def _fetch_common_passwords(dest: Path) -> FetchResult:
    try:
        raw = _http_get(COMMON_PASSWORDS_URL).decode("utf-8", errors="ignore")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return FetchResult("common_passwords", False, str(e))

    passwords = [line.strip().lower() for line in raw.splitlines() if line.strip()]
    if not passwords:
        return FetchResult("common_passwords", False, "empty response")

    dest.write_text("\n".join(passwords) + "\n", encoding="utf-8")
    return FetchResult("common_passwords", True, f"{len(passwords)} passwords")

def _write_sequences(dest: Path) -> FetchResult:
    dest.write_text("\n".join(BUNDLED_SEQUENCES) + "\n", encoding="utf-8")
    return FetchResult("sequences", True, f"{len(BUNDLED_SEQUENCES)} patterns (bundled)")

def _fetch_breached_hashes(dest: Path) -> FetchResult:
    try:
        raw = _http_get(BREACH_SOURCE_URL).decode("utf-8", errors="ignore")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return FetchResult("breached_hash", False, str(e))

    passwords = [line.strip() for line in raw.splitlines() if line.strip()]
    if not passwords:
        return FetchResult("breached_hash", False, "empty response")

    hashes = {hashlib.sha1(pw.encode("utf-8")).hexdigest().upper() for pw in passwords}
    dest.write_text("\n".join(sorted(hashes)) + "\n", encoding="utf-8")
    return FetchResult("breached_hash", True, f"{len(hashes)} hashes")

def fetch_all(config) -> list:
    """Populate `<master_dir>/data/` with all four datasets.

    Returns a list of FetchResult, one per dataset, so callers can report
    per-file success/failure. Never raises: network failures are reported,
    not fatal, since every consumer has a small built-in fallback.
    """
    config.data_dir.mkdir(parents=True, exist_ok=True)

    return [
        _fetch_wordlist(config.wordlist_file),
        _fetch_common_passwords(config.common_passwords_file),
        _write_sequences(config.sequences_file),
        _fetch_breached_hashes(config.breach_db_file)
    ]