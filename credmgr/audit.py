"""Password health audit.

Checks performed:
  - duplicate passwords   (same password reused across different accounts)
  - weak passwords        (short, common, low character diversity, patterns)
  - reused passwords      (current password matches one of that account's own history)
  - old passwords         (not changed within config.password_max_age_days)
  - breached passwords    (matched against a local, offline SHA-1 hash database)

The common-password, sequence-pattern, and breach-hash datasets are fetched
by `credmgr init` (see datasources.py) into `<master_dir>/data/`. The
constants below are only the small fallback used when those files are
missing -- e.g. an offline first run.

Adding a new check: write a `find_*` function and wire it into run_audit()
and AuditReport.
"""

from __future__ import annotations

import hashlib
import re
import string
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .models import Credentials

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "letmein", "admin",
    "welcome", "monkey", "dragon", "football", "iloveyou", "abc123",
    "111111", "123123", "password1", "1234567890", "qwerty123",
    "sunshine", "princess", "trustno1"
}

_SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm")

def load_common_passwords(config) -> set:
    """Returns the fetched common-passwords set from
    `config.common_passwords_file` if present and non-empty, otherwise the
    small bundled COMMON_PASSWORDS fallback."""
    try:
        text = config.common_passwords_file.read_text(encoding="utf-8")
        passwords = {line.strip().lower() for line in text.splitlines() if line.strip()}
        if passwords:
            return passwords
    except OSError:
        pass
    return COMMON_PASSWORDS

def load_sequences(config) -> tuple:
    """Returns the fetched sequence patterns from `config.sequences_file`
    if present and non-empty, otherwise the small bundled _SEQUENCES
    fallback."""
    try:
        text = config.sequences_file.read_text(encoding="utf-8")
        sequences = tuple(line.strip().lower() for line in text.splitlines() if line.strip())
        if sequences:
            return sequences
    except OSError:
        pass
    return _SEQUENCES

@dataclass
class AuditReport:
    duplicates: dict = field(default_factory=dict)
    weak: list = field(default_factory=list)
    reused: list = field(default_factory=list)
    old: list = field(default_factory=list)
    breached: list = field(default_factory=list)
    breach_db_available: bool = False

def _has_sequence(password: str, sequences=_SEQUENCES, min_run: int = 4) -> bool:
    lowered = password.lower()
    for seq in sequences:
        for i in range(len(seq) - min_run + 1):
            if seq[i:i + min_run] in lowered:
                return True
    return False

def weakness_reasons(password: str, common_passwords=None, sequences=None) -> list:
    common_passwords = COMMON_PASSWORDS if common_passwords is None else common_passwords
    sequences = _SEQUENCES if sequences is None else sequences

    reasons = []

    if len(password) < 12:
        reason = "short (<12 characters)" if len(password) > 8 else "too short (<8 characters)"
        reasons.append(reason)

    if password.lower() in common_passwords:
        reasons.append("common password")

    classes = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password)
    ])
    if classes < 3:
        reasons.append("low character diversity")

    if re.search(r"(.)\1{2,}", password):
        reasons.append("repeated characters")

    if _has_sequence(password, sequences):
        reasons.append("sequential/keyboard pattern")

    return reasons

def find_duplicates(creds: Credentials) -> dict:
    by_password = defaultdict(list)
    for service, accounts in creds.services.items():
        for acc in accounts:
            by_password[acc.password].append((service, acc.userid))
    return {pw: locs for pw, locs in by_password.items() if len(locs) > 1}

def find_reused(creds: Credentials) -> list:
    reused = []
    for service, accounts in creds.services.items():
        for acc in accounts:
            past_passwords = {h.password for h in acc.history}
            if acc.password in past_passwords:
                reused.append((service, acc.userid))
    return reused

def find_old(creds: Credentials, max_age_days: int) -> list:
    now = time.time()
    old = []
    for service, accounts in creds.services.items():
        for acc in accounts:
            age_days = (now - acc.updated_at) / 86400
            if age_days > max_age_days:
                old.append((service, acc.userid, age_days))
    return old

def load_breach_hashes(path: Path):
    """Loads a flat file of SHA-1 password hashes, one per line.

    Supports plain "HASH" lines or HIBP-style "HASH:count" lines (the count
    is ignored). Returns None if the file doesn't exist, so callers can
    distinguish "no database configured" from "database has zero hashes".
    """
    if not path.exists():
        return None

    hashes = set()
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            hashes.add(line.split(":")[0].strip().upper())
    return hashes

def find_breached(creds: Credentials, breach_hashes: set) -> list:
    hits = []
    for service, accounts in creds.services.items():
        for acc in accounts:
            digest = hashlib.sha1(acc.password.encode("utf-8")).hexdigest().upper()
            if digest in breach_hashes:
                hits.append((service, acc.userid))
    return hits

def run_audit(creds: Credentials, config) -> AuditReport:
    report = AuditReport()

    common_passwords = load_common_passwords(config)
    sequences = load_sequences(config)

    report.duplicates = find_duplicates(creds)
    report.reused = find_reused(creds)
    report.old = find_old(creds, config.password_max_age_days)

    for service, accounts in creds.services.items():
        for acc in accounts:
            reasons = weakness_reasons(acc.password, common_passwords, sequences)
            if reasons:
                report.weak.append((service, acc.userid, reasons))

    breach_hashes = load_breach_hashes(Path(config.breach_db_file))
    if breach_hashes is not None:
        report.breach_db_available = True
        report.breached = find_breached(creds, breach_hashes)

    return report