"""Password and passphrase generation.

Security: uses the `secrets` module (CSPRNG) throughout, never `random`.
"""

from __future__ import annotations

import secrets
import string

from .config import Configuration, config as _default_config
_default_config: Configuration
from .wordlist import load_word_list

# Every special character `generate_password` can use by default, and
# the only ones a caller-supplied `special_chars` may draw from.
DEFAULT_SPECIAL_CHARS = string.punctuation

def normalize_special_chars(special_chars: str) -> str:
    """Validate and de-duplicate a caller-supplied special-character set,
    preserving first-seen order. Raises ValueError if it contains
    anything that isn't a printable ASCII symbol (letters, digits,
    whitespace, control and non-ASCII characters are rejected -- letters
    and digits are always part of the alphabet already, and the rest
    would make for passwords many sites silently mangle or refuse)."""
    bad = sorted({c for c in special_chars if c not in string.punctuation})
    if bad:
        shown = " ".join(repr(c) for c in bad)
        raise ValueError(
            f"Special characters must be printable ASCII symbols "
            f"({string.punctuation}); not allowed: {shown}"
        )
    return "".join(dict.fromkeys(special_chars))

def generate_password(length: int, special_chars: str | None = None) -> str:
    """Generate a random password of `length` characters.

    `special_chars=None` (default) draws specials from all of
    `string.punctuation`. A string restricts the specials to exactly
    those characters -- nothing outside it is ever emitted. An empty
    string means "no special characters at all" (letters and digits
    only). Every character class that is in play appears at least
    once.
    """
    specials = DEFAULT_SPECIAL_CHARS if special_chars is None else normalize_special_chars(special_chars)

    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if specials:
        classes.append(specials)

    if length < len(classes):
        raise ValueError(f"Password length must be at least {len(classes)} to include every character class.")

    alphabet = "".join(classes)
    # One guaranteed pick from each class, the rest from the whole
    # alphabet, then a CSPRNG shuffle so the guaranteed ones aren't
    # always in the first positions.
    chars = [secrets.choice(c) for c in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)

def generate_passphrase(num_words: int, config=None) -> str:
    words = load_word_list(config or _default_config)
    return "-".join(secrets.choice(words) for _ in range(num_words))
