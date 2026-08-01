"""Password and passphrase generation.

Security: uses the `secrets` module (CSPRNG) throughout, never `random`.
"""

from __future__ import annotations

import secrets
import string

from .config import Configuration, config as _default_config
_default_config: Configuration
from .wordlist import load_word_list

def generate_password(length: int) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Guarantee at least one of each character class.
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in string.punctuation for c in pwd)
        ):
            return pwd

def generate_passphrase(num_words: int, config=None) -> str:
    words = load_word_list(config or _default_config)
    return "-".join(secrets.choice(words) for _ in range(num_words))