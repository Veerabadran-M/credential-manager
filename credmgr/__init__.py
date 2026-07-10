"""credmgr: a local, envelope-encrypted credential manager.

Package layout
--------------
credmgr/
    models.py       Account / Credentials / history data models
    config.py       Runtime configuration (defaults + persisted overrides)
    crypto/
        ciphers.py  AEAD cipher backends (AES-256-GCM, XChaCha20-Poly1305)
        envelope.py Envelope encryption primitives (KDF, DEK wrap/unwrap)
    vault.py        Versioned, encrypted vault file I/O + migrations
    auth.py         Master-password authentication + session DEK caching
    generator.py    Password / passphrase generation
    wordlist.py     Word list used by the passphrase generator
    search.py       Fuzzy + global search across the vault
    audit.py        Password health audit (weak/duplicate/reused/old/breached)
    clipboard.py    Clipboard copy with auto-clear
    ui.py           Terminal rendering helpers (rich)
    cli.py          Argument parsing and command dispatch

Extending credmgr
-----------------
- New cipher:        add a class to crypto/ciphers.py and register it in CIPHERS.
- New vault version:  bump vault.CURRENT_VERSION and add an entry to vault.MIGRATIONS.
- New audit check:    add a function to audit.py and wire it into run_audit().
- New command:        add a cmd_* function and a subparser in cli.py.
"""

__version__ = "2.0.0"