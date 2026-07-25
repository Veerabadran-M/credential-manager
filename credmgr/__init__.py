"""credmgr: a local, envelope-encrypted credential manager.

Package layout
--------------
credmgr/
    models.py       Account / Credentials / history data models
    config.py       Runtime configuration (defaults + persisted overrides)
    crypto/         Pluggable AEAD encryption backend system
        base.py         Abstract EncryptionBackend interface
        registry.py     Plugin discovery, lookup, and selection
        exceptions.py   Shared exception types
        envelope.py     Envelope encryption primitives (KDF, DEK wrap/unwrap)
        plugins/        Bundled backend plugins (one file per backend)
    vault.py        Versioned, encrypted vault file I/O + migrations
    auth.py         Master-password authentication + session DEK caching
    generator.py    Password / passphrase generation
    wordlist.py     Word list used by the passphrase generator
    search.py       Fuzzy + global search across the vault
    audit.py        Password health audit (weak/duplicate/reused/old/breached)
    clipboard.py    Clipboard copy with auto-clear
    ui.py           Terminal rendering helpers (rich)
    cli.py          Typer-based argument parsing and command dispatch

Extending credmgr
-----------------
- New crypto backend: add a file to crypto/plugins/ implementing
                       EncryptionBackend and give it a unique `.name` --
                       it's discovered automatically. See crypto/base.py
                       and the README's "Writing custom crypto plugins".
- New vault version:   bump vault.CURRENT_VERSION and add an entry to
                       vault.MIGRATIONS.
- New audit check:     add a function to audit.py and wire it into run_audit().
- New command:         add a cmd_* function and an @app.command() in cli.py.
"""

__version__ = "3.1.0"