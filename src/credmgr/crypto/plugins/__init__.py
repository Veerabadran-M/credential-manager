"""Bundled encryption backend plugins.

Each module defines one or more EncryptionBackend subclasses, discovered
automatically by crypto/registry.py via pkgutil. Adding a backend only
requires dropping a new module here.
"""