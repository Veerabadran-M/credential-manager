"""Bundled backend plugins.

Every module in this package is expected to define one or more
EncryptionBackend subclasses. The registry (crypto/registry.py) discovers
them automatically via pkgutil -- nothing needs to be imported or listed
here manually. To add a new backend, drop a new module in this directory;
no other file in the codebase needs to change.
"""