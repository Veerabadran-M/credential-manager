"""Plugin discovery and lookup for vault schemas.

Mirrors credmgr/crypto/registry.py: the only module that walks
schemas/plugins/. Everything else looks up a schema by name (get_schema)
or lists all known schemas (all_schemas). A plugin that fails to import
is skipped rather than crashing the app.
"""

from __future__ import annotations

import importlib
import pkgutil

from .base import Schema

class UnknownSchemaError(Exception):
    pass

_registry: dict[str, type[Schema]] = {}
_discovered = False

def register(schema_cls: type[Schema]) -> None:
    """Register a schema class under its `.name`. Last registration for a
    given name wins, which lets tests inject fakes without ceremony."""
    _registry[schema_cls.name] = schema_cls

def _discover() -> None:
    """Import every module under credmgr.schemas.plugins and register any
    Schema subclasses found in it. Safe to call repeatedly."""
    global _discovered
    if _discovered:
        return

    from . import plugins as plugins_pkg

    for _finder, module_name, _is_pkg in pkgutil.iter_modules(plugins_pkg.__path__):
        try:
            module = importlib.import_module(f"{plugins_pkg.__name__}.{module_name}")
        except Exception:
            # A broken schema plugin must never take down the whole app.
            continue

        for attr_value in vars(module).values():
            if (isinstance(attr_value, type)
                and issubclass(attr_value, Schema)
                and attr_value is not Schema):
                register(attr_value)

    _discovered = True

def all_schemas() -> list[str]:
    """Every registered schema name."""
    _discover()
    return list(_registry)

def get_schema(name: str) -> Schema:
    """Look up a schema by name and return a ready-to-use instance.

    Raises UnknownSchemaError if no plugin registers that name.
    """
    _discover()
    try:
        schema_cls = _registry[name]
    except KeyError:
        known = ", ".join(sorted(_registry)) or "(none registered)"
        raise UnknownSchemaError(f"Unknown schema '{name}'. Known schemas: {known}")
    return schema_cls()
