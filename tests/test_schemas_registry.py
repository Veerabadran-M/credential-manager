"""Tests for schema plugin discovery, lookup, and registration."""

from __future__ import annotations

import pytest

from credmgr.schemas import registry as schema_registry
from credmgr.schemas.base import Schema
from credmgr.schemas.registry import UnknownSchemaError, get_schema


def test_bundled_schemas_are_discovered():
    names = schema_registry.all_schemas()
    assert "credentials" in names
    assert "env" in names


def test_get_schema_returns_instance():
    schema = get_schema("credentials")
    assert schema.name == "credentials"


def test_get_schema_unknown_name_raises():
    with pytest.raises(UnknownSchemaError, match="Unknown schema"):
        get_schema("not-a-real-schema")


def test_register_overrides_existing_entry():
    class FakeSchema(Schema):
        name = "credentials"

        @classmethod
        def new_document(cls):
            return None

        @classmethod
        def parse(cls, plaintext):
            return None

        @classmethod
        def serialize(cls, document):
            return b""

    original = schema_registry._registry.get("credentials")
    try:
        schema_registry.register(FakeSchema)
        assert schema_registry.get_schema("credentials").__class__ is FakeSchema
    finally:
        # Restore the real plugin so other tests aren't affected.
        if original is not None:
            schema_registry.register(original)
