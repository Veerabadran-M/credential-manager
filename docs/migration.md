# Migration

`credmgr` distinguishes two kinds of migration, each solving a different
problem and living in a different code path. This page covers both.

| Kind | Trigger | Needs the master password? | Code |
|---|---|---|---|
| [Vault format version](#vault-format-version) | Automatic, on read | No — `Vault` only checks the field | n/a (see below) |
| [Crypto backend](#crypto-backend-migration) | Manual — `credmgr migrate` | Yes — re-encrypts vault contents | `vault.migrate_backend()` |

## Vault format version

`vault.json`'s `version` field identifies the on-disk layout described in
[vault-format.md](vault-format.md); the current and, so far, only
released layout is Vault Format v1 (`vault.CURRENT_VERSION == 1`). There
is no migration machinery for this field today — `Vault` simply refuses
to open a vault whose `version` is newer than the running build supports
(see [Upgrading `credmgr` itself](#upgrading-credmgr-itself) below). A
future format change would add explicit version-migration handling here,
keyed off that field.

## Crypto backend migration

Switching which algorithm encrypts a vault's contents is a deliberate,
user-initiated operation, independent of the vault format version above:

```bash
credmgr migrate --backend xchacha-pynacl
```

This is covered in detail, including the exact sequence of operations
and what it does and doesn't write to disk, in
[crypto.md](crypto.md#migrating-between-backends).

## Moving data between schemas

There is currently no built-in converter between schemas (e.g.
`credentials` → `env`). To move data across schemas, use each schema's
`export`/`import` commands and reshape the exported data by hand, or
write a small script against the schema's documented format (see
[plugin-system.md](plugin-system.md#bundled-schemas)).

## Upgrading `credmgr` itself

A vault whose `version` is newer than the running build supports raises
a clear error asking you to upgrade:

```
Vault version 2 is newer than the version this build of credmgr supports (1). Please upgrade credmgr.
```

There is no downgrade path — always back up `vault.json`/`vault.bak`
(or use `credmgr export`) before upgrading across a major version.
