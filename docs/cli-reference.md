# CLI Reference

`credmgr` is built with [Typer](https://typer.tiangolo.com/). Run
`credmgr --help` or `credmgr <command> --help` at any time for full,
up-to-date usage — this page is a organized companion, not a replacement.

## Request flow

Every command follows the same generic dispatch path through `cli.py`,
regardless of which schema the active vault uses:

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as cli.py (Typer)
    participant Auth as auth.py
    participant Vault as vault.py
    participant Schema as active schema plugin

    U->>CLI: credmgr add netflix alice --generate
    CLI->>Auth: authenticate()
    Auth->>Vault: unlock() / unlock_with_dek()
    Vault-->>Auth: (DEK, document)
    Auth-->>CLI: (DEK, document, vault)
    CLI->>Schema: get_schema(vault.schema_name)
    CLI->>Schema: cmd_add(document, args, opts, config)
    Schema-->>CLI: mutated (bool)
    alt mutated is True
        CLI->>Vault: save(document, DEK)
        Vault->>Schema: serialize(document)
        Vault-->>U: vault.json re-encrypted and written
    else mutated is False
        CLI-->>U: no write
    end
```

Setup commands (`init`, `passwd`, `migrate`, `config`, `vault ...`) skip
the schema-dispatch step and operate on the vault or config directly.

## Setup & configuration

| Command | Description |
|---|---|
| `credmgr init [--skip-data-fetch] [--backend NAME]` | Initialize the active vault (defaults to a `default` vault with the `credentials` schema) |
| `credmgr fetch-data` | (Re-)download the wordlist / common-passwords / sequences / breach-hash datasets |
| `credmgr passwd` | Change the master password (re-wraps the DEK only; vault contents untouched) |
| `credmgr migrate [--backend NAME]` | Re-encrypt the active vault under a different crypto backend |
| `credmgr config show` | Display current configuration |
| `credmgr config set <key> <value>` | Change a mutable configuration value |
| `credmgr config reset` | Reset configuration to defaults (with confirmation) |

## Vault management

| Command | Description |
|---|---|
| `credmgr vault create <name> [--schema NAME] [--backend NAME]` | Create a new named vault |
| `credmgr vault list` | List all vaults and their schema; `*` marks the active one |
| `credmgr vault current` | Show the active vault's name |
| `credmgr vault use <name>` | Switch the active vault |
| `credmgr vault delete <name>` | Delete a vault (must not be the active one; asks for confirmation) |

## Entry read/write commands (schema-dispatched)

These commands are generic — their exact argument shape depends on the
active vault's schema. Examples below assume the default `credentials`
schema (`<service> [userid]`); for the `env` schema, substitute
`<KEY> [VALUE]`. See [plugin-system.md](plugin-system.md) for schema
details.

| Command | Description |
|---|---|
| `credmgr list` | List all stored entries in the *active* vault |
| `credmgr list-all` | List every service and userid under it *(credentials schema)*, or every key/LHS *(env schema)* — across **every vault on disk**, not just the active one. Prompts for each vault's master password in turn (`*` marks the active vault, same as `vault list`) |
| `credmgr get <service> [userid]` | Display credentials in a table |
| `credmgr search <query>` | Fuzzy search across entries |
| `credmgr copy <service> [userid]` | Copy a value to the clipboard (auto-clears) |
| `credmgr add <service> <userid> [--generate] [--passphrase] [--notes "..."]` | Add an entry |
| `credmgr update <service> <userid> userid <new_userid>` | Rename an account's userid *(credentials schema)* |
| `credmgr update <service> <userid> password [--generate] [--passphrase]` | Change password, old one kept in history *(credentials schema)* |
| `credmgr update <service> <userid> notes "<text>"` | Update notes *(credentials schema)* |
| `credmgr update <KEY> <VALUE>` | Update a value *(env schema)* |
| `credmgr history <service> <userid>` | Show password history for an account *(credentials schema only)* |
| `credmgr delete <service> [userid]` | Delete an account, or a whole service if no userid given |
| `credmgr audit` | Run the password health audit *(credentials schema only)* |
| `credmgr export` | Print the entire vault as plaintext (always re-prompts for the password) |
| `credmgr import <filepath>` | Import entries from a file, skipping duplicates/invalid entries |
| `credmgr generate [--passphrase] [--length N] [--words N]` | Generate a password/passphrase without storing it |

Service/userid lookups (`get`, `copy`, `update`, `delete`, `history`) use
progressively looser matching in the `credentials` schema: exact →
case-insensitive substring → fuzzy (`difflib`, threshold configurable via
`fuzzy_threshold`). Ambiguous matches list candidates instead of guessing.

`list-all` is the one exception to "operates on the active vault only":
it walks every vault returned by `credmgr vault list`, unlocking each in
turn (its own master password, its own schema) before printing that
vault's listing.

## Cross-vault search (`global`)

| Command | Description |
|---|---|
| `credmgr global <query>` | Search a metadata index across **every vault** for `query`, without switching or decrypting the active vault. Once you pick a result, it prompts for that one vault's password and displays the entry. |

```bash
credmgr global github
credmgr global OPENAI_API_KEY
```

Unlike every other entry command, `global` never touches the active
vault. It searches `~/.credmgr/index.json` — a plaintext catalogue of
searchable identifiers only (service names, userids, env keys — never
passwords or keys) that every mutating command (`add`/`update`/`delete`/
`import`/`vault create`/`vault delete`) keeps in sync automatically. If
a vault's contents changed without the index knowing (a fresh install,
a hand-edited `vault.json`, ...), `global` detects that from file
metadata alone and transparently re-indexes just that vault (prompting
for its password) before searching — no vault is ever decrypted just to
search it.

- **No matches** → `No matching entries found.`
- **One match** → shows vault/schema/summary and asks `View this secret? [Y/n]`.
- **Multiple matches** → a numbered list (`vault  schema  <schema-specific summary>`) to pick from.

Whichever way you get there, only the one vault behind your final
selection is ever unlocked — see [plugin-system.md](plugin-system.md)
for how a schema plugin contributes to and resolves entries in the
index.

## Common flags

| Flag | Applies to | Meaning |
|---|---|---|
| `--generate` | `add`, `update`, `generate` | Generate a value instead of prompting |
| `--passphrase` | `add`, `update`, `generate` | Generate a Diceware-style passphrase instead of a random password |
| `--length N` | `add`, `update`, `generate` | Generated password length |
| `--words N` | `add`, `update`, `generate` | Generated passphrase word count |
| `--notes "..."` / `-n` | `add` | Attach notes to a new entry |
| `--backend NAME` | `init`, `vault create`, `migrate` | Choose a crypto backend non-interactively |
| `--schema NAME` | `vault create` | Choose a schema for a new vault (default: `credentials`) |
| `--skip-data-fetch` | `init` | Skip downloading optional security datasets |

## Examples

```bash
# First-time setup
credmgr init

# Everyday credentials use
credmgr add netflix alice --generate
credmgr get netflix alice
credmgr copy netflix alice
credmgr search netflix
credmgr audit

# Multiple vaults with different schemas
credmgr vault create work --schema credentials
credmgr vault create employee --schema env
credmgr vault use employee
credmgr add EMPLOYEE_ID 123456
credmgr vault use default

# Maintenance
credmgr passwd
credmgr migrate --backend aesgcm-cryptography
credmgr config set password_max_age_days 60

# Find something without knowing (or switching to) its vault
credmgr global github
credmgr global OPENAI_API_KEY
```
