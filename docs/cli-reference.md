# CLI Reference

`credmgr` is built with [Typer](https://typer.tiangolo.com/). Run
`credmgr --help` or `credmgr <command> --help` at any time for full,
up-to-date usage — this page is a organized companion, not a replacement.

## Request flow

Every command follows the same generic dispatch path through
`cli/commands.py` and `core/manager.py`, regardless of which schema the
active vault uses:

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as cli/commands.py (Typer)
    participant Core as core/manager.py
    participant Auth as auth.py
    participant Vault as vault.py
    participant Schema as active schema plugin

    U->>CLI: credmgr add netflix alice --generate
    CLI->>Core: CredentialManager.add(args, opts)
    Core->>Core: unlock() (cache hit, or raises PasswordRequired)
    Core->>Auth: authenticate(password)
    Auth->>Vault: unlock() / unlock_with_dek()
    Vault-->>Auth: (DEK, document)
    Auth-->>Core: (DEK, document, vault)
    Core->>Schema: get_schema(vault.schema_name)
    Core->>Schema: cmd_add(document, args, opts, config)
    Schema-->>Core: CommandResult(mutated, lines, ...)
    alt mutated is True
        Core->>Vault: save(document, DEK)
        Vault->>Schema: serialize(document)
        Vault-->>U: vault.json re-encrypted and written
    end
    Core-->>CLI: CommandResult
    CLI-->>U: rendered via cli/ui.py
```

Setup commands (`init`, `passwd`, `migrate`, `config`, `vault ...`) skip
the schema-dispatch step and operate on the vault or config directly, via
their own `CredentialManager` methods.

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
`<KEY> [VALUE]`; for the `text` schema, substitute `[line|start-end]`
(or no args at all — see below). See [plugin-system.md](plugin-system.md)
for schema details.

| Command | Description |
|---|---|
| `credmgr list` | List all stored entries in the *active* vault |
| `credmgr list-all` | List every service and userid under it *(credentials schema)*, or every key *(env schema)* — across **every vault on disk**, not just the active one. Prompts for each vault's master password in turn (`*` marks the active vault, same as `vault list`). Not supported by the `text` schema |
| `credmgr get <service> [userid]` | Display credentials in a table |
| `credmgr search <query>` | Fuzzy search across entries |
| `credmgr copy <service> [userid]` | Copy a value to the clipboard (auto-clears) |
| `credmgr add <service> <userid> [--generate] [--passphrase] [-spl CHARS] [--notes "..."]` | Add an entry |
| `credmgr update <service> <userid> userid <new_userid>` | Rename an account's userid *(credentials schema)* |
| `credmgr update <service> <userid> password [--generate] [--passphrase] [-spl CHARS]` | Change password, old one kept in history *(credentials schema)* |
| `credmgr update <service> <userid> notes "<text>"` | Update notes *(credentials schema)* |
| `credmgr update <service> <userid> account <new_userid> [--generate] [--passphrase] [-spl CHARS]` | Replace both userid and password in one step, old password kept in history *(credentials schema)* |
| `credmgr update <KEY> <VALUE>` | Update a value *(env schema)* |
| `credmgr history <service> <userid>` | Show password history for an account *(credentials schema only)* |
| `credmgr delete <service> [userid]` | Delete an account, or a whole service if no userid given |
| `credmgr audit` | Run the password health audit *(credentials schema only)* |
| `credmgr export` | Print the entire vault as plaintext (always re-prompts for the password) |
| `credmgr import <filepath>` | Import entries from a file, skipping duplicates/invalid entries |
| `credmgr generate [--passphrase] [--length N] [--words N] [-spl CHARS]` | Generate a password/passphrase without storing it |

### The `text` schema

A `text` vault has no keyed entries at all — the decrypted plaintext
*is* the document, so the generic commands above are repurposed around
line numbers purely for convenience:

| Command | Description |
|---|---|
| `credmgr get` | Print the whole vault content |
| `credmgr get <line>` / `credmgr get <start>-<end>` | Print one line or an inclusive range of lines (1-indexed) |
| `credmgr search <text>` | Print every line containing `text` (case-insensitive), with line numbers |
| `credmgr copy` | Copy the entire content to the clipboard |
| `credmgr copy <line>` | Copy just that line |
| `credmgr add <text...>` | Append `text...` as one new line |
| `credmgr add <filepath>` | Upload/append the content of an existing file, verbatim (like `import`) |
| `credmgr add` | Open `config.editor` on a blank temp file; whatever's saved is appended verbatim |
| `credmgr update <text...>` | Replace the entire content with `text...` (pass `""` to clear it without a confirmation prompt) |
| `credmgr update <filepath>` | Replace the entire content with an existing file's content, verbatim |
| `credmgr update` | Open `config.editor` on a temp file pre-filled with the current content, so you edit it in place; whatever's saved replaces the vault |
| `credmgr delete` | Clear the entire content (asks for confirmation first) |
| `credmgr delete <line>` | Remove just that line, no confirmation needed |
| `credmgr import <filepath>` | Append the file's content to whatever is already stored |
| `credmgr export` | Print the raw content exactly as stored |

`add`/`update <filepath>` only kick in when the single argument names a
file that actually exists on disk (`os.path.isfile`) — anything else,
including a nonexistent path, is treated as literal text instead. The
editor used for the no-argument form is `config.editor`, which
defaults to `$VISUAL`, then `$EDITOR`, then a platform default
(`nano`, or `notepad` on Windows); override it with `credmgr config set
editor <command>` (e.g. `vim`, `"code --wait"`).

`list-all`, `history`, and `audit` aren't supported by `text`, and its
vaults don't participate in `credmgr global` or `credmgr transfer` — there are
no identifiers to search or select, only the content itself.

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
| `credmgr global <query>` | Search **every vault** for `query`. Each vault is unlocked in turn, searched in memory, and discarded unless it has a match. |

```bash
credmgr global github
credmgr global OPENAI_API_KEY
```

`global` never touches the active vault and **stores nothing**: there is
no index, catalogue or cache of service names, userids or keys on disk
(earlier versions kept a plaintext `~/.credmgr/index.json`; it is deleted
automatically the next time you run `global` or save any vault). The
trade-off is speed: every searched vault needs its master password (or a
still-valid session key), and each password costs one Argon2 derivation,
so a search takes roughly as long as unlocking all your vaults.

- You are prompted for each vault's master password in turn (vault-name order). Enter nothing to skip that vault; a wrong password skips it with a warning instead of aborting the search.
- `text` vaults can't be searched and are skipped without a prompt.
- **No matches** → `No matching entries found.`
- **One match** → shows vault/schema/summary and asks `View this secret? [Y/n]`.
- **Multiple matches** → a numbered list (`vault  schema  <schema-specific summary>`) to pick from.

Only vaults with at least one match stay unlocked in memory after the
search, so showing the selected secret needs no second prompt. See
[plugin-system.md](plugin-system.md) for how a schema plugin takes part.

## Moving entries between vaults (`transfer`)

| Command | Description |
|---|---|
| `credmgr transfer <src> <dst> <entry...>` | **Move** the selected entries from vault `src` to vault `dst` |
| `credmgr transfer <src> <dst> --all` | Move every entry |
| `... --copy` | Copy instead of move; the source is left untouched |
| `... --overwrite` | Replace entries that already exist in the destination (default: skip them) |

`<entry...>` is whatever that schema's `get`/`delete` take:
`<service> [userid]` for `credentials` (a bare service moves all its
accounts), `<KEY>` for `env`. Both vaults must use the **same schema**
(`credmgr vault list` shows each) — otherwise the command stops before
asking for any password. `text` vaults don't support `transfer`. The
vaults may use different crypto backends and have different master
passwords; you are prompted for both.

```bash
credmgr transfer personal work github alice
credmgr transfer personal work github
credmgr transfer old-env new-env --all --copy
```

Moved entries keep everything: password, notes, password history, and
created/updated timestamps. Safety properties:

- The destination is saved **first**; entries are removed from the source only afterwards, and only the ones actually written to the destination. A failure part-way can leave an entry in both vaults, never in neither.
- Entries that already exist in the destination (same service+userid, or same key) are **skipped and left in the source**, and listed in the output. Re-run with `--overwrite` to replace them.
- A wrong password for either vault aborts the command before anything is changed.

## Generating passwords with a restricted special-character set (`-spl`)

By default generated passwords draw their symbols from all printable ASCII
punctuation. Some sites accept only a few, so:

```bash
credmgr generate --length 20 -spl '!@#_'
credmgr add netflix alice --generate -spl '-_.'
credmgr update github alice password --generate -spl '@'
```

- Passwords contain letters, digits and **only** the symbols you list, with at least one of each class (lowercase, uppercase, digit, and a symbol from your list).
- `-spl ''` means no symbols at all (letters and digits only).
- `CHARS` must be printable ASCII symbols (``!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~``); letters, digits, spaces and non-ASCII characters are rejected. Duplicates are ignored.
- Quote the value in your shell, and use `-spl='-_'` if it starts with `-`.
- Not valid together with `--passphrase`.

## Common flags

| Flag | Applies to | Meaning |
|---|---|---|
| `--generate` | `add`, `update`, `generate` | Generate a value instead of prompting |
| `--passphrase` | `add`, `update`, `generate` | Generate a Diceware-style passphrase instead of a random password |
| `--length N` | `add`, `update`, `generate` | Generated password length |
| `--words N` | `add`, `update`, `generate` | Generated passphrase word count |
| `-spl CHARS` (alias `--special-chars`) | `add`, `update`, `generate` | Restrict generated passwords' special characters to exactly `CHARS` (see below) |
| `--notes "..."` / `-n` | `add` | Attach notes to a new entry |
| `--backend NAME` | `init`, `vault create`, `migrate` | Choose a crypto backend non-interactively |
| `--schema NAME` | `vault create` | Choose a schema for a new vault (default: `credentials`; also `env`, `text`) |
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

# A vault that's just an encrypted text file
credmgr vault create notes --schema text
credmgr vault use notes
credmgr add "server root password is in the safe"
credmgr add ./private-key.pem       # uploads the file's content
credmgr config set editor vim       # or "code --wait", etc. (default: $VISUAL/$EDITOR)
credmgr add                         # opens $EDITOR on a blank file
credmgr update                      # opens $EDITOR pre-filled with the current content
credmgr get
credmgr vault use default

# Maintenance
credmgr passwd
credmgr migrate --backend aesgcm-cryptography
credmgr config set password_max_age_days 60

# Find something without knowing (or switching to) its vault
credmgr global github
credmgr global OPENAI_API_KEY
```
