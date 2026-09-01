"""Command-line interface: Typer argument parsing and command dispatch.

This is a thin frontend over credmgr.core.CredentialManager: every
command here does argument parsing, calls CredentialManager, and renders
(or prompts for) whatever it needs -- it holds no application logic
of its own. Generic commands (add/update/delete/list/get/search/copy/
history/audit/import/export) also hold no schema-specific logic;
CredentialManager dispatches those to the active vault's schema
(credmgr/schemas/), so new schemas can be added without touching this
file.
"""

from __future__ import annotations

from typing import List, Optional

import typer

from ..core import (AuthenticationError, BackendUnavailableError,
                     ContentRequired, CredentialManager, PasswordRequired,
                     SchemaError, SecretRequired, UnknownBackendError,
                     UnknownSchemaError, VaultError, VaultNotFound)
from ..config import (ARGON2_MAX_MEMORY_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM,
                     ARGON2_MIN_TIME_COST, config)
from ..crypto.registry import available_backends, get_backend, resolve_backend
from ..schemas import all_schemas, get_schema
from ..vaultmgr import VaultManagerError, validate_vault_name
from . import ui
from .ui import ask_choice, ask_int, console, fatal, open_editor, prompt_new_password, safe_getpass

manager = CredentialManager(config)

''' ------------------------------ HELPERS ------------------------------ '''

def _call(fn, *args, opts: dict | None = None, **kwargs):
    """Call a CredentialManager method, prompting on the terminal for whatever it
    says it needs (the vault's master password, and/or -- for write
    commands -- a new secret value to store) and retrying, until it
    succeeds or a real error surfaces. Turns SchemaError/VaultError/
    friends into a clean CLI error instead of a traceback.

    `opts`, when given, is threaded through as the final positional
    argument (matching every schema.cmd_add/cmd_update signature) so it
    can be updated in place across a SecretRequired retry.
    """
    call_args = args if opts is None else (*args, opts)
    try:
        while True:
            try:
                return fn(*call_args, **kwargs)
            except PasswordRequired as e:
                kwargs["password"] = safe_getpass(e.prompt)
            except SecretRequired:
                opts = {**opts, "password": prompt_new_password()}
                call_args = (*args, opts)
            except ContentRequired as e:
                opts = {**opts, "content": open_editor(config.editor, e.initial)}
                call_args = (*args, opts)
    except (SchemaError, VaultError, AuthenticationError, BackendUnavailableError,
            UnknownBackendError, VaultManagerError, VaultNotFound) as e:
        fatal(str(e))

def _load_vault_not_found_message(name: str) -> str:
    if name == config.active_vault:
        return (
            f"No vault found for the active vault '{name}'. "
            f"Run 'credmgr init' (if this is your first vault) or "
            f"'credmgr vault create {name} --schema <name>' first."
        )
    return f"No vault found for '{name}'. Run 'credmgr init' first."

def _render(result) -> None:
    ui.render_result(result)

''' ------------------------------ COMMANDS: SETUP ------------------------------ '''

def _report_fetch_results(results) -> None:
    for r in results:
        if r.ok:
            console.print(f"  [green]\u2713[/green] {r.name}: {r.detail}")
        else:
            console.print(f"  [yellow]\u2717[/yellow] {r.name}: could not fetch ({r.detail}); using built-in default")

def _choose_backend_interactively() -> str:
    backends = available_backends()
    if not backends:
        fatal(
            "No cryptographic backend is available. Install at least one of:\n"
            "  pip install credmgr[cryptography]\n"
            "  pip install credmgr[pynacl]\n"
            "  pip install credmgr[pycryptodome]\n"
            "or simply: pip install credmgr[all]"
        )

    # Stable order: whatever resolve_backend()/default_backend() would pick
    # first is shown (and defaulted to) first.
    default_name = resolve_backend(config_value=config.backend)
    ordered = sorted(backends, key=lambda n: (n != default_name, n))

    console.print("\nSelect the encryption backend for this vault:", style="bold cyan")
    numbers = [str(i) for i in range(1, len(ordered) + 1)]
    for num, name in zip(numbers, ordered):
        algorithm = get_backend(name).algorithm
        suffix = " (Recommended/Default)" if name == default_name else ""
        console.print(f"  [{num}] [white]{algorithm}[/white] ({name}){suffix}")
    console.print()
    console.print(
        "[bold yellow]Note:[/] This choice determines how all credentials are encrypted. "
        "Once the vault is created, switching backends requires 'credmgr migrate'. "
        "Choose carefully."
    )

    default_num = numbers[ordered.index(default_name)] if default_name in ordered else numbers[0]
    choice = ask_choice("Encryption backend", numbers, default_num)
    backend_name = ordered[int(choice) - 1]
    console.print(f"Selected: [bold green]{get_backend(backend_name).algorithm}[/] ({backend_name})")
    return backend_name

def _resolve_backend_noninteractive(backend_name: str | None) -> str:
    if backend_name:
        try:
            get_backend(backend_name)
        except (UnknownBackendError, BackendUnavailableError) as e:
            fatal(str(e))
        console.print(f"Using backend: [bold green]{get_backend(backend_name).algorithm}[/] ({backend_name})")
        return backend_name
    return _choose_backend_interactively()

def cmd_init(skip_data_fetch: bool = False, backend_name: str | None = None) -> None:
    if manager.vault_exists():
        console.print("Vault already initialized.", style="bold blue")
        return

    backend_name = _resolve_backend_noninteractive(backend_name)

    console.print("\nSet parameters for the Argon2 key derivation function:", style="bold magenta")
    console.print(
        "[bold yellow]Note:[/] The defaults exceed OWASP's current minimums "
        f"(time cost {ARGON2_MIN_TIME_COST}, memory {ARGON2_MIN_MEMORY_COST:,} KiB, "
        f"parallelism {ARGON2_MIN_PARALLELISM}).\n"
        "Increasing them improves resistance against brute-force attacks, "
        "but also increases the time and memory required to unlock the vault."
    )

    advanced = ask_choice("\nConfigure Argon2 parameters manually?", ["y", "n"], "n")

    argon2_time_cost = argon2_memory_cost = argon2_parallelism = None
    if advanced == "y":
        argon2_time_cost = ask_int(
            "Argon2 time cost",
            default=config.argon2_time_cost,
            min_value=ARGON2_MIN_TIME_COST,
            max_value=20
        )
        argon2_memory_cost = ask_int(
            "Argon2 memory cost (KiB)",
            default=config.argon2_memory_cost,
            min_value=ARGON2_MIN_MEMORY_COST,
            max_value=ARGON2_MAX_MEMORY_COST
        )
        argon2_parallelism = ask_int(
            "Argon2 parallelism",
            default=config.argon2_parallelism,
            min_value=ARGON2_MIN_PARALLELISM,
            max_value=16
        )
        console.print("\nSelected Argon2 parameters:", style="bold green")
    else:
        console.print("\nUsing secure defaults:", style="bold green")

    console.print("Setting up a new credential vault.", style="bold cyan")
    master = safe_getpass("Set master password: ")
    confirm = safe_getpass("Confirm master password: ")
    if master != confirm:
        fatal("Passwords do not match.")

    console.print("Deriving key (this takes a moment)\u2026", style="bold yellow")

    if not skip_data_fetch:
        console.print(f"Fetching security datasets into {config.data_dir} \u2026", style="bold cyan")

    result = _call(
        manager.init_vault, master, backend_name,
        argon2_time_cost=argon2_time_cost, argon2_memory_cost=argon2_memory_cost,
        argon2_parallelism=argon2_parallelism, skip_data_fetch=skip_data_fetch,
    )

    console.print(f"  Time cost   : {result.argon2_time_cost}")
    console.print(f"  Memory cost : {result.argon2_memory_cost:,} KiB")
    console.print(f"  Parallelism : {result.argon2_parallelism}")
    console.print(f"  Key length  : {result.argon2_hash_len} bytes")
    console.print()
    console.print("Vault created and master password set.", style="bold green")

    if result.fetch_results is None:
        console.print(f"Skipped fetching security datasets into {config.data_dir}.", style="dim")
    else:
        _report_fetch_results(result.fetch_results)

    console.print("Use 'add' to start storing credentials securely.", style="bold magenta")

def cmd_fetch_data() -> None:
    """(Re-)download the wordlist, common-passwords, sequences, and
    breached-hash datasets into <master_dir>/data/. Safe to re-run any
    time -- e.g. to retry after a failed `init`, or to refresh the data.
    """
    console.print(f"Fetching security datasets into {config.data_dir} \u2026", style="bold cyan")
    results = manager.fetch_data()
    _report_fetch_results(results)

def cmd_passwd() -> None:
    """Rotate the active vault's master password. Only the DEK is
    re-wrapped -- the (potentially large) vault contents are never
    re-encrypted."""
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))

    old = safe_getpass("Current master password: ")
    new = safe_getpass("New master password: ")
    confirm = safe_getpass("Confirm new master password: ")
    if new != confirm:
        fatal("New passwords do not match.")

    try:
        manager.change_password(old, new)
    except (AuthenticationError, BackendUnavailableError, VaultError) as e:
        fatal(str(e))

    console.print("Master password changed.", style="bold green")

def cmd_migrate(new_backend: str | None) -> None:
    """Re-encrypt the active vault under a different crypto backend.

    Backend selection follows CLI > environment (CREDMGR_BACKEND) > config
    file > built-in default, same as everywhere else backends are chosen.
    """
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))

    target = resolve_backend(cli_value=new_backend, config_value=config.backend)
    try:
        get_backend(target)  # fail fast, before prompting for the password
    except (UnknownBackendError, BackendUnavailableError) as e:
        fatal(str(e))

    master = safe_getpass("Master password: ")

    try:
        resolved = manager.migrate_backend(master, target)
    except (AuthenticationError, BackendUnavailableError, VaultError) as e:
        fatal(str(e))

    console.print(f"Vault migrated to backend '[bold green]{resolved}[/]' ({get_backend(resolved).algorithm}).", style="bold green")

def cmd_config_show() -> None:
    for key, value in manager.config_show().items():
        colour = "red" if key in config.immutable_parameters else "cyan"
        console.print(f"  [bold {colour}]{key}[/bold {colour}] = [white]{value}[/white]")

def cmd_config_set(key: str, value: str) -> None:
    try:
        manager.config_set(key, value)
    except (KeyError, ValueError) as e:
        fatal(str(e))
    console.print(f"Set [bold cyan]{key}[/bold cyan] = [white]{getattr(config, key)}[/white]", style="bold green")

def cmd_config_reset() -> None:
    confirm = input("Reset all configuration to defaults? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return
    manager.config_reset()
    console.print("Configuration reset to defaults.", style="bold green")

def cmd_generate(passphrase: bool, length: int, words: int) -> str:
    try:
        value = manager.generate_secret(passphrase=passphrase, length=length, words=words)
    except ValueError as e:
        fatal(str(e))
    label = "Passphrase" if passphrase else "Password"
    console.print(f"\n  [bold cyan]{label}:[/bold cyan]  [bold white]{value}[/bold white]")
    return value

''' ------------------------------ COMMANDS: VAULT MANAGEMENT ------------------------------ '''

def cmd_vault_create(name: str, schema_name: str, backend_name: str | None) -> None:
    try:
        validate_vault_name(name)
    except VaultManagerError as e:
        fatal(str(e))

    try:
        get_schema(schema_name)
    except UnknownSchemaError as e:
        fatal(str(e))

    if manager.vault_exists(name):
        fatal(f"Vault '{name}' already exists.")

    backend_name = _resolve_backend_noninteractive(backend_name) if backend_name else resolve_backend(config_value=config.backend)
    try:
        get_backend(backend_name)
    except (UnknownBackendError, BackendUnavailableError) as e:
        fatal(str(e))

    console.print(f"Creating vault '[bold cyan]{name}[/bold cyan]' (schema: {schema_name}, backend: {backend_name})", style="bold cyan")
    master = safe_getpass("Set master password: ")
    confirm = safe_getpass("Confirm master password: ")
    if master != confirm:
        fatal("Passwords do not match.")

    console.print("Deriving key (this takes a moment)\u2026", style="bold yellow")
    try:
        manager.vault_create(name, schema_name, backend_name, master)
    except VaultError as e:
        fatal(str(e))

    console.print(f"Vault '{name}' created.", style="bold green")

def cmd_vault_list() -> None:
    vaults = manager.vault_list()
    if not vaults:
        console.print("No vaults found. Run 'credmgr vault create <name>' to make one.", style="bold yellow")
        return
    for v in vaults:
        if v.active:
            console.print(f"* [bold green]{v.name}[/bold green] ({v.schema})")
        else:
            console.print(f"  {v.name} ({v.schema})")

def cmd_vault_current() -> None:
    console.print(manager.vault_current(), style="bold cyan")

def cmd_vault_use(name: str) -> None:
    if name == config.active_vault:
        if not manager.vault_exists(name):
            fatal(f"Vault '{name}' does not exist. Run 'credmgr vault create {name}' first.")
        console.print(f"'{name}' is already the active vault.", style="bold blue")
        return
    try:
        manager.vault_use(name)
    except VaultNotFound:
        fatal(f"Vault '{name}' does not exist. Run 'credmgr vault create {name}' first.")
    console.print(f"Active vault switched to '[bold green]{name}[/bold green]'.", style="bold green")

def cmd_vault_delete(name: str) -> None:
    if not manager.vault_exists(name):
        fatal(f"Vault '{name}' does not exist.")
    if name == config.active_vault:
        fatal("Cannot delete the active vault. Switch to another vault first with 'credmgr vault use <name>'.")

    confirm = input(f"Delete vault '{name}' and all its data? This cannot be undone. [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    try:
        manager.vault_delete(name)
    except VaultManagerError as e:
        fatal(str(e))
    console.print(f"Vault '{name}' deleted.", style="bold red")

''' ------------------------------ CLI (Typer) ------------------------------ '''

app = typer.Typer(
    name="credmgr",
    help="Secure Credential Manager CLI tool",
    no_args_is_help=True,
    add_completion=False
)

config_app = typer.Typer(help="View or edit configuration", no_args_is_help=False)
app.add_typer(config_app, name="config")

vault_app = typer.Typer(help="Create, list, and switch between vaults", no_args_is_help=True)
app.add_typer(vault_app, name="vault")

''' -------- setup commands (no vault / no auth required) -------- '''

@app.command(name="init", help="Initialize the credential vault")
def init_cmd(
    skip_data_fetch: bool = typer.Option(
        False, "--skip-data-fetch",
        help="Don't download the wordlist/common-passwords/breach-hash datasets; use built-in defaults",
    ),
    backend_name: Optional[str] = typer.Option(
        None, "--backend", metavar="NAME",
        help="Crypto backend to use (skips the interactive prompt); see 'credmgr config show'",
    )
) -> None:
    cmd_init(skip_data_fetch=skip_data_fetch, backend_name=backend_name)

@app.command(name="fetch-data", help="(Re-)download the wordlist, common-passwords, sequences, and breached-hash datasets")
def fetch_data_cmd() -> None:
    cmd_fetch_data()

@app.command(name="passwd", help="Change the master password")
def passwd_cmd() -> None:
    cmd_passwd()

@app.command(name="migrate", help="Re-encrypt the vault under a different crypto backend")
def migrate_cmd(
    backend_name: Optional[str] = typer.Option(
        None, "--backend", metavar="NAME",
        help="Target backend name (default: env CREDMGR_BACKEND, then config, then built-in default)",
    )
) -> None:
    cmd_migrate(backend_name)

@app.command(name="generate", help="Generate a random password or passphrase")
def generate_cmd(
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N")
) -> None:
    cmd_generate(passphrase, length, words)

''' -------- config sub-app -------- '''

@config_app.callback(invoke_without_command=True)
def config_callback(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        cmd_config_show()

@config_app.command(name="show", help="Show current configuration")
def config_show_cmd() -> None:
    cmd_config_show()

@config_app.command(name="set", help="Set a configuration value")
def config_set_cmd(key: str, value: str) -> None:
    cmd_config_set(key, value)

@config_app.command(name="reset", help="Reset configuration to defaults")
def config_reset_cmd() -> None:
    cmd_config_reset()

''' -------- vault sub-app -------- '''

@vault_app.command(name="create", help="Create a new vault")
def vault_create_cmd(
    name: str,
    schema: str = typer.Option(
        "credentials", "--schema", metavar="NAME",
        help=f"Schema for the new vault's contents ({', '.join(sorted(all_schemas())) or 'none registered'})"
    ),
    backend_name: Optional[str] = typer.Option(None, "--backend", metavar="NAME", help="Crypto backend to use (skips the interactive prompt)")
) -> None:
    cmd_vault_create(name, schema, backend_name)

@vault_app.command(name="list", help="List all vaults")
def vault_list_cmd() -> None:
    cmd_vault_list()

@vault_app.command(name="current", help="Show the active vault")
def vault_current_cmd() -> None:
    cmd_vault_current()

@vault_app.command(name="use", help="Switch the active vault")
def vault_use_cmd(name: str) -> None:
    cmd_vault_use(name)

@vault_app.command(name="delete", help="Delete a vault (not the active one)")
def vault_delete_cmd(name: str) -> None:
    cmd_vault_delete(name)

''' -------- read commands (vault + auth required) -------- '''

@app.command(name="list", help="List all entries in the active vault")
def list_cmd() -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    _render(_call(manager.list_entries, password=None))

def cmd_list_all() -> None:
    """Walk every vault on disk (not just the active one), authenticating
    against each in turn, and print its schema-shaped listing: every
    service + userid under it (credentials), or every key (env)."""
    names = manager.vault_names()
    if not names:
        console.print("No vaults found. Run 'credmgr vault create <name>' to make one.", style="bold yellow")
        return

    for i, name in enumerate(names):
        if i:
            console.print()
        schema_name = manager.peek_schema(name)
        marker = "*" if name == config.active_vault else " "
        console.print(f"{marker} [bold cyan]{name}[/bold cyan] ({schema_name})")

        result = _call(manager.list_all_for_vault, name, password=None)
        _render(result)

@app.command(name="list-all", help="List services/userids (credentials) or keys (env) across every vault, not just the active one")
def list_all_cmd() -> None:
    cmd_list_all()

''' ------------------------------ COMMANDS: GLOBAL (CROSS-VAULT) SEARCH ------------------------------ '''

def _ensure_index_fresh(names: list) -> None:
    """Bring the metadata index up to date before a global search.

    Prunes vaults that no longer exist, then re-derives metadata only
    for vaults CredentialManager flags as out of sync (missing from the
    index, changed on disk, or hand-edited). Vaults that are already up
    to date are never touched or unlocked -- this is what keeps `global`
    fast even with many vaults.
    """
    stale = manager.stale_index_vaults()
    if not stale:
        return

    console.print("Refreshing the search index for out-of-date vaults\u2026", style="dim")
    for name in stale:
        _call(manager.refresh_vault_index, name, password=None)

def _render_match_row(index: int, match: dict) -> str:
    fields = "  ".join(value for _label, value in match["summary"])
    return f"  {index}. {match['vault']:<12} {match['schema']:<12} {fields}"

def _render_match_details(match: dict) -> None:
    console.print(f"Vault    : [bold cyan]{match['vault']}[/bold cyan]")
    console.print(f"Schema   : {match['schema']}")
    for label, value in match["summary"]:
        console.print(f"{label:<9}: {value}")

def cmd_global(query: str) -> None:
    """Search every vault's metadata index for `query` without unlocking
    or switching any vault, then unlock only the single vault the user
    selects to retrieve the actual secret. See globalindex.py."""
    query = (query or "").strip()
    if not query:
        fatal("Usage: credmgr global <query>")

    names = manager.vault_names()
    if not names:
        console.print("No vaults found. Run 'credmgr vault create <name>' to make one.", style="bold yellow")
        return

    _ensure_index_fresh(names)
    matches = manager.index_search(query)

    if not matches:
        console.print("No matching entries found.", style="bold yellow")
        return

    if len(matches) == 1:
        match = matches[0]
        console.print("\nFound 1 match\n", style="bold cyan")
        _render_match_details(match)
        choice = ask_choice("\nView this secret?", ["y", "n"], "y")
        if choice != "y":
            return
    else:
        console.print(f"\n[bold cyan]Found {len(matches)} matches[/bold cyan]\n")
        for i, m in enumerate(matches, start=1):
            console.print(_render_match_row(i, m))
        console.print()
        try:
            raw = input("Select an entry: ").strip()
        except KeyboardInterrupt:
            print()
            return
        if not raw.isdigit() or not (1 <= int(raw) <= len(matches)):
            console.print("Invalid selection.", style="bold red")
            return
        match = matches[int(raw) - 1]

    # Only the selected vault is ever unlocked; the active vault (and
    # every other vault) is left completely untouched.
    result = _call(manager.get_from_vault, match["vault"], match["args"], password=None)
    _render(result)

@app.command(name="global", help="Search for an entry across every vault via the metadata index, then unlock only the matching vault")
def global_cmd(query: str) -> None:
    cmd_global(query)

@app.command(name="audit", help="Run a password health audit (credentials schema only)")
def audit_cmd() -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    _render(_call(manager.audit, password=None))

@app.command(name="get", help="Display stored entries; args are schema-specific, e.g. <service> [userid]")
def get_cmd(args: Optional[List[str]] = typer.Argument(None)) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    _render(_call(manager.get, args or [], password=None))

@app.command(name="search", help="Search entries")
def search_cmd(query: str) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    _render(_call(manager.search, query, password=None))

@app.command(name="copy", help="Copy a stored value to the clipboard; args are schema-specific")
def copy_cmd(args: Optional[List[str]] = typer.Argument(None)) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    args = list(args or [])
    result = _call(manager.copy, args, password=None)

    while result.choices:
        _render(result)
        console.print()
        for i, choice in enumerate(result.choices, start=1):
            console.print(f"  {i}. {choice}")
        try:
            raw = input("Select an account: ").strip()
        except KeyboardInterrupt:
            print()
            return
        if not raw.isdigit() or not (1 <= int(raw) <= len(result.choices)):
            console.print("Invalid selection.", style="bold red")
            return
        args = [args[0], result.choices[int(raw) - 1]]
        result = _call(manager.copy, args, password=None)

    _render(result)

@app.command(name="history", help="Show change history for an entry (credentials schema only)")
def history_cmd(args: List[str] = typer.Argument(...)) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    _render(_call(manager.history, args, password=None))

''' -------- write commands (vault + auth required, may persist) -------- '''

@app.command(name="add", help="Add a new entry; args are schema-specific, e.g. <service> <userid>, <KEY> <VALUE>, or (text schema) a filepath/string/nothing")
def add_cmd(
    args: List[str] = typer.Argument(None),
    generate: bool = typer.Option(False, "--generate"),
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N"),
    notes: str = typer.Option("", "--notes", "-n", metavar="TEXT")
) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    opts = {"generate": generate, "passphrase": passphrase, "length": length, "words": words, "notes": notes}
    _render(_call(manager.add, args or [], opts=opts, password=None))

@app.command(name="update", help="Update an existing entry; args are schema-specific, e.g. <service> <userid> <field> [new_value], <KEY> <VALUE>, or (text schema) a filepath/string/nothing")
def update_cmd(
    args: List[str] = typer.Argument(None),
    generate: bool = typer.Option(False, "--generate"),
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N")
) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    opts = {"generate": generate, "passphrase": passphrase, "length": length, "words": words}
    _render(_call(manager.update, args or [], opts=opts, password=None))

@app.command(name="delete", help="Delete an entry; args are schema-specific, e.g. <service> [userid] or <KEY>")
def delete_cmd(args: List[str] = typer.Argument(...)) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    args = list(args)
    result = _call(manager.delete, args, password=None)

    if result.needs_confirmation:
        _render(result)
        confirm = ask_choice("Proceed?", ["y", "n"], "n")
        if confirm != "y":
            print("Aborted.")
            return
        result = _call(manager.delete, args, password=None, confirmed=True)

    _render(result)

@app.command(name="import", help="Import entries from a file")
def import_cmd(filepath: str) -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    _render(_call(manager.import_entries, filepath, password=None))

@app.command(name="export", help="Print all entries in the active vault")
def export_cmd() -> None:
    if not manager.vault_exists():
        fatal(_load_vault_not_found_message(config.active_vault))
    result = _call(manager.export, password=None)
    print(result.raw)

def main() -> None:
    app()

if __name__ == "__main__":
    main()
