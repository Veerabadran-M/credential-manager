"""Command-line interface: Typer argument parsing and command dispatch.

Generic commands (add/update/delete/list/get/search/copy/history/audit/
import/export) hold no schema-specific logic -- they collect arguments
and option flags and hand them to the active vault's schema
(credmgr/schemas/) to do the actual work, so new schemas can be added
without touching this file.
"""

from __future__ import annotations

from typing import List, Optional

import typer

from . import datasources
from . import vaultmgr
from .config import (ARGON2_MAX_MEMORY_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM,
                     ARGON2_MIN_TIME_COST, config)
from .crypto import BackendUnavailableError, UnknownBackendError
from .crypto.registry import available_backends, get_backend, resolve_backend
from .generator import generate_passphrase, generate_password
from .schemas import SchemaError, UnknownSchemaError, all_schemas, get_schema
from .ui import ask_choice, ask_int, console, fatal, safe_getpass
from .vault import AuthenticationError, Vault, VaultError

''' ------------------------------ HELPERS ------------------------------ '''

def _load_authenticated():
    """Ensure the active vault exists and authenticate against it. Used by
    every command that operates on stored vault contents. Returns
    (dek, document, vault, schema)."""
    if not Vault(config).exists():
        fatal(
            f"No vault found for the active vault '{config.active_vault}'. "
            f"Run 'credmgr init' (if this is your first vault) or "
            f"'credmgr vault create {config.active_vault} --schema <name>' first."
        )

    from .auth import authenticate  # local import: avoids a circular import at load time

    dek, document, vault = authenticate()
    schema = get_schema(vault.schema_name)
    return dek, document, vault, schema

def _save_if_mutated(vault: Vault, document, dek: bytes, mutated: bool) -> None:
    if mutated:
        try:
            vault.save(document, dek)
        except VaultError as e:
            fatal(str(e))

def _dispatch(fn, *args):
    """Call a schema cmd_* method, turning SchemaError into a clean CLI
    error instead of a traceback."""
    try:
        return fn(*args)
    except SchemaError as e:
        fatal(str(e))

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

def _resolve_backend_noninteractive(backend: str | None) -> str:
    if backend:
        try:
            get_backend(backend)
        except (UnknownBackendError, BackendUnavailableError) as e:
            fatal(str(e))
        console.print(f"Using backend: [bold green]{get_backend(backend).algorithm}[/] ({backend})")
        return backend
    return _choose_backend_interactively()

def cmd_init(skip_data_fetch: bool = False, backend: str | None = None) -> None:
    vault = Vault(config)  # the active vault -- "default" on a brand-new install

    if vault.exists():
        console.print("Vault already initialized.", style="bold blue")
        return

    backend = _resolve_backend_noninteractive(backend)
    config.backend = backend

    console.print("\nSet parameters for the Argon2 key derivation function:", style="bold magenta")
    console.print(
        "[bold yellow]Note:[/] The defaults exceed OWASP's current minimums "
        f"(time cost {ARGON2_MIN_TIME_COST}, memory {ARGON2_MIN_MEMORY_COST:,} KiB, "
        f"parallelism {ARGON2_MIN_PARALLELISM}).\n"
        "Increasing them improves resistance against brute-force attacks, "
        "but also increases the time and memory required to unlock the vault."
    )

    advanced = ask_choice("\nConfigure Argon2 parameters manually?", ["y", "n"], "n")

    if advanced == "y":
        config.argon2_time_cost = ask_int(
            "Argon2 time cost",
            default=config.argon2_time_cost,
            min_value=ARGON2_MIN_TIME_COST,
            max_value=20
        )

        config.argon2_memory_cost = ask_int(
            "Argon2 memory cost (KiB)",
            default=config.argon2_memory_cost,
            min_value=ARGON2_MIN_MEMORY_COST,
            max_value=ARGON2_MAX_MEMORY_COST
        )

        config.argon2_parallelism = ask_int(
            "Argon2 parallelism",
            default=config.argon2_parallelism,
            min_value=ARGON2_MIN_PARALLELISM,
            max_value=16
        )

        console.print("\nSelected Argon2 parameters:", style="bold green")
    else:
        console.print("\nUsing secure defaults:", style="bold green")

    console.print(f"  Time cost   : {config.argon2_time_cost}")
    console.print(f"  Memory cost : {config.argon2_memory_cost:,} KiB")
    console.print(f"  Parallelism : {config.argon2_parallelism}")
    console.print(f"  Key length  : {config.argon2_hash_len} bytes")
    console.print()

    console.print("Setting up a new credential vault.", style="bold cyan")
    master = safe_getpass("Set master password: ")
    confirm = safe_getpass("Confirm master password: ")

    if master != confirm:
        fatal("Passwords do not match.")

    console.print("Deriving key (this takes a moment)…", style="bold yellow")
    vault.create(backend, master, "credentials")

    console.print("Vault created and master password set.", style="bold green")

    if skip_data_fetch:
        console.print(f"Skipped fetching security datasets into {config.data_dir}.", style="dim")
    else:
        console.print(f"Fetching security datasets into {config.data_dir} …", style="bold cyan")
        results = datasources.fetch_all(config)
        _report_fetch_results(results)

    config.save()

    console.print("Use 'add' to start storing credentials securely.", style="bold magenta")

def cmd_fetch_data() -> None:
    """(Re-)download the wordlist, common-passwords, sequences, and
    breached-hash datasets into <master_dir>/data/. Safe to re-run any
    time -- e.g. to retry after a failed `init`, or to refresh the data."""
    console.print(f"Fetching security datasets into {config.data_dir} …", style="bold cyan")
    results = datasources.fetch_all(config)
    _report_fetch_results(results)

def cmd_passwd() -> None:
    """Rotate the active vault's master password. Only the DEK is
    re-wrapped -- the (potentially large) vault contents are never
    re-encrypted."""
    vault = Vault(config)
    if not vault.exists():
        fatal(f"No vault found for '{config.active_vault}'. Run 'credmgr init' first.")

    old = safe_getpass("Current master password: ")
    new = safe_getpass("New master password: ")
    confirm = safe_getpass("Confirm new master password: ")

    if new != confirm:
        fatal("New passwords do not match.")

    try:
        vault.rotate_master_password(old, new)
    except (AuthenticationError, BackendUnavailableError, VaultError) as e:
        fatal(str(e))

    console.print("Master password changed.", style="bold green")

def cmd_migrate(new_backend: str | None) -> None:
    """Re-encrypt the active vault under a different crypto backend.

    Backend selection follows CLI > environment (CREDMGR_BACKEND) > config
    file > built-in default, same as everywhere else backends are chosen.
    """
    vault = Vault(config)
    if not vault.exists():
        fatal(f"No vault found for '{config.active_vault}'. Run 'credmgr init' first.")

    target = resolve_backend(cli_value=new_backend, config_value=config.backend)

    try:
        get_backend(target)  # fail fast, before prompting for the password
    except (UnknownBackendError, BackendUnavailableError) as e:
        fatal(str(e))

    master = safe_getpass("Master password: ")

    try:
        vault.migrate_backend(master, target)
    except (AuthenticationError, BackendUnavailableError, VaultError) as e:
        fatal(str(e))

    # Update "backend" value in config
    if config.backend != target:
        config.backend = target
        config.save()

    # The DEK changed, so any cached session key is now stale.
    from .auth import delete_cache, session_cache_paths  # local import: avoids a circular import at load time
    delete_cache(session_cache_paths())

    console.print(f"Vault migrated to backend '[bold green]{target}[/]' ({get_backend(target).algorithm}).", style="bold green")

def cmd_config_show() -> None:
    for key, value in config.as_dict().items():
        colour = "red" if key in config.immutable_parameters else "cyan"
        console.print(f"  [bold {colour}]{key}[/bold {colour}] = [white]{value}[/white]")

def cmd_config_set(key: str, value: str) -> None:
    if key in config.immutable_parameters and vaultmgr.list_vault_names(config):
        fatal(
            f"'{key}' is fixed once a vault exists. To use a different "
            "backend, run 'credmgr migrate --backend <n>'. To change the "
            "Argon2 work factor, create a new vault ('credmgr vault create') "
            "and import data into it."
        )
    try:
        config.set_value(key, value)
    except (KeyError, ValueError) as e:
        fatal(str(e))
    config.save()
    console.print(f"Set [bold cyan]{key}[/bold cyan] = [white]{getattr(config, key)}[/white]", style="bold green")

def cmd_config_reset() -> None:
    confirm = input("Reset all configuration to defaults? [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return
    if config.settings_file.exists():
        config.settings_file.unlink()
    console.print("Configuration reset to defaults.", style="bold green")

def cmd_generate(passphrase: bool, length: int, words: int) -> str:
    if length < 8:
        fatal("Password length must be at least 8.")
    if length > 256:
        fatal("Password length must be 256 characters or fewer.")
    if words < 3 or words > 12:
        fatal("Passphrase word count must be between 3 and 12.")

    if passphrase:
        value = generate_passphrase(words)
        label = "Passphrase"
    else:
        value = generate_password(length)
        label = "Password"

    console.print(f"\n  [bold cyan]{label}:[/bold cyan]  [bold white]{value}[/bold white]")
    return value

''' ------------------------------ COMMANDS: VAULT MANAGEMENT ------------------------------ '''

def cmd_vault_create(name: str, schema_name: str, backend: str | None) -> None:
    try:
        vaultmgr.validate_vault_name(name)
    except vaultmgr.VaultManagerError as e:
        fatal(str(e))

    try:
        get_schema(schema_name)
    except UnknownSchemaError as e:
        fatal(str(e))

    vault = Vault(config, name=name)
    if vault.exists():
        fatal(f"Vault '{name}' already exists.")

    backend = _resolve_backend_noninteractive(backend) if backend else resolve_backend(config_value=config.backend)
    try:
        get_backend(backend)
    except (UnknownBackendError, BackendUnavailableError) as e:
        fatal(str(e))

    console.print(f"Creating vault '[bold cyan]{name}[/bold cyan]' (schema: {schema_name}, backend: {backend})", style="bold cyan")
    master = safe_getpass("Set master password: ")
    confirm = safe_getpass("Confirm master password: ")
    if master != confirm:
        fatal("Passwords do not match.")

    console.print("Deriving key (this takes a moment)…", style="bold yellow")
    try:
        vault.create(backend, master, schema_name)
    except VaultError as e:
        fatal(str(e))

    console.print(f"Vault '{name}' created.", style="bold green")

def cmd_vault_list() -> None:
    names = vaultmgr.list_vault_names(config)
    if not names:
        console.print("No vaults found. Run 'credmgr vault create <name>' to make one.", style="bold yellow")
        return

    for name in names:
        schema_name = vaultmgr.peek_schema(config, name)
        if name == config.active_vault:
            console.print(f"* [bold green]{name}[/bold green] ({schema_name})")
        else:
            console.print(f"  {name} ({schema_name})")

def cmd_vault_current() -> None:
    console.print(config.active_vault, style="bold cyan")

def cmd_vault_use(name: str) -> None:
    if not vaultmgr.vault_exists(config, name):
        fatal(f"Vault '{name}' does not exist. Run 'credmgr vault create {name}' first.")

    if name == config.active_vault:
        console.print(f"'{name}' is already the active vault.", style="bold blue")
        return

    config.active_vault = name
    config.save()
    console.print(f"Active vault switched to '[bold green]{name}[/bold green]'.", style="bold green")

def cmd_vault_delete(name: str) -> None:
    if not vaultmgr.vault_exists(config, name):
        fatal(f"Vault '{name}' does not exist.")

    if name == config.active_vault:
        fatal("Cannot delete the active vault. Switch to another vault first with 'credmgr vault use <name>'.")

    confirm = input(f"Delete vault '{name}' and all its data? This cannot be undone. [y/N] ").strip().lower()
    if confirm != "y":
        print("Aborted.")
        return

    try:
        vaultmgr.delete_vault(config, name)
    except vaultmgr.VaultManagerError as e:
        fatal(str(e))

    console.print(f"Vault '{name}' deleted.", style="bold red")

''' ------------------------------ CLI (Typer) ------------------------------ '''

app = typer.Typer(
    name="credmgr",
    help="Secure Credential Manager CLI tool",
    no_args_is_help=True,
    add_completion=False,
    epilog="""\
Examples:\n
credmgr init\n
credmgr fetch-data\n
credmgr add netflix alice\n
credmgr add netflix alice --generate\n
credmgr add netflix alice --generate --passphrase\n
credmgr add netflix alice --notes "backup email is alice@x.com"\n
credmgr generate\n
credmgr copy netflix\n
credmgr get netflix alice\n
credmgr search netflix\n
credmgr update netflix alice password --generate\n
credmgr update netflix alice notes "backup email is alice@x.com"\n
credmgr history netflix alice\n
credmgr audit\n
credmgr config show\n
credmgr config set password_max_age_days 60\n
credmgr passwd\n
credmgr delete netflix alice\n
credmgr export\n
credmgr migrate --backend aesgcm-cryptography\n
credmgr vault create work --schema credentials\n
credmgr vault create employee --schema env\n
credmgr vault list\n
credmgr vault use work\n
credmgr add EMPLOYEE_ID 123456
"""
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
    backend: Optional[str] = typer.Option(
        None, "--backend", metavar="NAME",
        help="Crypto backend to use (skips the interactive prompt); see 'credmgr config show'",
    )
) -> None:
    cmd_init(skip_data_fetch=skip_data_fetch, backend=backend)

@app.command(name="fetch-data", help="(Re-)download the wordlist, common-passwords, sequences, and breached-hash datasets")
def fetch_data_cmd() -> None:
    cmd_fetch_data()

@app.command(name="passwd", help="Change the master password")
def passwd_cmd() -> None:
    cmd_passwd()

@app.command(name="migrate", help="Re-encrypt the vault under a different crypto backend")
def migrate_cmd(
    backend: Optional[str] = typer.Option(
        None, "--backend", metavar="NAME",
        help="Target backend name (default: env CREDMGR_BACKEND, then config, then built-in default)",
    )
) -> None:
    cmd_migrate(backend)

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
    backend: Optional[str] = typer.Option(None, "--backend", metavar="NAME", help="Crypto backend to use (skips the interactive prompt)")
) -> None:
    cmd_vault_create(name, schema, backend)

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
    _, document, _, schema = _load_authenticated()
    _dispatch(schema.cmd_list, document, [], config)

def cmd_list_all() -> None:
    """Walk every vault on disk (not just the active one), authenticating
    against each in turn, and print its schema-shaped listing: every
    service + userid under it (credentials), or every key/LHS (env)."""
    names = vaultmgr.list_vault_names(config)
    if not names:
        console.print("No vaults found. Run 'credmgr vault create <name>' to make one.", style="bold yellow")
        return

    from .auth import authenticate  # local import: avoids a circular import at load time

    for i, name in enumerate(names):
        if i:
            console.print()
        schema_name = vaultmgr.peek_schema(config, name)
        marker = "*" if name == config.active_vault else " "
        console.print(f"{marker} [bold cyan]{name}[/bold cyan] ({schema_name})")

        _, document, vault = authenticate(vault_name=name, prompt=f"Master password for vault '{name}': ")
        schema = get_schema(vault.schema_name)
        _dispatch(schema.cmd_list_all, document, config)

@app.command(name="list-all", help="List services/userids (credentials) or keys (env) across every vault, not just the active one")
def list_all_cmd() -> None:
    cmd_list_all()

@app.command(name="audit", help="Run a password health audit (credentials schema only)")
def audit_cmd() -> None:
    _, document, _, schema = _load_authenticated()
    _dispatch(schema.cmd_audit, document, config)

@app.command(name="get", help="Display stored entries; args are schema-specific, e.g. <service> [userid]")
def get_cmd(args: Optional[List[str]] = typer.Argument(None)) -> None:
    _, document, _, schema = _load_authenticated()
    _dispatch(schema.cmd_get, document, args or [], config)

@app.command(name="search", help="Search entries")
def search_cmd(query: str) -> None:
    _, document, _, schema = _load_authenticated()
    _dispatch(schema.cmd_search, document, query, config)

@app.command(name="copy", help="Copy a stored value to the clipboard; args are schema-specific")
def copy_cmd(args: Optional[List[str]] = typer.Argument(None)) -> None:
    _, document, _, schema = _load_authenticated()
    _dispatch(schema.cmd_copy, document, args or [], config)

@app.command(name="history", help="Show change history for an entry (credentials schema only)")
def history_cmd(args: List[str] = typer.Argument(...)) -> None:
    _, document, _, schema = _load_authenticated()
    _dispatch(schema.cmd_history, document, args, config)

''' -------- write commands (vault + auth required, may persist) -------- '''

@app.command(name="add", help="Add a new entry; args are schema-specific, e.g. <service> <userid> or <KEY> <VALUE>")
def add_cmd(
    args: List[str] = typer.Argument(...),
    generate: bool = typer.Option(False, "--generate"),
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N"),
    notes: str = typer.Option("", "--notes", "-n", metavar="TEXT")
) -> None:
    dek, document, vault, schema = _load_authenticated()
    opts = {"generate": generate, "passphrase": passphrase, "length": length, "words": words, "notes": notes}
    mutated = _dispatch(schema.cmd_add, document, args, opts, config)
    _save_if_mutated(vault, document, dek, mutated)

@app.command(name="update", help="Update an existing entry; args are schema-specific, e.g. <service> <userid> <field> [new_value] or <KEY> <VALUE>")
def update_cmd(
    args: List[str] = typer.Argument(...),
    generate: bool = typer.Option(False, "--generate"),
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N")
) -> None:
    dek, document, vault, schema = _load_authenticated()
    opts = {"generate": generate, "passphrase": passphrase, "length": length, "words": words}
    mutated = _dispatch(schema.cmd_update, document, args, opts, config)
    _save_if_mutated(vault, document, dek, mutated)

@app.command(name="delete", help="Delete an entry; args are schema-specific, e.g. <service> [userid] or <KEY>")
def delete_cmd(args: List[str] = typer.Argument(...)) -> None:
    dek, document, vault, schema = _load_authenticated()
    mutated = _dispatch(schema.cmd_delete, document, args, config)
    _save_if_mutated(vault, document, dek, mutated)

@app.command(name="import", help="Import entries from a file")
def import_cmd(filepath: str) -> None:
    dek, document, vault, schema = _load_authenticated()
    mutated = _dispatch(schema.cmd_import, document, filepath, config)
    _save_if_mutated(vault, document, dek, mutated)

@app.command(name="export", help="Print all entries in the active vault")
def export_cmd() -> None:
    if not Vault(config).exists():
        fatal(f"No vault found for '{config.active_vault}'. Run 'credmgr init' first.")

    # Always re-authenticate for export, regardless of any cached session.
    from .auth import authenticate
    _, fresh_document, vault = authenticate(fresh=True)
    schema = get_schema(vault.schema_name)
    _dispatch(schema.cmd_export, fresh_document, config)

def main() -> None:
    app()

if __name__ == "__main__":
    main()
