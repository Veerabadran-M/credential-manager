"""Command-line interface: Typer-based argument parsing and command dispatch."""

from __future__ import annotations

import json
import time
from enum import Enum
from typing import Optional

import typer

from . import audit as audit_mod
from . import datasources
from .clipboard import copy_to_clipboard
from .config import (ARGON2_MAX_MEMORY_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM,
                     ARGON2_MIN_TIME_COST, config)
from .crypto import BackendUnavailableError, UnknownBackendError
from .crypto.registry import available_backends, get_backend, resolve_backend
from .generator import generate_passphrase, generate_password
from .models import Account, Credentials, PasswordHistoryEntry
from .search import global_search, resolve_for_mutation, search_accounts, search_services
from .ui import console, fatal, prompt_new_password, render_get_results, safe_getpass, ask_choice, ask_int
from .vault import AuthenticationError, Vault, VaultError

''' ------------------------------ HELPERS ------------------------------ '''

MAX_LABEL_LENGTH = 128
MAX_QUERY_LENGTH = 512
MIN_PASSWORD_LENGTH = 8

def _validate_text_value(value: str, name: str, *, max_length: int) -> str:
    if value is None:
        raise ValueError(f"{name} is required.")
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text.")
    if value != value.strip():
        raise ValueError(f"{name} cannot start or end with whitespace.")
    if not value:
        raise ValueError(f"{name} cannot be empty.")
    if len(value) > max_length:
        raise ValueError(f"{name} must be {max_length} characters or fewer.")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} cannot contain control characters.")
    return value

def _validate_text(value: str, name: str, *, max_length: int) -> str:
    try:
        return _validate_text_value(value, name, max_length=max_length)
    except ValueError as e:
        fatal(str(e))

def _validate_service_user(service: str, userid: str | None = None) -> None:
    _validate_text(service, "service", max_length=MAX_LABEL_LENGTH)
    if userid is not None:
        _validate_text(userid, "userid", max_length=MAX_LABEL_LENGTH)

def _validate_secret_options(*, length: int, words: int) -> None:
    if length < MIN_PASSWORD_LENGTH:
        fatal(f"Password length must be at least {MIN_PASSWORD_LENGTH}.")
    if length > 256:
        fatal("Password length must be 256 characters or fewer.")
    if words < 3 or words > 12:
        fatal("Passphrase word count must be between 3 and 12.")

def get_password(*, generate: bool = False, passphrase: bool = False, length: int, words: int) -> str:
    _validate_secret_options(length=length, words=words)
    if generate:
        password = (generate_passphrase(words) if passphrase else generate_password(length))
        label = "Passphrase" if passphrase else "Password"

        console.print(f"\n[bold cyan]Generated {label}:[/bold cyan] [bold white]{password}[/bold white]")
        copy_to_clipboard(password, label=label)
        console.print()
        return password

    return prompt_new_password()

def _push_history(acc: Account) -> None:
    acc.history.insert(0, PasswordHistoryEntry(password=acc.password, changed_at=acc.updated_at))
    del acc.history[config.password_history_limit:]

def _load_authenticated() -> tuple[bytes, Credentials, Vault]:
    """Ensure a vault exists and authenticate against it. Used by every
    command that operates on stored credentials."""
    if not Vault(config).exists():
        fatal("No vault found. Run 'credmgr init' first.")

    from .auth import authenticate  # local import: avoids a circular import at load time

    dek, creds = authenticate()
    return dek, creds, Vault(config)

def _save_if_mutated(vault: Vault, creds: Credentials, dek: bytes, mutated: bool) -> None:
    if mutated:
        try:
            vault.save(creds, dek)
        except VaultError as e:
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

def cmd_init(skip_data_fetch: bool = False, backend: str | None = None) -> None:

    if config.vault_file.exists():
        console.print("Vault already initialized.", style="bold blue")
        return

    if backend:
        # Explicit --backend on `init` skips the interactive prompt entirely.
        try:
            get_backend(backend)
        except (UnknownBackendError, BackendUnavailableError) as e:
            fatal(str(e))
        console.print(f"Using backend: [bold green]{get_backend(backend).algorithm}[/] ({backend})")
    else:
        backend = _choose_backend_interactively()

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
    vault = Vault(config)

    console.print("Setting up a new credential vault.", style="bold cyan")
    master = safe_getpass("Set master password: ")
    confirm = safe_getpass("Confirm master password: ")

    if master != confirm:
        fatal("Passwords do not match.")

    console.print("Deriving key (this takes a moment)…", style="bold yellow")
    vault.create(backend, master)

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
    """Rotate the master password. Only the DEK is re-wrapped -- the (potentially
    large) vault contents are never re-encrypted."""
    vault = Vault(config)
    if not vault.exists():
        fatal("No vault found. Run 'credmgr init' first.")

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
    """Re-encrypt the vault under a different crypto backend.

    Backend selection follows CLI > environment (CREDMGR_BACKEND) > config
    file > built-in default, same as everywhere else backends are chosen.
    """
    vault = Vault(config)
    if not vault.exists():
        fatal("No vault found. Run 'credmgr init' first.")

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
    if key in config.immutable_parameters and Vault(config).exists():
        fatal(
            f"'{key}' is fixed for the existing vault. To use a different "
            "backend, run 'credmgr migrate --backend <name>'. To change the "
            "Argon2 work factor, create a new vault and import data into it."
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

''' ------------------------------ COMMANDS: READ ------------------------------ '''

def cmd_list(creds: Credentials) -> None:
    if not creds.services:
        console.print("No services stored.", style="bold yellow")
        return

    for service, accounts in creds.services.items():
        console.print(f"{service}  ({len(accounts)} account{'s' if len(accounts) != 1 else ''})", style="bold magenta")
        for acc in accounts:
            console.print(f"  - {acc.userid}", style="white")

def cmd_get(creds: Credentials, service, userid) -> None:
    _validate_service_user(service, userid)
    matched_services = search_services(creds, service)
    if not matched_services:
        console.print(f"\n[yellow]No service matching '[bold]{service}[/bold]' found.[/yellow]\n")
        return

    results = []
    for svc in matched_services:
        accounts = creds.services[svc]
        if userid is None:
            results.append((svc, accounts))
        else:
            matched_accounts = search_accounts(accounts, userid)
            if matched_accounts:
                results.append((svc, matched_accounts))

    if not results:
        console.print(f"\n[yellow]No account '[bold]{userid}[/bold]' found under matching services.[/yellow]\n")
        return

    render_get_results(results)

def cmd_search(creds: Credentials, query: str) -> None:
    _validate_text(query, "query", max_length=MAX_QUERY_LENGTH)
    results = global_search(creds, query)
    if not results:
        console.print(f"No matches for '{query}'.", style="bold yellow")
        return

    console.print(f"\n[bold cyan]{len(results)} match(es) for '{query}':[/bold cyan]\n")
    for service, acc, field_hit in results:
        console.print(
            f"  [bold green]{service}[/bold green] / [white]{acc.userid}[/white] "
            f"[dim](matched: {field_hit})[/dim]"
        )

def cmd_copy(creds: Credentials, service, userid) -> None:
    _validate_service_user(service, userid)
    matched_services = search_services(creds, service)
    if not matched_services:
        console.print(f"Service '{service}' not found.", style="bold red")
        return
    if len(matched_services) > 1:
        console.print(
            f"Ambiguous service '{service}'. Be more specific. Matches: {', '.join(matched_services)}",
            style="bold yellow"
        )
        return
    svc = matched_services[0]
    accounts = creds.services[svc]

    if not accounts:
        console.print(f"No accounts under '{svc}'.", style="bold yellow")
        return

    if userid is not None:
        matched_accounts = search_accounts(accounts, userid)
        if not matched_accounts:
            console.print(f"No account '{userid}' under '{svc}'.", style="bold red")
            return
        if len(matched_accounts) > 1:
            console.print("Multiple matches -- please be more specific:", style="bold yellow")
            for m in matched_accounts:
                console.print(f"  [white]- {m.userid}[/white]")
            return
        acc = matched_accounts[0]
    else:
        if len(accounts) == 1:
            acc = accounts[0]
        else:
            console.print(f"\n  [bold cyan]Accounts under '[green]{svc}[/green]':[/bold cyan]")
            for i, a in enumerate(accounts, start=1):
                console.print(f"  [bold white]{i}.[/bold white] [white]{a.userid}[/white]")
            console.print()
            try:
                raw = input("  Select account (number): ").strip()
            except KeyboardInterrupt:
                print()
                return
            if not raw.isdigit() or not (1 <= int(raw) <= len(accounts)):
                console.print("[bold red]Invalid selection.[/bold red]")
                return
            acc = accounts[int(raw) - 1]

    console.print()
    copy_to_clipboard(acc.password, label=f"{svc} / {acc.userid}")

def cmd_history(creds: Credentials, service, userid) -> None:
    _validate_service_user(service, userid)
    resolved = resolve_for_mutation(creds, service, userid)
    if resolved is None:
        return
    svc, accounts, acc = resolved

    if acc is None:
        console.print("\nSpecify a userid to view its password history.", style="bold yellow")
        return
    if not acc.history:
        console.print(f"\nNo password history for '{acc.userid}' under '{svc}'.", style="bold yellow")
        return

    console.print(f"\n[bold cyan]Password history for {svc} / {acc.userid}:[/bold cyan]")
    for entry in acc.history:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.changed_at))
        console.print(f"  [dim]{when}[/dim]  {entry.password}")

''' ------------------------------ COMMANDS: WRITE ------------------------------ '''

def cmd_add(creds: Credentials, service, userid, password, notes: str = "") -> None:
    _validate_service_user(service, userid)
    accounts = creds.services.setdefault(service, [])

    if search_accounts(accounts, userid):
        console.print(f"Account '{userid}' already exists under '{service}'. Use 'update'.", style="bold yellow")
        return

    now = time.time()
    accounts.append(Account(userid=userid, password=password, notes=notes, created_at=now, updated_at=now))
    console.print(f"Added '{userid}' under '{service}'", style="bold green")

def cmd_update_userid(creds: Credentials, service, userid, new_userid) -> bool:
    _validate_service_user(service, userid)
    _validate_text(new_userid, "new userid", max_length=MAX_LABEL_LENGTH)
    resolved = resolve_for_mutation(creds, service, userid)
    if resolved is None:
        return False
    svc, accounts, acc = resolved

    if search_accounts(accounts, new_userid) and new_userid.lower() != acc.userid.lower():
        console.print(f"Account '{new_userid}' already exists under '{svc}'.", style="bold yellow")
        return False

    acc.userid = new_userid
    console.print(f"Renamed '{userid}' -> '{new_userid}' under '{svc}'", style="bold green")
    return True

def cmd_update_password(creds: Credentials, service, userid, password) -> bool:
    _validate_service_user(service, userid)
    resolved = resolve_for_mutation(creds, service, userid)
    if resolved is None:
        return False
    svc, accounts, acc = resolved

    _push_history(acc)
    acc.password = password
    acc.updated_at = time.time()
    console.print(f"Password updated for '{acc.userid}' under '{svc}'", style="bold green")
    return True

def cmd_update_account(creds: Credentials, service, userid, new_userid, password) -> bool:
    _validate_service_user(service, userid)
    _validate_text(new_userid, "new userid", max_length=MAX_LABEL_LENGTH)
    resolved = resolve_for_mutation(creds, service, userid)
    if resolved is None:
        return False
    svc, accounts, acc = resolved

    if search_accounts(accounts, new_userid) and new_userid.lower() != acc.userid.lower():
        console.print(f"Account '{new_userid}' already exists under '{svc}'.", style="bold yellow")
        return False

    _push_history(acc)
    acc.userid = new_userid
    acc.password = password
    acc.updated_at = time.time()
    console.print(f"Account updated: '{userid}' -> '{new_userid}' under '{svc}'", style="bold green")
    return True

def cmd_update_notes(creds: Credentials, service, userid, notes: str) -> bool:
    _validate_service_user(service, userid)
    resolved = resolve_for_mutation(creds, service, userid)
    if resolved is None:
        return False
    svc, accounts, acc = resolved

    acc.notes = notes
    console.print(f"Notes updated for '{acc.userid}' under '{svc}'", style="bold green")
    return True

def cmd_delete(creds: Credentials, service, userid) -> bool:
    _validate_service_user(service, userid)
    resolved = resolve_for_mutation(creds, service, userid)
    if resolved is None:
        return False
    svc, accounts, acc = resolved

    if acc is None:
        n = len(accounts)
        confirm = input(f"Delete all {n} account(s) under '{svc}'? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return False
        del creds.services[svc]
        console.print(f"Deleted service '{svc}'.", style="bold red")
    else:
        accounts.remove(acc)
        if not accounts:
            del creds.services[svc]
            console.print(f"Deleted '{acc.userid}' -- '{svc}' removed (no accounts left).", style="bold red")
        else:
            console.print(f"Deleted '{acc.userid}' from '{svc}'.", style="bold red")

    return True

def cmd_export() -> None:
    # Always re-authenticate for export, regardless of any cached session.
    from .auth import authenticate

    _, fresh_creds = authenticate(fresh=True)
    print(json.dumps(fresh_creds.to_dict(), indent=4))

def cmd_import(creds: Credentials, filepath: str) -> None:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            imported = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        console.print(f"Failed to read import file: {e}", style="bold red")
        return

    if not isinstance(imported, dict):
        console.print("Import file must contain a JSON object of services.", style="bold red")
        return

    now = time.time()
    for service, accounts in imported.items():
        try:
            _validate_text_value(service, "service", max_length=MAX_LABEL_LENGTH)
        except ValueError as e:
            console.print(f"Skipping invalid service name in import: {service!r} ({e})", style="bold yellow")
            continue
        if not isinstance(accounts, list):
            console.print(f"Skipping invalid accounts list under '{service}'.", style="bold yellow")
            continue
        existing = creds.services.setdefault(service, [])
        existing_userids = {acc.userid for acc in existing}

        for acc_data in accounts:
            if not isinstance(acc_data, dict) or "userid" not in acc_data or "password" not in acc_data:
                console.print(f"Skipping invalid account under '{service}'.", style="bold yellow")
                continue
            try:
                _validate_text_value(acc_data["userid"], "userid", max_length=MAX_LABEL_LENGTH)
            except ValueError as e:
                console.print(f"Skipping invalid account under '{service}' ({e}).", style="bold yellow")
                continue
            if not isinstance(acc_data["password"], str):
                console.print(f"Skipping invalid account under '{service}' (password must be text).", style="bold yellow")
                continue
            if not isinstance(acc_data.get("notes", ""), str):
                console.print(f"Skipping invalid account under '{service}' (notes must be text).", style="bold yellow")
                continue
            if acc_data["userid"] in existing_userids:
                console.print(f"Skipping duplicate: {service}/{acc_data['userid']}", style="bold yellow")
                continue

            existing.append(Account(
                userid=acc_data["userid"],
                password=acc_data["password"],
                notes=acc_data.get("notes", ""),
                created_at=now,
                updated_at=now
            ))

    console.print("Import completed.", style="bold green")

def cmd_generate(passphrase: bool, length: int, words: int) -> str:
    _validate_secret_options(length=length, words=words)
    if passphrase:
        value = generate_passphrase(words)
        label = "Passphrase"
    else:
        value = generate_password(length)
        label = "Password"

    console.print(f"\n  [bold cyan]{label}:[/bold cyan]  [bold white]{value}[/bold white]")
    return value

''' ------------------------------ COMMANDS: AUDIT ------------------------------ '''

def cmd_audit(creds: Credentials) -> None:
    report = audit_mod.run_audit(creds, config)

    console.print("\n[bold cyan]Password Audit[/bold cyan]\n")

    if report.duplicates:
        console.print("[bold yellow]Duplicate passwords:[/bold yellow]")
        for locations in report.duplicates.values():
            where = ", ".join(f"{s}/{u}" for s, u in locations)
            console.print(f"  - {where}")
    else:
        console.print("[green]No duplicate passwords.[/green]")
    console.print()

    if report.weak:
        console.print("[bold yellow]Weak passwords:[/bold yellow]")
        for service, userid, reasons in report.weak:
            console.print(f"  - {service}/{userid}: {', '.join(reasons)}")
    else:
        console.print("[green]No weak passwords detected.[/green]")
    console.print()

    if report.reused:
        console.print("[bold yellow]Reused passwords (matches an earlier password):[/bold yellow]")
        for service, userid in report.reused:
            console.print(f"  - {service}/{userid}")
    else:
        console.print("[green]No password reuse detected.[/green]")
    console.print()

    if report.old:
        console.print(f"[bold yellow]Passwords older than {config.password_max_age_days} days:[/bold yellow]")
        for service, userid, age in report.old:
            console.print(f"  - {service}/{userid}: {int(age)} days old")
    else:
        console.print("[green]No stale passwords.[/green]")
    console.print()

    if report.breach_db_available:
        if report.breached:
            console.print("[bold red]Breached passwords (found in local breach database):[/bold red]")
            for service, userid in report.breached:
                console.print(f"  - {service}/{userid}")
        else:
            console.print("[green]No breached passwords found.[/green]")
    else:
        console.print(
            f"[dim]Breach check skipped: no database at {config.breach_db_file}. "
            "Run 'credmgr fetch-data' to download one, or populate it yourself with "
            "one SHA-1 password hash per line (see README).[/dim]"
        )

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
credmgr migrate --backend aesgcm-cryptography
"""
)

config_app = typer.Typer(help="View or edit configuration", no_args_is_help=False)
app.add_typer(config_app, name="config")

class UpdateField(str, Enum):
    userid = "userid"
    password = "password"
    notes = "notes"
    account = "account"

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

''' -------- read commands (vault + auth required) -------- '''

@app.command(name="list", help="List all stored services and accounts")
def list_cmd() -> None:
    _, creds, _ = _load_authenticated()
    cmd_list(creds)

@app.command(name="audit", help="Run a password health audit")
def audit_cmd() -> None:
    _, creds, _ = _load_authenticated()
    cmd_audit(creds)

@app.command(name="get", help="Display stored credentials")
def get_cmd(
    service: str,
    userid: Optional[str] = typer.Argument(None)
) -> None:
    _, creds, _ = _load_authenticated()
    cmd_get(creds, service, userid)

@app.command(name="search", help="Search services, userids, and notes")
def search_cmd(query: str) -> None:
    _, creds, _ = _load_authenticated()
    cmd_search(creds, query)

@app.command(name="copy", help="Copy a password to the clipboard")
def copy_cmd(
    service: str,
    userid: Optional[str] = typer.Argument(None)
) -> None:
    _, creds, _ = _load_authenticated()
    cmd_copy(creds, service, userid)

@app.command(name="history", help="Show password history for an account")
def history_cmd(service: str, userid: str) -> None:
    _, creds, _ = _load_authenticated()
    cmd_history(creds, service, userid)

''' -------- write commands (vault + auth required, may persist) -------- '''

@app.command(name="add", help="Add a new account")
def add_cmd(
    service: str,
    userid: str,
    generate: bool = typer.Option(False, "--generate"),
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N"),
    notes: str = typer.Option("", "--notes", "-n", metavar="TEXT")
) -> None:
    dek, creds, vault = _load_authenticated()
    password = get_password(generate=generate, passphrase=passphrase, length=length, words=words)
    cmd_add(creds, service, userid, password, notes=notes)
    _save_if_mutated(vault, creds, dek, True)

@app.command(name="update", help="Update an existing account")
def update_cmd(
    service: str,
    userid: str,
    field: UpdateField,
    new_value: Optional[str] = typer.Argument(None),
    generate: bool = typer.Option(False, "--generate"),
    passphrase: bool = typer.Option(False, "--passphrase"),
    length: int = typer.Option(config.password_length, "--length", metavar="N"),
    words: int = typer.Option(config.passphrase_num_word, "--words", metavar="N")
) -> None:
    dek, creds, vault = _load_authenticated()
    mutated = False

    match field:
        case UpdateField.userid:
            if not new_value:
                fatal("'update … userid' requires a <new_value> argument.")
            mutated = cmd_update_userid(creds, service, userid, new_value)

        case UpdateField.password:
            password = get_password(generate=generate, passphrase=passphrase, length=length, words=words)
            mutated = cmd_update_password(creds, service, userid, password)

        case UpdateField.notes:
            if new_value is None:
                fatal("'update … notes' requires a <new_value> argument.")
            mutated = cmd_update_notes(creds, service, userid, new_value)

        case UpdateField.account:
            if not new_value:
                fatal("'update … account' requires a <new_value> argument.")
            password = get_password(generate=generate, passphrase=passphrase, length=length, words=words)
            mutated = cmd_update_account(creds, service, userid, new_value, password)

    _save_if_mutated(vault, creds, dek, mutated)

@app.command(name="delete", help="Delete a service or account")
def delete_cmd(
    service: str,
    userid: Optional[str] = typer.Argument(None)
) -> None:
    dek, creds, vault = _load_authenticated()
    mutated = cmd_delete(creds, service, userid)
    _save_if_mutated(vault, creds, dek, mutated)

@app.command(name="import", help="Import credentials from a plaintext JSON file")
def import_cmd(filepath: str) -> None:
    dek, creds, vault = _load_authenticated()
    cmd_import(creds, filepath)
    _save_if_mutated(vault, creds, dek, True)

@app.command(name="export", help="Print all credentials as plain JSON")
def export_cmd() -> None:
    if not Vault(config).exists():
        fatal("No vault found. Run 'credmgr init' first.")
    cmd_export()

def main() -> None:
    app()

if __name__ == "__main__":
    main()