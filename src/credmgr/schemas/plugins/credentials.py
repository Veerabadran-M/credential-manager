"""Credentials schema: service/account/password/notes/history.

credmgr's original data model, unchanged in behavior -- add/update/
delete/list/get/search/copy/history/audit/import/export -- now
implemented as a Schema plugin so vault.py and cli.py don't need to know
its shape.
"""

from __future__ import annotations

import json
import time

from ... import audit as audit_mod
from ...clipboard import copy_to_clipboard
from ...generator import generate_passphrase, generate_password
from ...models import Account, Credentials, PasswordHistoryEntry
from ...search import (global_search, resolve_for_mutation, search_accounts,
                        search_services)
from ...ui import console, prompt_new_password, render_get_results
from ...validation import validate_text
from ..base import Schema, SchemaError

MAX_LABEL_LENGTH = 128
MAX_QUERY_LENGTH = 512
MIN_PASSWORD_LENGTH = 8

UPDATE_FIELDS = ("userid", "password", "notes", "account")

def _validate(value: str, name: str, *, max_length: int) -> str:
    try:
        return validate_text(value, name, max_length=max_length)
    except ValueError as e:
        raise SchemaError(str(e)) from e

def _validate_service_user(service, userid=None) -> None:
    _validate(service, "service", max_length=MAX_LABEL_LENGTH)
    if userid is not None:
        _validate(userid, "userid", max_length=MAX_LABEL_LENGTH)

def _push_history(acc: Account, history_limit: int) -> None:
    acc.history.insert(0, PasswordHistoryEntry(password=acc.password, changed_at=acc.updated_at))
    del acc.history[history_limit:]

class CredentialsSchema(Schema):
    name = "credentials"

    # ---- parse/serialize ----

    @classmethod
    def new_document(cls) -> Credentials:
        return Credentials()

    @classmethod
    def parse(cls, plaintext: bytes) -> Credentials:
        return Credentials.from_dict(json.loads(plaintext.decode("utf-8")))

    @classmethod
    def serialize(cls, document: Credentials) -> bytes:
        return json.dumps(document.to_dict()).encode("utf-8")

    # ---- shared helpers ----

    def _get_password(self, opts: dict) -> str:
        length = opts.get("length", MIN_PASSWORD_LENGTH)
        words = opts.get("words", 5)
        if length < MIN_PASSWORD_LENGTH:
            raise SchemaError(f"Password length must be at least {MIN_PASSWORD_LENGTH}.")
        if length > 256:
            raise SchemaError("Password length must be 256 characters or fewer.")
        if words < 3 or words > 12:
            raise SchemaError("Passphrase word count must be between 3 and 12.")

        if opts.get("generate"):
            passphrase = opts.get("passphrase", False)
            password = generate_passphrase(words) if passphrase else generate_password(length)
            label = "Passphrase" if passphrase else "Password"
            console.print(f"\n[bold cyan]Generated {label}:[/bold cyan] [bold white]{password}[/bold white]")
            copy_to_clipboard(password, label=label)
            console.print()
            return password

        return prompt_new_password()

    # ---- read ----

    def cmd_list(self, document: Credentials, args, config) -> None:
        if not document.services:
            console.print("No services stored.", style="bold yellow")
            return
        for service, accounts in document.services.items():
            console.print(f"{service}  ({len(accounts)} account{'s' if len(accounts) != 1 else ''})", style="bold magenta")
            for acc in accounts:
                console.print(f"  - {acc.userid}", style="white")

    def cmd_get(self, document: Credentials, args, config) -> None:
        if not args or len(args) > 2:
            raise SchemaError("Usage: credmgr get <service> [userid]")
        service, userid = args[0], (args[1] if len(args) == 2 else None)
        _validate_service_user(service, userid)

        matched_services = search_services(document, service)
        if not matched_services:
            console.print(f"\n[yellow]No service matching '[bold]{service}[/bold]' found.[/yellow]\n")
            return

        results = []
        for svc in matched_services:
            accounts = document.services[svc]
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

    def cmd_search(self, document: Credentials, query: str, config) -> None:
        _validate(query, "query", max_length=MAX_QUERY_LENGTH)
        results = global_search(document, query)
        if not results:
            console.print(f"No matches for '{query}'.", style="bold yellow")
            return

        console.print(f"\n[bold cyan]{len(results)} match(es) for '{query}':[/bold cyan]\n")
        for service, acc, field_hit in results:
            console.print(
                f"  [bold green]{service}[/bold green] / [white]{acc.userid}[/white] "
                f"[dim](matched: {field_hit})[/dim]"
            )

    def cmd_copy(self, document: Credentials, args, config) -> None:
        if not args or len(args) > 2:
            raise SchemaError("Usage: credmgr copy <service> [userid]")
        service, userid = args[0], (args[1] if len(args) == 2 else None)
        _validate_service_user(service, userid)

        matched_services = search_services(document, service)
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
        accounts = document.services[svc]

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

    def cmd_history(self, document: Credentials, args, config) -> None:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr history <service> <userid>")
        service, userid = args
        _validate_service_user(service, userid)
        resolved = resolve_for_mutation(document, service, userid)
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

    # ---- write ----

    def cmd_add(self, document: Credentials, args, opts: dict, config) -> bool:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr add <service> <userid>")
        service, userid = args
        _validate_service_user(service, userid)
        accounts = document.services.setdefault(service, [])

        if search_accounts(accounts, userid):
            console.print(f"Account '{userid}' already exists under '{service}'. Use 'update'.", style="bold yellow")
            return False

        password = self._get_password(opts)
        notes = opts.get("notes", "")
        now = time.time()
        accounts.append(Account(userid=userid, password=password, notes=notes, created_at=now, updated_at=now))
        console.print(f"Added '{userid}' under '{service}'", style="bold green")
        return True

    def cmd_update(self, document: Credentials, args, opts: dict, config) -> bool:
        if len(args) < 3:
            raise SchemaError(
                "Usage: credmgr update <service> <userid> <field> [new_value]  "
                f"(field: {', '.join(UPDATE_FIELDS)})"
            )
        service, userid, field, *rest = args
        new_value = rest[0] if rest else None

        if field not in UPDATE_FIELDS:
            raise SchemaError(f"Unknown field '{field}'. Must be one of: {', '.join(UPDATE_FIELDS)}")

        _validate_service_user(service, userid)

        if field == "userid":
            if not new_value:
                raise SchemaError("'update ... userid' requires a <new_value> argument.")
            _validate(new_value, "new userid", max_length=MAX_LABEL_LENGTH)
            resolved = resolve_for_mutation(document, service, userid)
            if resolved is None:
                return False
            svc, accounts, acc = resolved
            if search_accounts(accounts, new_value) and new_value.lower() != acc.userid.lower():
                console.print(f"Account '{new_value}' already exists under '{svc}'.", style="bold yellow")
                return False
            acc.userid = new_value
            console.print(f"Renamed '{userid}' -> '{new_value}' under '{svc}'", style="bold green")
            return True

        if field == "password":
            resolved = resolve_for_mutation(document, service, userid)
            if resolved is None:
                return False
            svc, accounts, acc = resolved
            password = self._get_password(opts)
            _push_history(acc, config.password_history_limit)
            acc.password = password
            acc.updated_at = time.time()
            console.print(f"Password updated for '{acc.userid}' under '{svc}'", style="bold green")
            return True

        if field == "notes":
            if new_value is None:
                raise SchemaError("'update ... notes' requires a <new_value> argument.")
            resolved = resolve_for_mutation(document, service, userid)
            if resolved is None:
                return False
            svc, accounts, acc = resolved
            acc.notes = new_value
            console.print(f"Notes updated for '{acc.userid}' under '{svc}'", style="bold green")
            return True

        # field == "account"
        if not new_value:
            raise SchemaError("'update ... account' requires a <new_value> argument.")
        _validate(new_value, "new userid", max_length=MAX_LABEL_LENGTH)
        resolved = resolve_for_mutation(document, service, userid)
        if resolved is None:
            return False
        svc, accounts, acc = resolved
        if search_accounts(accounts, new_value) and new_value.lower() != acc.userid.lower():
            console.print(f"Account '{new_value}' already exists under '{svc}'.", style="bold yellow")
            return False
        password = self._get_password(opts)
        _push_history(acc, config.password_history_limit)
        acc.userid = new_value
        acc.password = password
        acc.updated_at = time.time()
        console.print(f"Account updated: '{userid}' -> '{new_value}' under '{svc}'", style="bold green")
        return True

    def cmd_delete(self, document: Credentials, args, config) -> bool:
        if not args or len(args) > 2:
            raise SchemaError("Usage: credmgr delete <service> [userid]")
        service, userid = args[0], (args[1] if len(args) == 2 else None)
        _validate_service_user(service, userid)
        resolved = resolve_for_mutation(document, service, userid)
        if resolved is None:
            return False
        svc, accounts, acc = resolved

        if acc is None:
            n = len(accounts)
            confirm = input(f"Delete all {n} account(s) under '{svc}'? [y/N] ").strip().lower()
            if confirm != "y":
                print("Aborted.")
                return False
            del document.services[svc]
            console.print(f"Deleted service '{svc}'.", style="bold red")
        else:
            accounts.remove(acc)
            if not accounts:
                del document.services[svc]
                console.print(f"Deleted '{acc.userid}' -- '{svc}' removed (no accounts left).", style="bold red")
            else:
                console.print(f"Deleted '{acc.userid}' from '{svc}'.", style="bold red")

        return True

    def cmd_audit(self, document: Credentials, config) -> None:
        report = audit_mod.run_audit(document, config)

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

    def cmd_import(self, document: Credentials, filepath: str, config) -> bool:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                imported = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            console.print(f"Failed to read import file: {e}", style="bold red")
            return False

        if not isinstance(imported, dict):
            console.print("Import file must contain a JSON object of services.", style="bold red")
            return False

        now = time.time()
        for service, accounts in imported.items():
            try:
                validate_text(service, "service", max_length=MAX_LABEL_LENGTH)
            except ValueError as e:
                console.print(f"Skipping invalid service name in import: {service!r} ({e})", style="bold yellow")
                continue
            if not isinstance(accounts, list):
                console.print(f"Skipping invalid accounts list under '{service}'.", style="bold yellow")
                continue
            existing = document.services.setdefault(service, [])
            existing_userids = {acc.userid for acc in existing}

            for acc_data in accounts:
                if not isinstance(acc_data, dict) or "userid" not in acc_data or "password" not in acc_data:
                    console.print(f"Skipping invalid account under '{service}'.", style="bold yellow")
                    continue
                try:
                    validate_text(acc_data["userid"], "userid", max_length=MAX_LABEL_LENGTH)
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
        return True

    def cmd_export(self, document: Credentials, config) -> None:
        print(json.dumps(document.to_dict(), indent=4))
