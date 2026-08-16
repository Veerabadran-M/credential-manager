"""Credentials schema: service/account/password/notes/history.

credmgr's original data model, unchanged in behavior -- add/update/
delete/list/get/search/copy/history/audit/import/export -- implemented
as a Schema plugin so vault.py and the application layer don't need to know its
shape. Every cmd_* method here returns a CommandResult instead of
printing or reading from the terminal; see schemas/base.py.
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
from ...validation import validate_text
from ..base import CommandResult, IndexEntry, Schema, SchemaError, SecretRequired, Table

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

def _clipboard_lines(result: CommandResult, clip) -> None:
    """Append a Line describing a copy_to_clipboard() outcome."""
    if clip.copied:
        result.say(f"{clip.label} copied to clipboard. Clears in {clip.timeout}s.", "bold green")
    else:
        result.say(f"{clip.label} was not copied ({clip.reason}).", "bold yellow")

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

    def _get_password(self, opts: dict, result: CommandResult) -> str:
        """Resolve the password to store: generate one (and copy it to the
        clipboard as a convenience, same as before) if opts["generate"] is
        set, otherwise use the plaintext password the caller already
        collected in opts["password"] -- this schema never prompts for one
        itself. `result` collects any user-facing notice about it."""
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
            result.say(f"Generated {label}: {password}", "bold cyan")
            _clipboard_lines(result, copy_to_clipboard(password, label=label))
            return password

        password = opts.get("password")
        if not password:
            raise SecretRequired("Password")
        return password

    # ---- read ----

    def cmd_list(self, document: Credentials, args, config) -> CommandResult:
        result = CommandResult()
        if not document.services:
            return result.say("No services stored.", "bold yellow")
        for service, accounts in document.services.items():
            result.say(f"{service}  ({len(accounts)} account{'s' if len(accounts) != 1 else ''})", "bold magenta")
            for acc in accounts:
                result.say(f"  - {acc.userid}", "white")
        return result

    def cmd_list_all(self, document: Credentials, config) -> CommandResult:
        result = CommandResult()
        if not document.services:
            return result.say("No services stored.", "bold yellow")
        for service, accounts in document.services.items():
            result.say(service, "bold magenta")
            for acc in accounts:
                result.say(f"  - {acc.userid}", "white")
        return result

    def cmd_get(self, document: Credentials, args, config) -> CommandResult:
        if not args or len(args) > 2:
            raise SchemaError("Usage: credmgr get <service> [userid]")
        service, userid = args[0], (args[1] if len(args) == 2 else None)
        _validate_service_user(service, userid)

        result = CommandResult()
        matched_services = search_services(document, service)
        if not matched_services:
            return result.say(f"No service matching '{service}' found.", "yellow")

        rows_by_service = []
        for svc in matched_services:
            accounts = document.services[svc]
            if userid is None:
                rows_by_service.append((svc, accounts))
            else:
                matched_accounts = search_accounts(accounts, userid)
                if matched_accounts:
                    rows_by_service.append((svc, matched_accounts))

        if not rows_by_service:
            return result.say(f"No account '{userid}' found under matching services.", "yellow")

        rows = []
        first = True
        for svc, accounts in rows_by_service:
            if not first:
                rows.append(["", "", "", ""])
            first = False
            for i, acc in enumerate(accounts):
                rows.append([svc if i == 0 else "", acc.userid, acc.password, acc.notes])

        result.table = Table(headers=["Service", "User ID", "Password", "Notes"], rows=rows)
        return result

    def cmd_search(self, document: Credentials, query: str, config) -> CommandResult:
        _validate(query, "query", max_length=MAX_QUERY_LENGTH)
        result = CommandResult()
        matches = global_search(document, query)
        if not matches:
            return result.say(f"No matches for '{query}'.", "bold yellow")

        result.say(f"{len(matches)} match(es) for '{query}':", "bold cyan")
        for service, acc, field_hit in matches:
            result.say(f"  {service} / {acc.userid}  (matched: {field_hit})")
        return result

    def cmd_copy(self, document: Credentials, args, config) -> CommandResult:
        if not args or len(args) > 2:
            raise SchemaError("Usage: credmgr copy <service> [userid]")
        service, userid = args[0], (args[1] if len(args) == 2 else None)
        _validate_service_user(service, userid)

        result = CommandResult()
        matched_services = search_services(document, service)
        if not matched_services:
            return result.say(f"Service '{service}' not found.", "bold red")
        if len(matched_services) > 1:
            return result.say(
                f"Ambiguous service '{service}'. Be more specific. Matches: {', '.join(matched_services)}",
                "bold yellow"
            )
        svc = matched_services[0]
        accounts = document.services[svc]

        if not accounts:
            return result.say(f"No accounts under '{svc}'.", "bold yellow")

        if userid is not None:
            matched_accounts = search_accounts(accounts, userid)
            if not matched_accounts:
                return result.say(f"No account '{userid}' under '{svc}'.", "bold red")
            if len(matched_accounts) > 1:
                result.say("Multiple matches -- please be more specific:", "bold yellow")
                result.choices = [m.userid for m in matched_accounts]
                return result
            acc = matched_accounts[0]
        elif len(accounts) == 1:
            acc = accounts[0]
        else:
            # Ambiguous: ask the caller to retry with a specific userid
            # (frontend presents `result.choices` and re-invokes
            # cmd_copy(document, [service, chosen_userid], config)).
            result.say(f"Multiple accounts under '{svc}' -- specify a userid.", "bold cyan")
            result.choices = [a.userid for a in accounts]
            return result

        _clipboard_lines(result, copy_to_clipboard(acc.password, label=f"{svc} / {acc.userid}"))
        return result

    def cmd_history(self, document: Credentials, args, config) -> CommandResult:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr history <service> <userid>")
        service, userid = args
        _validate_service_user(service, userid)
        svc, accounts, acc = resolve_for_mutation(document, service, userid)

        result = CommandResult()
        if acc is None:
            return result.say("Specify a userid to view its password history.", "bold yellow")
        if not acc.history:
            return result.say(f"No password history for '{acc.userid}' under '{svc}'.", "bold yellow")

        result.say(f"Password history for {svc} / {acc.userid}:", "bold cyan")
        for entry in acc.history:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.changed_at))
            result.say(f"  {when}  {entry.password}", "dim")
        return result

    # ---- write ----

    def cmd_add(self, document: Credentials, args, opts: dict, config) -> CommandResult:
        if len(args) != 2:
            raise SchemaError("Usage: credmgr add <service> <userid>")
        service, userid = args
        _validate_service_user(service, userid)
        accounts = document.services.setdefault(service, [])

        result = CommandResult()
        if search_accounts(accounts, userid):
            return result.say(f"Account '{userid}' already exists under '{service}'. Use 'update'.", "bold yellow")

        password = self._get_password(opts, result)
        notes = opts.get("notes", "")
        now = time.time()
        accounts.append(Account(userid=userid, password=password, notes=notes, created_at=now, updated_at=now))
        result.say(f"Added '{userid}' under '{service}'", "bold green")
        result.mutated = True
        return result

    def cmd_update(self, document: Credentials, args, opts: dict, config) -> CommandResult:
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
        result = CommandResult()

        if field == "userid":
            if not new_value:
                raise SchemaError("'update ... userid' requires a <new_value> argument.")
            _validate(new_value, "new userid", max_length=MAX_LABEL_LENGTH)
            svc, accounts, acc = resolve_for_mutation(document, service, userid)
            if search_accounts(accounts, new_value) and new_value.lower() != acc.userid.lower():
                return result.say(f"Account '{new_value}' already exists under '{svc}'.", "bold yellow")
            acc.userid = new_value
            result.say(f"Renamed '{userid}' -> '{new_value}' under '{svc}'", "bold green")
            result.mutated = True
            return result

        if field == "password":
            svc, accounts, acc = resolve_for_mutation(document, service, userid)
            password = self._get_password(opts, result)
            _push_history(acc, config.password_history_limit)
            acc.password = password
            acc.updated_at = time.time()
            result.say(f"Password updated for '{acc.userid}' under '{svc}'", "bold green")
            result.mutated = True
            return result

        if field == "notes":
            if new_value is None:
                raise SchemaError("'update ... notes' requires a <new_value> argument.")
            svc, accounts, acc = resolve_for_mutation(document, service, userid)
            acc.notes = new_value
            result.say(f"Notes updated for '{acc.userid}' under '{svc}'", "bold green")
            result.mutated = True
            return result

        # field == "account"
        if not new_value:
            raise SchemaError("'update ... account' requires a <new_value> argument.")
        _validate(new_value, "new userid", max_length=MAX_LABEL_LENGTH)
        svc, accounts, acc = resolve_for_mutation(document, service, userid)
        if search_accounts(accounts, new_value) and new_value.lower() != acc.userid.lower():
            return result.say(f"Account '{new_value}' already exists under '{svc}'.", "bold yellow")
        password = self._get_password(opts, result)
        _push_history(acc, config.password_history_limit)
        acc.userid = new_value
        acc.password = password
        acc.updated_at = time.time()
        result.say(f"Account updated: '{userid}' -> '{new_value}' under '{svc}'", "bold green")
        result.mutated = True
        return result

    def cmd_delete(self, document: Credentials, args, config, confirmed: bool = False) -> CommandResult:
        if not args or len(args) > 2:
            raise SchemaError("Usage: credmgr delete <service> [userid]")
        service, userid = args[0], (args[1] if len(args) == 2 else None)
        _validate_service_user(service, userid)
        svc, accounts, acc = resolve_for_mutation(document, service, userid)

        result = CommandResult()

        if acc is None:
            n = len(accounts)
            if not confirmed:
                result.say(f"Delete all {n} account(s) under '{svc}'?", "bold yellow")
                result.needs_confirmation = True
                return result
            del document.services[svc]
            result.say(f"Deleted service '{svc}'.", "bold red")
        else:
            accounts.remove(acc)
            if not accounts:
                del document.services[svc]
                result.say(f"Deleted '{acc.userid}' -- '{svc}' removed (no accounts left).", "bold red")
            else:
                result.say(f"Deleted '{acc.userid}' from '{svc}'.", "bold red")

        result.mutated = True
        return result

    def cmd_audit(self, document: Credentials, config) -> CommandResult:
        report = audit_mod.run_audit(document, config)
        result = CommandResult()
        result.say("Password Audit", "bold cyan")
        result.say("")

        if report.duplicates:
            result.say("Duplicate passwords:", "bold yellow")
            for locations in report.duplicates.values():
                where = ", ".join(f"{s}/{u}" for s, u in locations)
                result.say(f"  - {where}")
        else:
            result.say("No duplicate passwords.", "green")
        result.say("")

        if report.weak:
            result.say("Weak passwords:", "bold yellow")
            for service, userid, reasons in report.weak:
                result.say(f"  - {service}/{userid}: {', '.join(reasons)}")
        else:
            result.say("No weak passwords detected.", "green")
        result.say("")

        if report.reused:
            result.say("Reused passwords (matches an earlier password):", "bold yellow")
            for service, userid in report.reused:
                result.say(f"  - {service}/{userid}")
        else:
            result.say("No password reuse detected.", "green")
        result.say("")

        if report.old:
            result.say(f"Passwords older than {config.password_max_age_days} days:", "bold yellow")
            for service, userid, age in report.old:
                result.say(f"  - {service}/{userid}: {int(age)} days old")
        else:
            result.say("No stale passwords.", "green")
        result.say("")

        if report.breach_db_available:
            if report.breached:
                result.say("Breached passwords (found in local breach database):", "bold red")
                for service, userid in report.breached:
                    result.say(f"  - {service}/{userid}")
            else:
                result.say("No breached passwords found.", "green")
        else:
            result.say(
                f"Breach check skipped: no database at {config.breach_db_file}. "
                "Run 'credmgr fetch-data' to download one, or populate it yourself with "
                "one SHA-1 password hash per line (see README).",
                "dim"
            )

        return result

    def cmd_import(self, document: Credentials, filepath: str, config) -> CommandResult:
        result = CommandResult()
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                imported = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return result.say(f"Failed to read import file: {e}", "bold red")

        if not isinstance(imported, dict):
            return result.say("Import file must contain a JSON object of services.", "bold red")

        now = time.time()
        for service, accounts in imported.items():
            try:
                validate_text(service, "service", max_length=MAX_LABEL_LENGTH)
            except ValueError as e:
                result.say(f"Skipping invalid service name in import: {service!r} ({e})", "bold yellow")
                continue
            if not isinstance(accounts, list):
                result.say(f"Skipping invalid accounts list under '{service}'.", "bold yellow")
                continue
            existing = document.services.setdefault(service, [])
            existing_userids = {acc.userid for acc in existing}

            for acc_data in accounts:
                if not isinstance(acc_data, dict) or "userid" not in acc_data or "password" not in acc_data:
                    result.say(f"Skipping invalid account under '{service}'.", "bold yellow")
                    continue
                try:
                    validate_text(acc_data["userid"], "userid", max_length=MAX_LABEL_LENGTH)
                except ValueError as e:
                    result.say(f"Skipping invalid account under '{service}' ({e}).", "bold yellow")
                    continue
                if not isinstance(acc_data["password"], str):
                    result.say(f"Skipping invalid account under '{service}' (password must be text).", "bold yellow")
                    continue
                if not isinstance(acc_data.get("notes", ""), str):
                    result.say(f"Skipping invalid account under '{service}' (notes must be text).", "bold yellow")
                    continue
                if acc_data["userid"] in existing_userids:
                    result.say(f"Skipping duplicate: {service}/{acc_data['userid']}", "bold yellow")
                    continue

                existing.append(Account(
                    userid=acc_data["userid"],
                    password=acc_data["password"],
                    notes=acc_data.get("notes", ""),
                    created_at=now,
                    updated_at=now
                ))

        result.say("Import completed.", "bold green")
        result.mutated = True
        return result

    def cmd_export(self, document: Credentials, config) -> CommandResult:
        return CommandResult(raw=json.dumps(document.to_dict(), indent=4))

    # ---- global (cross-vault) search index ----

    def index_entries(self, document: Credentials) -> list[IndexEntry]:
        entries = []
        for service, accounts in document.services.items():
            for acc in accounts:
                entries.append(IndexEntry(
                    fields={"service": service, "userid": acc.userid},
                    summary=[("Service", service), ("User ID", acc.userid)],
                    args=[service, acc.userid],
                ))
        return entries
