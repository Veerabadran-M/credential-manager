"""Terminal UI: rich console helpers and rendering."""

from __future__ import annotations

import getpass
import sys

from rich import box
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt

console = Console()

def fatal(msg: str | None = None) -> None:
    if msg is not None:
        console.print(msg, style="bold red")
    sys.exit(1)

def safe_getpass(prompt: str) -> str:
    try:
        value = getpass.getpass(prompt)
        print("\033[F\033[K", end="")  # clear the line, move cursor up
        return value
    except KeyboardInterrupt:
        fatal()

def prompt_new_password() -> str:
    while True:
        password = safe_getpass("Enter password: ")
        confirmation = safe_getpass("Re-enter password: ")
        if password == confirmation:
            return password
        print("Passwords do not match. Try again.")

def render_get_results(results) -> None:
    """results: list[(service_name, list[Account])]"""

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        show_edge=False,
        pad_edge=False,
        padding=(0, 2)
    )

    table.add_column("Service", style="bold green", no_wrap=True)
    table.add_column("User ID", style="white", no_wrap=True)
    table.add_column("Password", style="dim white")
    table.add_column("Notes", style="blue")

    first_service = True
    for service_name, accounts in results:
        if not first_service:
            table.add_row("", "", "", "")
        first_service = False

        for i, acc in enumerate(accounts):
            svc_cell = Text(service_name, style="bold green") if i == 0 else Text("")
            table.add_row(svc_cell, acc.userid, acc.password, acc.notes)

    console.print()
    console.print(table)

def ask_choice(msg: str, choices: list, default=None):
    choice = Prompt.ask(msg, choices=choices, default=default)
    return choice

def ask_int(prompt: str, default: int, *, min_value: int | None = None, max_value: int | None = None) -> int:
    """Prompt the user for an integer with validation."""

    while True:
        value = input(f"{prompt} [{default}]: ").strip()

        if not value:
            return default

        try:
            value = int(value)
        except ValueError:
            console.print("Please enter a valid integer.", style="bold red")
            continue

        if min_value is not None and value < min_value:
            console.print(f"Value must be at least {min_value}.", style="bold red")
            continue

        if max_value is not None and value > max_value:
            console.print(f"Value must be at most {max_value}.", style="bold red")
            continue

        return value