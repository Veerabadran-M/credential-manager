"""Terminal UI: Rich console helpers, prompts, and rendering.

Everything terminal-specific lives here (and in cli/commands.py) -- Rich,
getpass, input(). Nothing under credmgr/core/ or credmgr/schemas/ imports
this module; it only ever consumes the plain data (CommandResult, Line,
Table, ...) those layers return.
"""

from __future__ import annotations

import getpass
import os
import shlex
import subprocess
import sys
import tempfile

from rich import box
from rich.console import Console
from rich.table import Table as RichTable
from rich.prompt import Prompt

from ..schemas.base import CommandResult

console = Console()

def fatal(msg: str | None = None) -> None:
    if msg is not None:
        console.print(msg, markup=False, style="bold red")
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

def open_editor(editor: str, initial_text: str = "") -> str:
    """Open `editor` (the user's configured `credmgr config set editor
    ...`, e.g. "vim", "code -w", "nano") on a private temp file seeded
    with `initial_text`, wait for it to exit, and return whatever's in
    the file afterwards.

    The temp file is created 0600 and lives under the same tmp
    directory Path.gettempdir() would use; it's removed again as soon
    as the editor exits, whether or not the user saved anything.
    """
    fd, path = tempfile.mkstemp(prefix="credmgr-", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(initial_text)

        try:
            command = shlex.split(editor) + [path]
        except ValueError as e:
            fatal(f"Invalid editor command '{editor}': {e}")

        try:
            completed = subprocess.run(command)
        except FileNotFoundError:
            fatal(
                f"Editor '{editor}' not found. Set a working one with "
                f"'credmgr config set editor <command>', or set $VISUAL/$EDITOR."
            )
        except OSError as e:
            fatal(f"Failed to launch editor '{editor}': {e}")
        else:
            if completed.returncode != 0:
                fatal(f"Editor '{editor}' exited with a non-zero status ({completed.returncode}); nothing saved.")

        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

def ask_choice(msg: str, choices: list, default=None):
    return Prompt.ask(msg, choices=choices, default=default)

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

def render_result(result: CommandResult, *, plain: bool = False) -> None:
    """Render a schema CommandResult: its lines (styled, unless `plain`),
    then its table, if any. Doesn't touch `result.raw` -- callers that
    care about piping/redirecting (e.g. `export`) print that themselves
    with a bare print()."""
    for line in result.lines:
        if plain or not line.style:
            console.print(line.text, markup=False)
        else:
            console.print(line.text, style=line.style, markup=False)

    if result.table is not None:
        render_table(result.table)

def render_table(table) -> None:
    rich_table = RichTable(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        show_edge=False,
        pad_edge=False,
        padding=(0, 2)
    )
    for i, header in enumerate(table.headers):
        # First column (typically the "grouping" column, e.g. Service)
        # gets a little visual emphasis; the rest render plainly.
        style = "bold green" if i == 0 else ("dim white" if header.lower() == "password" else "white")
        rich_table.add_column(header, style=style, no_wrap=(i == 0))

    for row in table.rows:
        rich_table.add_row(*row)

    console.print()
    console.print(rich_table)
