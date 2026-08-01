"""Clipboard copy with auto-clear after a timeout.

Security: clearing happens in a forked background process that sleeps
for config.clipboard_timeout, then wipes the clipboard only if it still
holds the value that was copied, so a secret doesn't linger indefinitely.
"""

from __future__ import annotations

import os
import time

from .config import config
from .ui import console

try:
    import pyperclip
except ImportError:
    pyperclip = None

def copy_to_clipboard(value: str, label: str = "Password") -> None:
    if pyperclip is None:
        console.print(
            f"  [bold yellow]pyperclip is not installed -- {label.lower()} "
            "was not copied.[/bold yellow]"
        )
        return

    try:
        pyperclip.copy(value)
    except pyperclip.PyperclipException:
        console.print(
            f"  [bold yellow]No clipboard mechanism available on this system "
            f"-- {label.lower()} was not copied.[/bold yellow]"
        )
        return

    console.print(
        f"  [bold green]{label} copied to clipboard.[/bold green] "
        f"[dim]Clears in {config.clipboard_timeout}s.[/dim]"
    )

    pid = os.fork()
    if pid == 0:
        try:
            time.sleep(config.clipboard_timeout)
            if pyperclip.paste() == value:
                pyperclip.copy("")
        except Exception:
            pass
        finally:
            os._exit(0)