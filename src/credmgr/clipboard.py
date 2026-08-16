"""Clipboard copy with auto-clear after a timeout.

Security: clearing happens in a forked background process that sleeps
for config.clipboard_timeout, then wipes the clipboard only if it still
holds the value that was copied, so a secret doesn't linger indefinitely.

This module is core application code: it never prints. `copy_to_clipboard`
returns a ClipboardResult describing what happened; callers (schema
plugins, then frontends) decide how to tell the user.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .config import config

try:
    import pyperclip
except ImportError:
    pyperclip = None

@dataclass
class ClipboardResult:
    copied: bool
    label: str
    timeout: int | None = None  # seconds until auto-clear, when copied is True
    reason: str | None = None   # human-readable reason, when copied is False

def copy_to_clipboard(value: str, label: str = "Password") -> ClipboardResult:
    if pyperclip is None:
        return ClipboardResult(copied=False, label=label, reason="pyperclip is not installed")

    try:
        pyperclip.copy(value)
    except pyperclip.PyperclipException:
        return ClipboardResult(copied=False, label=label, reason="no clipboard mechanism available on this system")

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

    return ClipboardResult(copied=True, label=label, timeout=config.clipboard_timeout)
