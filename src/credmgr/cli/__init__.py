"""credmgr.cli: the Typer-based terminal frontend.

A thin layer over credmgr.core.CredentialManager -- see commands.py.

(Deliberately named commands.py, not app.py: `from .commands import app`
below would otherwise rebind the `credmgr.cli.app` *attribute* to the
Typer instance, shadowing the `credmgr.cli.app` *submodule* of the same
name -- a classic footgun for anything that later needs the module
itself, e.g. `import credmgr.cli.app as ...` or monkeypatching one of
its names in a test.)
"""

from __future__ import annotations

from .commands import app, main

__all__ = ["app", "main"]
