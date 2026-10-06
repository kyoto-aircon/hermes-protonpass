"""Make the installed Hermes Agent tree (and its runtime deps) importable in tests.

The plugin is loaded *inside* Hermes, so at runtime ``agent.secret_sources`` and
its dependencies are already importable. Tests run standalone, so point them at
the installed tree via ``HERMES_AGENT_DIR`` (default: the standard per-user
install location). When the running interpreter lacks Hermes' runtime
dependencies (e.g. ``ruamel.yaml``), a matching Hermes virtualenv's
``site-packages`` is appended — override with ``HERMES_SITE_PACKAGES``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_DEFAULT = r"C:\Users\Spheraz\AppData\Local\hermes\hermes-agent"
_HERMES = os.environ.get("HERMES_AGENT_DIR", _DEFAULT)

if Path(_HERMES).is_dir() and _HERMES not in sys.path:
    sys.path.insert(0, _HERMES)


def _needs_venv_deps() -> bool:
    try:
        import ruamel.yaml  # noqa: F401

        return False
    except Exception:
        return True


def _candidate_site_packages() -> list[str]:
    override = os.environ.get("HERMES_SITE_PACKAGES")
    if override:
        return [override]
    installs = Path(_HERMES).parent / "installs"
    if not installs.is_dir():
        return []
    pattern = "*/environments/*/venv/Lib/site-packages"
    return sorted(str(path) for path in installs.glob(pattern))


if _needs_venv_deps():
    for candidate in _candidate_site_packages():
        if Path(candidate, "ruamel", "yaml").is_dir() and candidate not in sys.path:
            sys.path.append(candidate)
            break
