"""Load Hermes's conformance kit by path (our local ``tests`` package would
otherwise shadow the installed one)."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

_HERMES = os.environ.get(
    "HERMES_AGENT_DIR", r"C:\Users\Spheraz\AppData\Local\hermes\hermes-agent"
)
_PATH = Path(_HERMES) / "tests" / "secret_sources" / "conformance.py"

_spec = importlib.util.spec_from_file_location("hermes_secret_source_conformance", _PATH)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

SecretSourceConformance = _module.SecretSourceConformance
