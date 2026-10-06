"""Load the plugin package by path so tests can import it without a package name."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location("protonpass_plugin", _ROOT / "__init__.py")
_module = importlib.util.module_from_spec(_spec)
sys.modules["protonpass_plugin"] = _module
_spec.loader.exec_module(_module)

ProtonPassSource = _module.ProtonPassSource
register = _module.register
clear_caches = _module.clear_caches
find_pass_cli = _module.find_pass_cli
_parse_ref = _module._parse_ref
_validate_references = _module._validate_references
_status_command = _module._status_command
_login = _module._login
_read_field = _module._read_field
_session_dir = _module._session_dir
_classify_pass_error = _module._classify_pass_error
_STORE = _module._STORE
TOKEN_ENV = _module._DEFAULT_TOKEN_ENV

