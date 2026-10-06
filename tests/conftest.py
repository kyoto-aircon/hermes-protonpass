"""Shared fixtures: a controllable fake ``pass-cli`` binary."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

FAKE_CLI = r'''
import json, os, sys, pathlib
HERE = pathlib.Path(__file__).resolve().parent
LOG = HERE / "pass.log"
MODE = HERE / "mode.txt"
STATE = HERE / "state.json"

def mode():
    try:
        return MODE.read_text().strip()
    except OSError:
        return "ok"

def bump_reads():
    try:
        state = json.loads(STATE.read_text() or "{}")
    except Exception:
        state = {}
    n = int(state.get("reads", 0)) + 1
    state["reads"] = n
    STATE.write_text(json.dumps(state))
    return n

argv = sys.argv[1:]
entry = {
    "argv": argv,
    "pat": os.environ.get("PROTON_PASS_PERSONAL_ACCESS_TOKEN"),
    "session_dir": os.environ.get("PROTON_PASS_SESSION_DIR"),
    "reason": os.environ.get("PROTON_PASS_AGENT_REASON"),
}
with open(LOG, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(entry) + "\n")

if "--output" in argv and "json" in argv:
    sys.stderr.write("unexpected full-json read\n")
    sys.exit(3)

if not argv:
    sys.exit(2)
cmd = argv[0]
if cmd == "login":
    if mode() == "login_fail":
        sys.stderr.write("invalid personal access token\n")
        sys.exit(1)
    if mode() == "network":
        sys.stderr.write("network connection error\n")
        sys.exit(1)
    if mode() == "warm":
        sys.stderr.write("already authenticated\n")
        sys.exit(1)
    sys.stderr.write("Successfully authenticated\n")
    sys.exit(0)
if cmd == "info":
    sys.exit(0)
if cmd == "item" and len(argv) >= 2 and argv[1] == "view":
    def val(flag):
        return argv[argv.index(flag) + 1] if flag in argv else None
    title, field = val("--item-title"), val("--field")
    m = mode()
    if m == "expired_once" and bump_reads() == 1:
        sys.stderr.write("session expired, please log in again\n")
        sys.exit(1)
    if m == "network":
        sys.stderr.write("network connection error\n")
        sys.exit(1)
    data = {
        "Google": {
            "password": "hunter2-proton",
            "email": "jane@example.com",
            "username": "",
            "urls": "https://google.com, https://accounts.google.com",
            "totp_uri": "otpauth://totp/Google?secret=ABC",
        },
    }
    if title not in data:
        sys.stderr.write("item not found: %s\n" % title)
        sys.exit(1)
    if field not in data[title]:
        sys.stderr.write("unknown field %s\n" % field)
        sys.exit(1)
    sys.stdout.write(data[title][field] + "\n")
    sys.exit(0)
sys.stderr.write("unknown command\n")
sys.exit(2)
'''


@pytest.fixture(autouse=True)
def _clear_plugin_cache():
    """Keep the in-process/disk cache from leaking between tests."""
    from tests._plugin import clear_caches

    clear_caches()
    yield
    clear_caches()


@pytest.fixture
def fake_pass(tmp_path: Path) -> SimpleNamespace:
    """A fake ``pass-cli`` that logs argv + child env per call, with a mode file."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "fake_pass_cli.py"
    script.write_text(FAKE_CLI, encoding="utf-8")

    if os.name == "nt":
        wrapper = bin_dir / "pass-cli.cmd"
        wrapper.write_text(f'@echo off\r\npython "{script}" %*\r\n', encoding="utf-8")
    else:
        wrapper = bin_dir / "pass-cli"
        wrapper.write_text(f'#!/bin/sh\nexec python "{script}" "$@"\n', encoding="utf-8")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)

    log_path = bin_dir / "pass.log"
    mode_path = bin_dir / "mode.txt"
    state_path = bin_dir / "state.json"
    mode_path.write_text("ok", encoding="utf-8")
    state_path.write_text("{}", encoding="utf-8")

    def set_mode(value: str) -> None:
        mode_path.write_text(value, encoding="utf-8")
        state_path.write_text("{}", encoding="utf-8")

    def entries() -> list:
        if not log_path.exists():
            return []
        return [
            json.loads(line)
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    node = SimpleNamespace(
        binary=str(wrapper),
        log_path=log_path,
        bin_dir=bin_dir,
        set_mode=set_mode,
        entries=entries,
        calls=lambda: [e["argv"] for e in entries()],
        clear_log=lambda: log_path.unlink() if log_path.exists() else None,
    )
    return node
