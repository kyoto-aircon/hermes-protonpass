from pathlib import Path
import sys

import pytest

from agent.secret_sources.base import ErrorKind

from tests._plugin import (
    TOKEN_ENV,
    _classify_pass_error,
    _login,
    _parse_ref,
    _read_field,
    _session_dir,
    find_pass_cli,
)


def test_login_error_scrubs_token(monkeypatch, tmp_path):
    mod = sys.modules["protonpass_plugin"]

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "invalid personal access token pst_leak"

    monkeypatch.setattr(mod, "run_secret_cli", lambda *a, **k: _Proc())
    error = _login(Path("pass-cli"), "pst_leak", _session_dir(tmp_path))
    assert error and "pst_leak" not in error


def test_find_pass_cli_pinned(fake_pass):
    assert find_pass_cli(fake_pass.binary) == Path(fake_pass.binary)
    assert find_pass_cli(str(Path(fake_pass.binary).with_name("missing"))) is None


def test_login_success_uses_argv_pat(fake_pass, tmp_path):
    session = _session_dir(tmp_path)
    assert _login(Path(fake_pass.binary), "pst_logintoken", session) is None
    call = fake_pass.calls()[0]
    assert call[:3] == ["login", "--pat", "pst_logintoken"]


def test_login_warm_session_is_success(fake_pass, tmp_path):
    fake_pass.set_mode("warm")
    session = _session_dir(tmp_path)
    assert _login(Path(fake_pass.binary), "pst_x", session) is None


def test_login_failure_returns_error(fake_pass, tmp_path):
    fake_pass.set_mode("login_fail")
    error = _login(Path(fake_pass.binary), "pst_bad", _session_dir(tmp_path))
    assert error and "invalid personal access token" in error


def test_read_field_maps_value_and_child_env(fake_pass, tmp_path):
    session = _session_dir(tmp_path)
    ref = _parse_ref("ppass://Personal/Google/password", "Personal")
    value = _read_field(Path(fake_pass.binary), ref, token="pst_secret", session_dir=session)
    assert value == "hunter2-proton"
    entry = fake_pass.entries()[0]
    assert entry["pat"] == "pst_secret"
    assert entry["reason"]
    assert entry["session_dir"] == str(session)
    assert "--output" not in entry["argv"]


def test_read_field_unknown_item_raises(fake_pass, tmp_path):
    ref = _parse_ref("ppass://Personal/Nope/password", "Personal")
    with pytest.raises(RuntimeError):
        _read_field(Path(fake_pass.binary), ref, token="t", session_dir=_session_dir(tmp_path))


@pytest.mark.parametrize("message,kind", [
    ("network connection error", ErrorKind.NETWORK),
    ("host not found", ErrorKind.NETWORK),
    ("session expired, please log in again", ErrorKind.AUTH_EXPIRED),
    ("invalid personal access token", ErrorKind.AUTH_FAILED),
    ("unknown field password2", ErrorKind.REF_INVALID),
    ("item not found: Nope", ErrorKind.REF_INVALID),
    ("failed to invoke pass-cli", ErrorKind.BINARY_MISSING),
    ("something totally unexpected", ErrorKind.INTERNAL),
])
def test_classify_pass_error(message, kind):
    assert _classify_pass_error(message) is kind
