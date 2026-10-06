import pytest

from agent.secret_sources.base import ErrorKind, FetchResult

from tests._plugin import TOKEN_ENV, ProtonPassSource


def _cfg(fake, **env):
    return {"enabled": True, "binary_path": fake.binary, "env": env}


def test_fetch_resolves_mapped_values(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "pst_token")
    cfg = _cfg(
        fake_pass,
        PW="ppass://Personal/Google/password",
        EMAIL="ppass://Google/email",
    )
    result = ProtonPassSource().fetch(cfg, tmp_path)
    assert result.ok, result.error
    assert result.secrets["PW"] == "hunter2-proton"
    assert result.secrets["EMAIL"] == "jane@example.com"

    # Audit marker + isolated session on every call; never a full-JSON read.
    assert fake_pass.entries()
    for entry in fake_pass.entries():
        assert entry["reason"]
        assert entry["session_dir"]
        assert "--output" not in entry["argv"]

    # The PAT appears only on the login argv channel (child env carries the rest).
    pat_argv = [call for call in fake_pass.calls() if "pst_token" in call]
    assert pat_argv and all(call[0] == "login" for call in pat_argv)


def test_fetch_no_refs_is_noop(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "pst_token")
    result = ProtonPassSource().fetch({"enabled": True}, tmp_path)
    assert result.ok and result.secrets == {}
    assert fake_pass.calls() == []


def test_fetch_missing_token_reports_not_configured(fake_pass, tmp_path, monkeypatch):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    result = ProtonPassSource().fetch(_cfg(fake_pass, PW="ppass://Google/password"), tmp_path)
    assert not result.ok
    assert result.error_kind is ErrorKind.NOT_CONFIGURED
    assert fake_pass.calls() == []


def test_fetch_missing_binary_reports(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    cfg = {
        "enabled": True,
        "binary_path": str(tmp_path / "nope"),
        "env": {"PW": "ppass://Google/password"},
    }
    result = ProtonPassSource().fetch(cfg, tmp_path)
    assert result.error_kind is ErrorKind.BINARY_MISSING


def test_fetch_empty_field_skipped(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    result = ProtonPassSource().fetch(
        _cfg(fake_pass, EMPTY="ppass://Google/username", PW="ppass://Google/password"),
        tmp_path,
    )
    assert result.ok
    assert "EMPTY" not in result.secrets
    assert result.secrets["PW"] == "hunter2-proton"
    assert any("EMPTY" in warning for warning in result.warnings)


def test_fetch_partial_failure_keeps_other_values(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    result = ProtonPassSource().fetch(
        _cfg(
            fake_pass,
            MISSING="ppass://Personal/Nope/password",
            PW="ppass://Google/password",
        ),
        tmp_path,
    )
    assert result.secrets.get("PW") == "hunter2-proton"
    assert any("MISSING" in warning for warning in result.warnings)


def test_fetch_expired_session_relogins_once(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    fake_pass.set_mode("expired_once")
    result = ProtonPassSource().fetch(_cfg(fake_pass, PW="ppass://Google/password"), tmp_path)
    assert result.ok and result.secrets["PW"] == "hunter2-proton"
    logins = [call for call in fake_pass.calls() if call and call[0] == "login"]
    assert len(logins) >= 2


def test_fetch_login_failure_reports_auth(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "bad")
    fake_pass.set_mode("login_fail")
    result = ProtonPassSource().fetch(_cfg(fake_pass, PW="ppass://Google/password"), tmp_path)
    assert not result.ok
    assert result.error_kind in (ErrorKind.AUTH_FAILED, ErrorKind.AUTH_EXPIRED)
    assert "PW" not in result.secrets


@pytest.mark.parametrize(
    "cfg",
    [
        {},
        {"enabled": True},
        {"enabled": True, "env": "not-a-dict"},
        {"enabled": True, "env": {"A": 123}},
        {"enabled": True, "cache_ttl_seconds": "bogus"},
    ],
)
def test_fetch_never_raises_on_malformed_config(cfg, fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    result = ProtonPassSource().fetch(cfg, tmp_path)
    assert isinstance(result, FetchResult)
