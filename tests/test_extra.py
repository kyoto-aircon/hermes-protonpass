"""Additional edge-case coverage for the Proton Pass secret source.

Complements the existing suite without modifying it. Covers cache-key
invalidation (reference map + PAT rotation), timeout coercion, a broken gear
settings backend, URL decoding, invalid env-var names, warm logins, CR/LF
stripping and the invariant that the PAT only ever rides the ``login`` argv.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.secret_sources.base import DEFAULT_FETCH_TIMEOUT_SECONDS

from tests._plugin import (
    TOKEN_ENV,
    ProtonPassSource,
    _parse_ref,
    _read_field,
)

_PLUGIN = sys.modules["protonpass_plugin"]


def _cfg(fake, **env):
    return {"enabled": True, "binary_path": fake.binary, "env": env}


class _Ctx:
    def __init__(self, data):
        self.data = data

    def get_config(self, key, default=None):
        return self.data.get(key, default)


class _RaisingCtx:
    """A gear context whose settings backend is completely broken."""

    def get_config(self, key, default=None):
        raise RuntimeError("settings backend unavailable")


# --- cache-key invalidation -------------------------------------------------


def test_cache_not_reused_when_reference_map_changes(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    first = ProtonPassSource().fetch(
        _cfg(fake_pass, PW="ppass://Google/password"), tmp_path
    )
    assert first.ok and first.secrets
    calls_after_first = len(fake_pass.calls())

    # Same PAT, different reference map -> different refs fingerprint -> cache miss.
    second = ProtonPassSource().fetch(
        _cfg(fake_pass, PW="ppass://Google/urls"), tmp_path
    )
    assert second.ok
    assert second.secrets["PW"] == "https://google.com, https://accounts.google.com"
    assert len(fake_pass.calls()) > calls_after_first, "stale refs cache was reused"


def test_cache_not_reused_after_pat_changes(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "token-one")
    cfg = _cfg(fake_pass, PW="ppass://Google/password")
    first = ProtonPassSource().fetch(cfg, tmp_path)
    assert first.ok and first.secrets
    calls_after_first = len(fake_pass.calls())

    monkeypatch.setenv(TOKEN_ENV, "token-two")
    second = ProtonPassSource().fetch(cfg, tmp_path)
    assert second.secrets == first.secrets
    assert len(fake_pass.calls()) > calls_after_first, "cache key ignored the PAT"


# --- fetch timeout ----------------------------------------------------------


def test_fetch_timeout_default():
    assert (
        ProtonPassSource().fetch_timeout_seconds({}) == DEFAULT_FETCH_TIMEOUT_SECONDS
    )


@pytest.mark.parametrize(
    "raw, expected",
    [
        (45, 45.0),
        ("45", 45.0),
        ("bogus", DEFAULT_FETCH_TIMEOUT_SECONDS),
        (0, DEFAULT_FETCH_TIMEOUT_SECONDS),
        (0.0, DEFAULT_FETCH_TIMEOUT_SECONDS),
        (-5, DEFAULT_FETCH_TIMEOUT_SECONDS),
    ],
)
def test_fetch_timeout_from_yaml_cfg(raw, expected):
    source = ProtonPassSource()
    value = source.fetch_timeout_seconds({"timeout_seconds": raw})
    assert value == expected
    assert value > 0


@pytest.mark.parametrize(
    "raw, expected",
    [
        (33, 33.0),
        ("33", 33.0),
        ("bogus", DEFAULT_FETCH_TIMEOUT_SECONDS),
        (0, DEFAULT_FETCH_TIMEOUT_SECONDS),
        (-5, DEFAULT_FETCH_TIMEOUT_SECONDS),
    ],
)
def test_fetch_timeout_from_gear_settings(raw, expected):
    source = ProtonPassSource()
    source.bind_context(_Ctx({"timeout_seconds": raw}))
    value = source.fetch_timeout_seconds({})
    assert value == expected
    assert value > 0


def test_fetch_timeout_yaml_wins_over_gear():
    source = ProtonPassSource()
    source.bind_context(_Ctx({"timeout_seconds": 33}))
    assert source.fetch_timeout_seconds({"timeout_seconds": 45}) == 45.0


# --- broken gear settings ---------------------------------------------------


def test_fetch_survives_ctx_that_raises(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    source = ProtonPassSource()
    source.bind_context(_RaisingCtx())
    result = source.fetch(_cfg(fake_pass, PW="ppass://Google/password"), tmp_path)
    assert result.ok, result.error
    assert result.secrets["PW"] == "hunter2-proton"


# --- reference decoding -----------------------------------------------------


@pytest.mark.parametrize(
    "ref, default_vault, expected",
    [
        (
            "ppass://Personal/My%20Item/password",
            "Personal",
            ("Personal", "My Item", "password"),
        ),
        (
            "ppass://Personal/My%2FItem/password",
            "Personal",
            ("Personal", "My/Item", "password"),
        ),
        (
            "ppass://My%2FItem/pass%20word",
            "Work",
            ("Work", "My/Item", "pass word"),
        ),
        (
            "ppass://Personal/Google/url%2Ffield",
            "Personal",
            ("Personal", "Google", "url/field"),
        ),
    ],
)
def test_parse_ref_decodes_encoded_segments(ref, default_vault, expected):
    parsed = _parse_ref(ref, default_vault)
    assert (parsed.vault, parsed.title, parsed.field) == expected


# --- invalid env-var names --------------------------------------------------


def test_invalid_env_name_skipped_valid_sibling_resolves(
    fake_pass, tmp_path, monkeypatch
):
    monkeypatch.setenv(TOKEN_ENV, "t")
    cfg = {
        "enabled": True,
        "binary_path": fake_pass.binary,
        "env": {
            "BAD-NAME": "ppass://Google/password",
            "has space": "ppass://Google/password",
            "GOOD": "ppass://Google/email",
        },
    }
    result = ProtonPassSource().fetch(cfg, tmp_path)
    assert result.ok, result.error
    assert result.secrets == {"GOOD": "jane@example.com"}
    assert any("BAD-NAME" in warning for warning in result.warnings)
    assert any("has space" in warning for warning in result.warnings)
    # Only the valid sibling was ever read.
    assert len([c for c in fake_pass.calls() if c[:2] == ["item", "view"]]) == 1


# --- warm login -------------------------------------------------------------


def test_warm_login_still_reads_fields(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    fake_pass.set_mode("warm")
    result = ProtonPassSource().fetch(
        _cfg(fake_pass, PW="ppass://Google/password"), tmp_path
    )
    assert result.ok, result.error
    assert result.secrets["PW"] == "hunter2-proton"
    assert [c for c in fake_pass.calls() if c and c[0] == "login"]
    assert [c for c in fake_pass.calls() if c[:2] == ["item", "view"]]


# --- trailing CR/LF ---------------------------------------------------------


def test_read_field_strips_trailing_crlf(monkeypatch):
    def fake_run(argv, *, extra_env=None, timeout=None):
        return SimpleNamespace(returncode=0, stdout="s3cret\r\n\r\n", stderr="")

    monkeypatch.setattr(_PLUGIN, "run_secret_cli", fake_run)
    ref = _parse_ref("ppass://Google/password", "Personal")
    value = _read_field(
        Path("pass-cli"), ref, token="t", session_dir=Path(".")
    )
    assert value == "s3cret"


def test_fetch_values_have_no_trailing_newlines(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    result = ProtonPassSource().fetch(
        _cfg(
            fake_pass,
            PW="ppass://Google/password",
            URLS="ppass://Google/urls",
        ),
        tmp_path,
    )
    assert result.ok
    assert result.secrets
    for value in result.secrets.values():
        assert value == value.rstrip("\r\n")


# --- PAT containment --------------------------------------------------------


def test_pat_only_on_login_argv(fake_pass, tmp_path, monkeypatch):
    token = "pat-that-must-not-leak-123"
    monkeypatch.setenv(TOKEN_ENV, token)
    result = ProtonPassSource().fetch(
        _cfg(fake_pass, PW="ppass://Google/password", EMAIL="ppass://Google/email"),
        tmp_path,
    )
    assert result.ok, result.error

    calls = fake_pass.calls()
    assert calls
    item_calls = [call for call in calls if call[:2] == ["item", "view"]]
    assert item_calls

    for call in calls:
        if any(token in arg for arg in call):
            assert call[0] == "login", f"PAT leaked into non-login argv: {call}"
            assert call[1] == "--pat" and call[2] == token
    for call in item_calls:
        assert all(token not in arg for arg in call)


# --- stale-cache fallback through the real orchestrator ---------------------


def _apply_through_orchestrator(cfg, home, environ):
    """Run ``registry.apply_all`` with only the plugin source registered.

    The bundled sources are suppressed (a no-op ``_ensure_builtin_sources``) so
    the assertion sees exactly the plugin's contribution; registry state is
    restored afterwards so tests stay hermetic.
    """
    from agent.secret_sources import registry
    from agent.secret_sources.registry import apply_all

    registry._reset_registry_for_tests()
    saved = registry._ensure_builtin_sources
    registry._ensure_builtin_sources = lambda: None
    try:
        assert registry.register_source(ProtonPassSource())
        return apply_all(cfg, home, environ=environ)
    finally:
        registry._ensure_builtin_sources = saved
        registry._reset_registry_for_tests()


def test_stale_cache_applies_through_orchestrator(fake_pass, tmp_path, monkeypatch):
    """After a NETWORK failure a disk-cached value must reach ``environ`` via
    ``apply_all`` (i.e. ``_stale_fallback`` returns ``ok=True`` with secrets)."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv(TOKEN_ENV, "t")
    env_map = {"STALE_PW": "ppass://Google/password"}

    warm = ProtonPassSource().fetch(
        {"enabled": True, "binary_path": fake_pass.binary,
         "cache_ttl_seconds": 300, "env": env_map},
        home,
    )
    assert warm.ok and warm.secrets["STALE_PW"] == "hunter2-proton"

    time.sleep(0.05)  # let the short TTL below expire so lookup misses
    fake_pass.set_mode("network")
    fake_pass.clear_log()  # only calls made by the orchestrator fetch remain

    environ = {TOKEN_ENV: "t"}  # PAT must ride the per-fetch env; STALE_PW is fresh
    report = _apply_through_orchestrator(
        {"protonpass": {"enabled": True, "binary_path": fake_pass.binary,
                        "cache_ttl_seconds": 0.01, "env": env_map}},
        home,
        environ,
    )

    # A login was attempted (cache lookup missed) and then the stale disk entry
    # was served despite the network failure.
    assert [c for c in fake_pass.calls() if c and c[0] == "login"], fake_pass.calls()
    assert environ.get("STALE_PW") == "hunter2-proton", (environ, report)
    assert "STALE_PW" in report.provenance
    assert report.provenance["STALE_PW"].source == "protonpass"
    assert report.provenance["STALE_PW"].shape == "mapped"


def test_no_stale_cache_through_orchestrator_when_ttl_zero(
    fake_pass, tmp_path, monkeypatch
):
    """``cache_ttl_seconds: 0`` must suppress the fallback at the orchestrator."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv(TOKEN_ENV, "t")
    env_map = {"STALE_PW": "ppass://Google/password"}

    warm = ProtonPassSource().fetch(
        {"enabled": True, "binary_path": fake_pass.binary,
         "cache_ttl_seconds": 300, "env": env_map},
        home,
    )
    assert warm.ok and warm.secrets

    fake_pass.set_mode("network")
    environ = {TOKEN_ENV: "t"}
    report = _apply_through_orchestrator(
        {"protonpass": {"enabled": True, "binary_path": fake_pass.binary,
                        "cache_ttl_seconds": 0, "env": env_map}},
        home,
        environ,
    )

    assert "STALE_PW" not in environ
    assert "STALE_PW" not in report.provenance
    assert report.sources and not report.sources[0].result.ok


# --- flag-injection resistance ----------------------------------------------


def test_read_field_uses_equals_joined_flags(fake_pass, tmp_path):
    """A title starting with ``-`` is glued to its flag with ``=`` so pass-cli
    can never parse it as a separate option."""
    ref = _parse_ref("ppass://Work/-Leading-Dash/password", "Personal")
    session = _PLUGIN._session_dir(tmp_path)

    with pytest.raises(RuntimeError):
        _read_field(Path(fake_pass.binary), ref, token="t", session_dir=session)

    argv = fake_pass.calls()[0]
    assert argv[:2] == ["item", "view"]
    assert "--vault-name=Work" in argv
    assert "--item-title=-Leading-Dash" in argv
    assert "--field=password" in argv
    # The user-controlled values are never standalone argv tokens.
    assert "Work" not in argv
    assert "-Leading-Dash" not in argv
    assert "password" not in argv
    # Precisely three option tokens, all ``=``-joined.
    options = [arg for arg in argv if arg.startswith("--")]
    assert len(options) == 3
    assert all("=" in arg for arg in options)


# --- PAT scrub boundary -----------------------------------------------------


@pytest.mark.parametrize(
    "token, expect_scrub",
    [("a", False), ("abcdefg", False), ("abcdefgh", True)],
)
def test_login_scrubs_token_only_at_eight_chars(
    monkeypatch, tmp_path, token, expect_scrub
):
    """Short tokens are left intact (replacing a 1-char token would corrupt the
    error text used for classification); >= 8 chars is always redacted."""

    class _Proc:
        returncode = 1
        stdout = ""
        stderr = f"invalid personal access token {token}"

    monkeypatch.setattr(_PLUGIN, "run_secret_cli", lambda *a, **k: _Proc())
    error = _PLUGIN._login(
        Path("pass-cli"), token, _PLUGIN._session_dir(tmp_path)
    )
    assert error is not None
    if expect_scrub:
        assert token not in error
        assert "***" in error
    else:
        assert token in error
