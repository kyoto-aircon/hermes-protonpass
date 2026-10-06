import time

from tests._plugin import TOKEN_ENV, ProtonPassSource


def _cfg(fake, ttl=300, **env):
    return {
        "enabled": True,
        "binary_path": fake.binary,
        "cache_ttl_seconds": ttl,
        "env": env,
    }


def test_second_fetch_hits_cache(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    cfg = _cfg(fake_pass, PW="ppass://Google/password")
    first = ProtonPassSource().fetch(cfg, tmp_path)
    assert first.ok and first.secrets
    calls_after_first = len(fake_pass.calls())

    second = ProtonPassSource().fetch(cfg, tmp_path)
    assert second.secrets == first.secrets
    assert len(fake_pass.calls()) == calls_after_first  # served from cache


def test_cache_ttl_zero_disables_cache(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    cfg = _cfg(fake_pass, ttl=0, PW="ppass://Google/password")
    ProtonPassSource().fetch(cfg, tmp_path)
    before = len(fake_pass.calls())
    ProtonPassSource().fetch(cfg, tmp_path)
    assert len(fake_pass.calls()) > before


def test_incomplete_pull_is_not_cached(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    cfg = _cfg(
        fake_pass,
        MISSING="ppass://Personal/Nope/password",
        PW="ppass://Google/password",
    )
    ProtonPassSource().fetch(cfg, tmp_path)
    before = len(fake_pass.calls())
    ProtonPassSource().fetch(cfg, tmp_path)
    assert len(fake_pass.calls()) > before


def test_stale_fallback_on_network_error(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    # A tiny positive TTL stores the entry but lets the next lookup miss.
    cfg = _cfg(fake_pass, ttl=0.01, PW="ppass://Google/password")
    warm = ProtonPassSource().fetch(cfg, tmp_path)
    assert warm.ok and warm.secrets

    time.sleep(0.05)
    fake_pass.set_mode("network")
    stale = ProtonPassSource().fetch(cfg, tmp_path)
    # Must be ok so the orchestrator (which drops non-ok results) applies it.
    assert stale.ok, stale.error
    assert stale.secrets.get("PW") == "hunter2-proton"
    assert any("stale" in warning.lower() for warning in stale.warnings)


def test_no_stale_fallback_when_cache_disabled(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    warm_cfg = _cfg(fake_pass, ttl=300, PW="ppass://Google/password")
    assert ProtonPassSource().fetch(warm_cfg, tmp_path).ok
    fake_pass.set_mode("network")
    failed = ProtonPassSource().fetch(
        _cfg(fake_pass, ttl=0, PW="ppass://Google/password"), tmp_path
    )
    assert not failed.ok
    assert failed.secrets == {}


def test_no_stale_fallback_for_auth_failure(fake_pass, tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "t")
    cfg = _cfg(fake_pass, ttl=0.01, PW="ppass://Google/password")
    ProtonPassSource().fetch(cfg, tmp_path)

    time.sleep(0.05)
    fake_pass.set_mode("login_fail")
    failed = ProtonPassSource().fetch(cfg, tmp_path)
    assert not failed.ok
    assert failed.secrets == {}
