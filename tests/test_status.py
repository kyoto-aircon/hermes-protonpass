from tests._plugin import TOKEN_ENV, ProtonPassSource, _status_command


class _Ctx:
    def __init__(self, data=None):
        self.data = data or {}

    def get_config(self, key, default=None):
        return self.data.get(key, default)


def _patch_config(monkeypatch, payload, home):
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly", lambda: payload
    )
    monkeypatch.setattr("hermes_constants.get_hermes_home", lambda: home)


def test_status_reports_without_leaking_token(fake_pass, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(TOKEN_ENV, "pst_supersecret")
    _patch_config(
        monkeypatch,
        {
            "secrets": {
                "protonpass": {
                    "enabled": True,
                    "binary_path": fake_pass.binary,
                    "env": {"PW": "ppass://Personal/Google/password"},
                }
            }
        },
        tmp_path,
    )
    _status_command(ProtonPassSource(), _Ctx())
    out = capsys.readouterr().out

    assert "pst_supersecret" not in out
    assert "Token:" in out and "set" in out
    assert "pass-cli:" in out
    assert "Personal" in out
    assert "1 configured" in out


def test_status_reports_unset_token(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(TOKEN_ENV, raising=False)
    _patch_config(monkeypatch, {"secrets": {}}, tmp_path)
    _status_command(ProtonPassSource(), _Ctx())
    out = capsys.readouterr().out

    assert "not set" in out
    assert "References:" in out
