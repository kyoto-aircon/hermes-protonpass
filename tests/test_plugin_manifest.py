from pathlib import Path

import yaml

PLUGIN_YAML = Path(__file__).resolve().parent.parent / "plugin.yaml"


def test_manifest_identity():
    data = yaml.safe_load(PLUGIN_YAML.read_text(encoding="utf-8"))
    assert data["name"] == "protonpass"
    assert data["kind"] == "backend"
    assert data["manifest_version"] == 2
    assert data["api_version"] == 1
    assert data["requires_hermes"] == ">=0.21.5"


def test_manifest_config_schema():
    data = yaml.safe_load(PLUGIN_YAML.read_text(encoding="utf-8"))
    schema = data["config_schema"]
    assert set(schema) == {
        "pat", "vault", "env_map", "cache_ttl_seconds",
        "binary_path", "timeout_seconds", "override_existing", "enabled",
    }
    assert schema["pat"]["type"] == "secret"
    assert schema["pat"]["env"] == "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
    assert schema["env_map"]["type"] == "dict"
    assert schema["enabled"]["type"] == "bool"


def test_manifest_renders_via_settings_loader(tmp_path):
    """The manifest must survive the real plugins_settings parser."""
    from hermes_cli.plugins_settings import _manifest_config_schema, _field_type

    schema = _manifest_config_schema(PLUGIN_YAML.parent)
    assert schema, "config_schema did not parse"
    assert _field_type(schema["pat"]) == "secret"
    assert _field_type(schema["env_map"]) == "json"
    assert _field_type(schema["vault"]) == "string"
    assert _field_type(schema["enabled"]) == "boolean"
