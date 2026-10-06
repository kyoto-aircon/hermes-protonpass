import pytest

from tests._plugin import (
    TOKEN_ENV,
    ProtonPassSource,
    _parse_ref,
    _validate_references,
)


class _Ctx:
    def __init__(self, data):
        self.data = data

    def get_config(self, key, default=None):
        return self.data.get(key, default)


def test_parse_ref_explicit_vault():
    ref = _parse_ref("ppass://Personal/Google/password", "Personal")
    assert (ref.vault, ref.title, ref.field) == ("Personal", "Google", "password")


def test_parse_ref_default_vault():
    ref = _parse_ref("ppass://Google/password", "Work")
    assert ref.vault == "Work"


def test_parse_ref_url_decodes_segments():
    ref = _parse_ref("ppass://Personal/My%20Item/urls", "Personal")
    assert ref.title == "My Item"


@pytest.mark.parametrize("bad", [
    "op://vault/item/field",
    "ppass://onlyone",
    "ppass://a/b/c/d",
    "ppass:///Google/password",
    123,
])
def test_parse_ref_rejects_malformed(bad):
    with pytest.raises(ValueError):
        _parse_ref(bad, "Personal")


def test_validate_references_warns_and_keeps_valid():
    valid, warnings = _validate_references(
        {"BAD-NAME": "ppass://Google/password", "OK": "not-a-ref", "GOOD": "ppass://Google/email"},
        "Personal",
    )
    assert set(valid) == {"GOOD"}
    assert len(warnings) == 2


def test_merged_refs_yaml_wins_per_variable():
    source = ProtonPassSource()
    source.bind_context(_Ctx({"env_map": {"A": "ppass://Gear/password",
                                          "B": "ppass://GearB/password"}}))
    merged = source._merged_refs({"env": {"A": "ppass://Yaml/password"}})
    assert merged["A"] == "ppass://Yaml/password"
    assert merged["B"] == "ppass://GearB/password"


def test_is_enabled_matrix():
    bare = ProtonPassSource()
    assert bare.is_enabled({}) is False
    assert bare.is_enabled({"enabled": False}) is False
    assert bare.is_enabled({"enabled": True}) is True
    assert bare.is_enabled({"env": {"A": "ppass://Google/password"}}) is True

    gear = ProtonPassSource()
    gear.bind_context(_Ctx({"env_map": {"A": "ppass://Google/password"}}))
    assert gear.is_enabled({}) is True

    gear_off = ProtonPassSource()
    gear_off.bind_context(_Ctx({"enabled": False, "env_map": {"A": "ppass://x/y"}}))
    assert gear_off.is_enabled({}) is False


def test_protected_vars_include_token_env():
    source = ProtonPassSource()
    assert source.protected_env_vars({}) == frozenset({TOKEN_ENV})
    assert source.protected_env_vars({"pat_env": "MY_PAT"}) == frozenset({"MY_PAT"})


def test_override_existing_precedence():
    source = ProtonPassSource()
    assert source.override_existing({}) is True
    assert source.override_existing({"override_existing": False}) is False
    source.bind_context(_Ctx({"override_existing": False}))
    assert source.override_existing({}) is False
