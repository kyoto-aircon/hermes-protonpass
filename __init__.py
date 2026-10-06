"""Proton Pass secret source for Hermes Agent.

Maps environment-variable names to ``ppass://`` references resolved through the
official Proton Pass CLI (``pass-cli``) at process startup, mirroring the bundled
1Password source. Example ``~/.hermes/config.yaml``::

    secrets:
      protonpass:
        enabled: true
        env:
          OPENAI_API_KEY: ppass://Personal/OpenAI/password

The same surface is available from the Plugins settings form (the manifest
``config_schema``); settings saved there are read lazily through
``ctx.get_config()`` and merged under the YAML section (YAML wins per key).

Security posture (mirrors ``agent/vault_backends/protonpass.py``):
- the personal access token travels on argv only in ``pass-cli login --pat`` and
  in the child environment;
- metadata/field reads use ``item view --field`` exclusively — never
  ``item view --output json``, which leaks ``totp_uri``/passkeys on agent sessions;
- every call carries ``PROTON_PASS_AGENT_REASON`` and an isolated
  ``PROTON_PASS_SESSION_DIR``;
- ``fetch()`` never raises and never prompts.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Tuple
from urllib.parse import unquote

from agent.secret_sources._cache import CachedFetch, SecretCache, fingerprint
from agent.secret_sources.base import (
    ErrorKind,
    FetchResult,
    SecretSource,
    classify_cli_error,
    coerce_float,
    get_source_environment,
    is_valid_env_name,
    run_secret_cli,
)

logger = logging.getLogger(__name__)

_DEFAULT_TOKEN_ENV = "PROTON_PASS_PERSONAL_ACCESS_TOKEN"
_DEFAULT_VAULT = "Personal"
_DEFAULT_CACHE_TTL = 300.0
_SCHEME = "ppass"
_CACHE_BASENAME = "ppass_cache.json"
_SESSION_DIRNAME = "ppass-session"
_CLI_TIMEOUT = 30.0
_ALREADY_AUTHENTICATED = "already authenticated"
# Mandatory, audited marker on every agent-session read.
_AGENT_REASON = (
    "Hermes secret source: resolving mapped Proton Pass references into "
    "environment variables at startup"
)


class _Ref(NamedTuple):
    vault: str
    title: str
    field: str


# --- cache ------------------------------------------------------------------

_CacheKey = Tuple[str, str]  # (token fingerprint, refs fingerprint)

_STORE: SecretCache[_CacheKey] = SecretCache(
    _CACHE_BASENAME, key_serializer=lambda key: f"{key[0]}|{key[1]}"
)


def clear_caches(home_path: Optional[Path] = None) -> None:
    """Drop the in-process and on-disk caches (e.g. after a PAT rotation)."""
    _STORE.clear(home_path)


_reset_cache_for_tests = clear_caches


# --- reference parsing ------------------------------------------------------


def _parse_ref(ref: Any, default_vault: str) -> _Ref:
    """``ppass://[vault/]title/field`` → :class:`_Ref`; raises ``ValueError``."""
    if not isinstance(ref, str):
        raise ValueError("reference is not a string")
    text = ref.strip()
    prefix = f"{_SCHEME}://"
    if not text.startswith(prefix):
        raise ValueError(f"{ref!r} is not a {_SCHEME}:// reference")
    parts = [unquote(p) for p in text[len(prefix):].split("/")]
    if len(parts) == 2:
        vault, (title, field) = default_vault, (parts[0], parts[1])
    elif len(parts) == 3:
        vault, title, field = parts
    else:
        raise ValueError(
            f"{ref!r} must be ppass://title/field or ppass://vault/title/field"
        )
    if not all(str(p).strip() for p in (vault, title, field)):
        raise ValueError(f"{ref!r} has an empty vault/item/field segment")
    return _Ref(str(vault).strip(), str(title).strip(), str(field).strip())


def _validate_references(
    references: Optional[Mapping[str, Any]], default_vault: str
) -> Tuple[Dict[str, _Ref], List[str]]:
    """``(valid, warnings)``: keep valid env names bound to parsed references."""
    valid: Dict[str, _Ref] = {}
    warnings: List[str] = []
    for name, ref in (references or {}).items():
        if not is_valid_env_name(str(name)):
            warnings.append(f"Skipping {name!r}: not a valid env-var name")
            continue
        try:
            valid[str(name)] = _parse_ref(ref, default_vault)
        except ValueError as exc:
            warnings.append(f"Skipping {name!r}: {exc}")
    return valid, warnings


def _refs_fingerprint(references: Mapping[str, _Ref]) -> str:
    material = "\n".join(
        f"{name}={references[name].vault}/{references[name].title}/{references[name].field}"
        for name in sorted(references)
    )
    return fingerprint(material)


# --- CLI plumbing -----------------------------------------------------------

# First matching rule wins (read/login errors only — a missing binary is detected
# by find_pass_cli before any call).
_PASS_ERROR_RULES = (
    (ErrorKind.TIMEOUT, ("timed out",)),
    (ErrorKind.AUTH_EXPIRED, ("session expired", "not logged in", "please log in",
                              "log in again", "unauthenticated")),
    (ErrorKind.AUTH_FAILED, ("unauthorized", "invalid personal access token",
                             "authentication failed", "401", "403", "permission denied")),
    (ErrorKind.REF_INVALID, ("not found", "no item", "does not exist", "unknown field",
                             "no such field", "invalid field")),
    (ErrorKind.NETWORK, ("network", "connection", "resolve host", "dns",
                         "temporary failure")),
)


def _classify_pass_error(message: str) -> ErrorKind:
    return classify_cli_error(message, _PASS_ERROR_RULES)


def find_pass_cli(binary_path: str = "") -> Optional[Path]:
    """Resolve a usable ``pass-cli``, or None. A pinned-but-missing path returns
    None rather than silently falling back to PATH."""
    if binary_path:
        pinned = Path(binary_path)
        return pinned if pinned.exists() else None
    found = shutil.which("pass-cli")
    return Path(found) if found else None


def _missing_binary_error(binary_path: str) -> str:
    if binary_path:
        return (f"secrets.protonpass.binary_path ({binary_path!r}) does not exist. "
                "Install the Proton Pass CLI or clear the path.")
    return ("Proton Pass references are configured but the pass-cli binary was not "
            "found. Install Proton Pass (https://proton.me/pass) or set binary_path.")


def _session_dir(home_path: Path) -> Path:
    directory = Path(home_path) / "cache" / _SESSION_DIRNAME
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # best effort: pass-cli can still run with its own default
    return directory


def _child_extra_env(token: str, session_dir: Path) -> Dict[str, str]:
    """Minimal extra env for a ``pass-cli`` child: audit marker, isolated session
    dir, the PAT, and the Windows/TMP basics ``run_secret_cli`` does not keep."""
    env: Dict[str, str] = {
        "PROTON_PASS_AGENT_REASON": _AGENT_REASON,
        "PROTON_PASS_SESSION_DIR": str(session_dir),
    }
    for key in ("APPDATA", "LOCALAPPDATA", "SystemRoot", "SYSTEMROOT", "TMP",
                "TEMP", "USERPROFILE", "HOME", "PATH"):
        value = os.environ.get(key)
        if value:
            env.setdefault(key, value)
    if token:
        env[_DEFAULT_TOKEN_ENV] = token
    return env


def _run(
    binary: Path, args: List[str], *, token: str, session_dir: Path,
    timeout: float = _CLI_TIMEOUT,
):
    return run_secret_cli(
        [str(binary), *args],
        extra_env=_child_extra_env(token, session_dir),
        timeout=timeout,
    )


def _login(
    binary: Path, token: str, session_dir: Path, timeout: float = _CLI_TIMEOUT
) -> Optional[str]:
    """Mint/refresh the agent session. Returns None on success (including a warm
    session reporting ``already authenticated`` on stderr), else the error text."""
    try:
        proc = _run(binary, ["login", "--pat", token], token=token,
                    session_dir=session_dir, timeout=timeout)
    except RuntimeError as exc:
        return str(exc)
    if proc.returncode == 0:
        return None
    err = (proc.stderr or proc.stdout or "").strip()
    if _ALREADY_AUTHENTICATED in err.lower():
        return None
    return err or f"pass-cli login exited {proc.returncode}"


def _read_field(
    binary: Path, ref: _Ref, *, token: str, session_dir: Path,
    timeout: float = _CLI_TIMEOUT,
) -> str:
    """Resolve one field. Raises ``RuntimeError`` on any CLI failure."""
    proc = _run(
        binary,
        ["item", "view", "--vault-name", ref.vault, "--item-title", ref.title,
         "--field", ref.field],
        token=token, session_dir=session_dir, timeout=timeout,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(err or f"pass-cli item view exited {proc.returncode}")
    return (proc.stdout or "").rstrip("\r\n")


# --- source -----------------------------------------------------------------


class ProtonPassSource(SecretSource):
    """Proton Pass as a registered **mapped** source (explicit per-var bindings,
    so its claims outrank bulk sources on contested vars)."""

    name = "protonpass"
    label = "Proton Pass"
    shape = "mapped"
    scheme = _SCHEME
    token_env_key = "pat_env"
    default_token_env = _DEFAULT_TOKEN_ENV
    # An explicit VAR->reference binding is the strongest user intent; a stale
    # .env line must not silently defeat it (1Password parity).
    override_existing_default = True
    _AUTH_HINT = ("Create a Viewer-scoped Proton Pass personal access token "
                  "(Settings -> API access) and set it in this plugin's settings "
                  "({token_env}).")
    remediation_hints = {
        ErrorKind.AUTH_FAILED: _AUTH_HINT,
        ErrorKind.AUTH_EXPIRED: _AUTH_HINT,
        ErrorKind.NOT_CONFIGURED: _AUTH_HINT,
        ErrorKind.BINARY_MISSING: ("Install the Proton Pass CLI (pass-cli) or set "
                                   "secrets.protonpass.binary_path / the binary_path setting."),
    }

    def __init__(self) -> None:
        self._ctx = None
        self._last_result: Optional[FetchResult] = None

    # -- config surfaces ----------------------------------------------------

    def bind_context(self, ctx) -> None:
        """Capture the PluginContext so ``fetch()`` can read gear-form settings."""
        self._ctx = ctx

    def _gear(self, key: str, default: Any = None) -> Any:
        if self._ctx is None:
            return default
        try:
            return self._ctx.get_config(key, default)
        except Exception:  # a broken settings read must never block a fetch
            return default

    def _merged_refs(self, cfg: Mapping[str, Any]) -> Dict[str, Any]:
        gear = self._gear("env_map")
        gear_env = gear if isinstance(gear, dict) else {}
        yaml_env = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
        merged: Dict[str, Any] = dict(gear_env)
        merged.update(yaml_env)  # YAML wins per variable
        return merged

    def _pick_str(self, cfg: Mapping[str, Any], key: str, gear_key: str, default: str) -> str:
        value = cfg.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        gear = self._gear(gear_key)
        if isinstance(gear, str) and gear.strip():
            return gear.strip()
        return default

    def _pick_value(self, cfg: Mapping[str, Any], key: str, gear_key: str, default: Any) -> Any:
        if cfg.get(key) is not None:
            return cfg[key]
        gear = self._gear(gear_key)
        return gear if gear is not None else default

    # -- contract hooks -----------------------------------------------------

    def is_enabled(self, cfg: dict) -> bool:
        """Enabled when configured: explicit flags win; otherwise the source turns
        itself on once either reference map has entries (no extra opt-in step)."""
        cfg = cfg if isinstance(cfg, dict) else {}
        flag = cfg.get("enabled")
        if flag is False:
            return False
        if flag is True:
            return True
        gear_flag = self._gear("enabled")
        if gear_flag is False:
            return False
        if gear_flag is True:
            return True
        yaml_env = cfg.get("env")
        if isinstance(yaml_env, dict) and yaml_env:
            return True
        gear_env = self._gear("env_map")
        return isinstance(gear_env, dict) and bool(gear_env)

    def override_existing(self, cfg: dict) -> bool:
        cfg = cfg if isinstance(cfg, dict) else {}
        flag = cfg.get("override_existing")
        if isinstance(flag, bool):
            return flag
        gear = self._gear("override_existing")
        if isinstance(gear, bool):
            return gear
        return self.override_existing_default

    def token_env(self, cfg: dict) -> str:
        if isinstance(cfg, dict):
            value = cfg.get(self.token_env_key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return self.default_token_env

    def fetch_timeout_seconds(self, cfg: dict) -> float:
        default = super().fetch_timeout_seconds({})
        raw = cfg.get("timeout_seconds") if isinstance(cfg, dict) else None
        if raw is None:
            raw = self._gear("timeout_seconds")
        if raw is None:
            return default
        value = coerce_float(raw, default)
        return value if value > 0 else default

    def config_schema(self) -> dict:
        """Informational only (the manifest ``config_schema`` drives the UI)."""
        return {
            "pat_env": {"description": "Env var holding the personal access token",
                        "default": _DEFAULT_TOKEN_ENV},
            "vault": {"description": "Default vault for 2-segment references",
                      "default": _DEFAULT_VAULT},
            "env": {"description": "Map of ENV_VAR -> ppass://[vault/]item/field",
                    "default": {}},
            "cache_ttl_seconds": {"description": "Disk cache TTL; 0 disables",
                                  "default": _DEFAULT_CACHE_TTL},
            "binary_path": {"description": "Pin pass-cli (empty = PATH)", "default": ""},
            "timeout_seconds": {"description": "Fetch wall-clock budget", "default": 120},
            "override_existing": {"description": "Overwrite .env/shell values",
                                  "default": True},
        }

    # -- fetch --------------------------------------------------------------

    def fetch(self, cfg: dict, home_path: Path) -> FetchResult:
        cfg = cfg if isinstance(cfg, dict) else {}
        result = FetchResult()
        home_path = Path(home_path)

        default_vault = self._pick_str(cfg, "vault", "vault", _DEFAULT_VAULT)
        valid, warnings = _validate_references(self._merged_refs(cfg), default_vault)
        result.warnings.extend(warnings)
        if not valid:
            return self._finish(result)  # nothing configured (or all refs skipped)

        pat_env = self.token_env(cfg)
        token = str(get_source_environment().get(pat_env, "") or "").strip()
        if not token:
            return self._finish(result.fail(
                f"{len(valid)} Proton Pass reference(s) are configured but {pat_env} "
                "is not set. Create a Viewer-scoped personal access token and add it "
                "in this plugin's settings.",
                ErrorKind.NOT_CONFIGURED,
            ))

        binary_path = self._pick_str(cfg, "binary_path", "binary_path", "")
        binary = find_pass_cli(binary_path)
        result.binary_path = binary
        if binary is None:
            return self._finish(result.fail(_missing_binary_error(binary_path),
                                            ErrorKind.BINARY_MISSING))

        cache_ttl = coerce_float(
            self._pick_value(cfg, "cache_ttl_seconds", "cache_ttl_seconds", _DEFAULT_CACHE_TTL),
            _DEFAULT_CACHE_TTL,
        )
        cache_key: _CacheKey = (fingerprint(token), _refs_fingerprint(valid))
        if cache_ttl > 0:
            cached = _STORE.lookup(cache_key, cache_ttl, home_path)
            if cached is not None:
                result.secrets = dict(cached.secrets)
                return self._finish(result)

        session = _session_dir(home_path)
        login_error = _login(binary, token, session)
        if login_error is not None:
            kind = _classify_pass_error(login_error)
            if kind is ErrorKind.INTERNAL:
                kind = ErrorKind.AUTH_FAILED
            result.error = f"pass-cli login failed: {login_error[:200]}"
            result.error_kind = kind
            return self._finish(self._stale_fallback(result, home_path, cache_key, cache_ttl))

        secrets, failures = self._resolve_all(
            binary, valid, token=token, session=session, result=result
        )
        result.secrets = secrets
        if cache_ttl > 0 and not failures and secrets:
            _STORE.store(cache_key, CachedFetch(secrets=dict(secrets), fetched_at=time.time()),
                         cache_ttl, home_path)
        return self._finish(result)

    def _resolve_all(
        self, binary: Path, valid: Mapping[str, _Ref], *, token: str,
        session: Path, result: FetchResult,
    ) -> Tuple[Dict[str, str], int]:
        secrets: Dict[str, str] = {}
        failures = 0
        relogged = False
        for name in sorted(valid):
            ref = valid[name]
            try:
                value = _read_field(binary, ref, token=token, session_dir=session)
            except RuntimeError as exc:
                kind = _classify_pass_error(str(exc))
                if kind is ErrorKind.AUTH_EXPIRED and not relogged:
                    relogged = True
                    if _login(binary, token, session) is None:
                        try:
                            value = _read_field(binary, ref, token=token, session_dir=session)
                        except RuntimeError as retry_exc:
                            result.warnings.append(f"{name}: {str(retry_exc)[:200]}")
                            failures += 1
                            continue
                    else:
                        result.warnings.append(f"{name}: {str(exc)[:200]}")
                        failures += 1
                        continue
                else:
                    result.warnings.append(f"{name}: {str(exc)[:200]}")
                    failures += 1
                    continue
            if not value.strip():
                result.warnings.append(
                    f"{name}: pass-cli returned an empty value for "
                    f"{ref.title!r} field {ref.field!r}"
                )
                failures += 1
                continue
            secrets[name] = value
        return secrets, failures

    def _stale_fallback(
        self, result: FetchResult, home_path: Path, cache_key: _CacheKey, cache_ttl: float
    ) -> FetchResult:
        """Serve a stale cache entry only for transport-class failures."""
        if result.error_kind not in (ErrorKind.NETWORK, ErrorKind.TIMEOUT):
            return result
        try:
            # ttl=inf reads the entry regardless of age; I/O errors → no fallback.
            cached = _STORE.disk.read(cache_key, float("inf"), home_path)
        except Exception:
            cached = None
        if cached is not None:
            result.secrets = dict(cached.secrets)
            result.warnings.append(
                "Served stale cached values: the Proton Pass backend was unreachable."
            )
        return result

    def _finish(self, result: FetchResult) -> FetchResult:
        self._last_result = result
        return result


# --- plugin registration ----------------------------------------------------


def _status_command(source: ProtonPassSource, ctx) -> None:
    """Read-only ``hermes protonpass status``."""
    cfg: Dict[str, Any] = {}
    try:
        from hermes_cli.config import load_config_readonly

        data = load_config_readonly() or {}
        section = data.get("secrets") if isinstance(data, dict) else {}
        if isinstance(section, dict) and isinstance(section.get("protonpass"), dict):
            cfg = dict(section["protonpass"])
    except Exception:
        cfg = {}

    pat_env = source.token_env(cfg)
    token = str(os.environ.get(pat_env, "") or "").strip()
    refs = source._merged_refs(cfg)
    default_vault = source._pick_str(cfg, "vault", "vault", _DEFAULT_VAULT)
    valid, warnings = _validate_references(refs, default_vault)
    binary = find_pass_cli(source._pick_str(cfg, "binary_path", "binary_path", ""))

    home = None
    try:
        from hermes_constants import get_hermes_home

        home = get_hermes_home()
    except Exception:
        home = None

    print("Proton Pass secret source")
    print(f"  Enabled:        {'yes' if source.is_enabled(cfg) else 'no'}")
    print(f"  Token:          {'set' if token else 'not set'} ({pat_env})")
    print(f"  pass-cli:       {binary if binary else 'not found (set binary_path)'}")
    print(f"  Default vault:  {default_vault}")
    print(f"  References:     {len(valid)} configured")
    for warning in warnings:
        print(f"    ! {warning}")

    if home is not None:
        try:
            path = _STORE.disk.path(home)
            if path.is_file():
                import json

                with open(path, "r", encoding="utf-8-sig") as handle:
                    payload = json.load(handle)
                fetched_at = float(payload.get("fetched_at", 0) or 0)
                age = max(0, int(time.time() - fetched_at))
                print(f"  Cache:          {path.name} (age {age}s)")
            else:
                print("  Cache:          absent")
        except Exception:
            print("  Cache:          unreadable")

    last = getattr(source, "_last_result", None)
    if last is not None:
        if last.ok:
            print(f"  Last fetch:     ok ({len(last.secrets)} value(s))")
        else:
            print(f"  Last fetch:     {last.error_kind.value if last.error_kind else 'error'} "
                  f"- {last.error}")
        for warning in last.warnings:
            print(f"    ! {warning}")


def register(ctx) -> None:  # noqa: ANN001 - PluginContext is host-provided
    """Hermes plugin entry point."""
    source = ProtonPassSource()
    source.bind_context(ctx)
    ctx.register_secret_source(source)

    def _setup_cli(parser) -> None:  # noqa: ANN001 - argparse subparser
        sub = parser.add_subparsers(dest="protonpass_command")
        status = sub.add_parser("status", help="Show Proton Pass secret-source status")
        status.set_defaults(func=_handler)
        parser.set_defaults(func=_handler)

    def _handler(_args) -> None:  # noqa: ANN001 - argparse namespace
        _status_command(source, ctx)

    ctx.register_cli_command(
        "protonpass",
        "Proton Pass secret source",
        _setup_cli,
        _handler,
        description="Inspect the Proton Pass secret source (read-only).",
    )


__all__ = [
    "ProtonPassSource",
    "clear_caches",
    "find_pass_cli",
    "register",
    "_parse_ref",
    "_validate_references",
]
