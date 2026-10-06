# hermes-protonpass — Design Specification

**Date:** 2026-10-06
**Status:** Approved
**Author:** Spheraz

## 1. Purpose

A Hermes Agent *secret source* plugin that resolves environment-variable values
from Proton Pass at process startup, mirroring the bundled 1Password secret
source. Users map env-var names to `ppass://` references; Hermes hydrates them
into the environment before the rest of the process reads credentials.

This is **not** the browser-autofill credential vault. The vault backend system
(`agent/vault_backends/`) is a closed, hard-coded tuple in Hermes core with no
plugin seam; an upstream PR already adds Proton Pass there. This plugin targets
only the `secrets:` startup-hydration seam, which is explicitly plugin-extensible
via `PluginContext.register_secret_source()`.

## 2. Goals / Non-goals

**Goals**
- Mirror the 1Password source's shape and UX (`mapped` refs, in-process + disk cache).
- Resolve references through the official Proton Pass CLI, `pass-cli`.
- Be fully configurable from the Hermes Plugins settings UI (Desktop gear form).
- Pass the bundled `SecretSourceConformance` kit.
- Be installable directly from GitHub (`hermes plugins install Spheraz/hermes-protonpass`)
  and, optionally, submittable to the catalog later.

**Non-goals**
- Browser autofill / `browser_vault_*` tools (core-owned; no plugin hook).
- Writing credentials back to Proton Pass.
- Bundling or auto-installing `pass-cli` (user-provided; detection only).

## 3. Architecture

```
plugin.yaml          manifest + config_schema (drives the Plugins settings UI)
__init__.py          ProtonPassSource(SecretSource) + register(ctx) + `hermes protonpass` CLI
tests/               conformance + unit tests (fake pass-cli shim)
README.md / LICENSE
```

`register(ctx)` captures `ctx`, constructs one `ProtonPassSource`, and calls
`ctx.register_secret_source(source)`. It also registers a read-only
`hermes protonpass status` CLI command.

### 3.1 Config surfaces (two disjoint stores)

Hermes does **not** merge plugin UI settings into the `secrets.<name>` section
passed to `fetch()`. The plugin therefore deliberately supports two surfaces:

| Surface | Store | Who reads it |
|---|---|---|
| `secrets.protonpass` in `config.yaml` | `secrets:` section | the orchestrator (`is_enabled(cfg)`, `fetch(cfg, home)`) |
| Plugins settings gear form | `plugins.entries.<id>.settings` | the source via `self._ctx.get_config(key)` |

Merge precedence inside the source: **YAML `secrets.protonpass` wins per key**,
then gear-form settings, then defaults. Reference maps (`env` and `env_map`) are
union-merged with the YAML map winning per variable.

The PAT is never stored in either config store: the `type: secret` field writes
to `~/.hermes/.env` under `PROTON_PASS_PERSONAL_ACCESS_TOKEN`.

### 3.2 Enablement

The conformance contract requires a source to be disabled by default
(`is_enabled({}) is False`). To avoid an extra opt-in step for UI users the
source is **enabled when configured**: explicit `enabled: true` enables,
explicit `enabled: false` disables, and otherwise the source enables itself if
either reference map is non-empty. An enabled source with no references is a
zero-cost no-op (no CLI calls).

## 4. Reference format

```
ppass://vault/item-title/field      # explicit vault
ppass://item-title/field            # default vault (config `vault`, default "Personal")
```

Segments are URL-decoded; titles containing `/` must URL-encode it (`%2F`).
`field` is one of the `pass-cli item view --field` names: `password`, `username`,
`email`, `urls`, `totp_uri` (any field `pass-cli` accepts).

Malformed references are skipped with a warning; a variable whose value resolves
empty is skipped with a warning (the classic wrong-`--field` pitfall).

## 5. Resolution flow (`fetch`)

1. Parse + validate refs. No refs → `FetchResult.ok` with nothing (fast path).
2. Resolve PAT from the env var named by `pat_env`
   (default `PROTON_PASS_PERSONAL_ACCESS_TOKEN`) using `get_source_environment()`.
   Missing PAT with refs present → `NOT_CONFIGURED`.
3. Resolve `pass-cli` (`binary_path` config, else `shutil.which("pass-cli")`).
   Missing → `BINARY_MISSING`.
4. Cache lookup (`<home>/cache/ppass_cache.json`, TTL, complete pulls only).
5. `pass-cli login --pat <PAT>` — idempotent; stderr "already authenticated" is a
   warm session (success). The PAT appears on argv **only** in this call and in
   the child env.
6. Per ref, one `pass-cli item view --vault-name V --item-title T --field F`.
   **Never** `item view --output json` (that leaks `totp_uri`/passkeys on agent
   sessions).
7. On an expiry-classified read error, re-login once and retry that ref.
8. Per-ref failures become warnings; the rest still resolve. Only a complete,
   error-free, non-empty pull is cached.
9. Stale cache is served only for `NETWORK`/`TIMEOUT` failures.

### 5.1 Child environment (secret confinement)

Every `pass-cli` call runs through `run_secret_cli()` with:
- minimal allowlisted base env (PATH/HOME/…),
- `PROTON_PASS_PERSONAL_ACCESS_TOKEN` = the resolved PAT,
- `PROTON_PASS_SESSION_DIR` = `<home>/cache/ppass-session` (isolated),
- `PROTON_PASS_AGENT_REASON` = a fixed audit marker,
- `NO_COLOR=1`, stdin `/dev/null` (never prompt).

## 6. Error taxonomy

`NOT_CONFIGURED`, `BINARY_MISSING`, `AUTH_FAILED`, `AUTH_EXPIRED`, `REF_INVALID`,
`NETWORK`, `EMPTY_VALUE`, `TIMEOUT`, `INTERNAL` — via `classify_cli_error` rules
over `pass-cli` stderr text.

## 7. Cache

Reuses `agent.secret_sources._cache.SecretCache` (same substrate as 1Password):
in-process dict over an atomic `0600` JSON file. Key = PAT fingerprint + refs
fingerprint. TTL from `cache_ttl_seconds` (0 disables both layers). Values only —
never tokens.

## 8. `hermes protonpass status`

Read-only. Prints: enabled, PAT presence (never the value), resolved binary,
default vault, reference count, cache freshness, and the last fetch error if the
startup pass ran in this process. No config writes.

## 9. Config schema (Plugins UI)

| Key | Type | Default | Meaning |
|---|---|---|---|
| `pat` | secret (`PROTON_PASS_PERSONAL_ACCESS_TOKEN`) | — | Proton Pass PAT (Viewer role) |
| `vault` | str | `Personal` | Default vault for 2-segment refs |
| `env_map` | dict (JSON) | `{}` | `ENV_VAR → ppass://…` map |
| `cache_ttl_seconds` | int | `300` | Disk cache TTL (0 = off) |
| `binary_path` | str | `""` | Pin `pass-cli` (empty = PATH) |
| `timeout_seconds` | int | `120` | Fetch wall-clock budget |
| `override_existing` | bool | `true` | Overwrite `.env`/shell values |
| `enabled` | bool | `true` | Master switch |

YAML equivalents live under `secrets.protonpass` (`env`, `pat_env`, `vault`,
`binary_path`, `cache_ttl_seconds`, `timeout_seconds`, `override_existing`,
`enabled`).

## 10. Testing

- `SecretSourceConformance` subclass (green = review bar).
- Ref parsing / config merge unit tests.
- Fake `pass-cli` shim (`.cmd` on Windows) that logs argv + child env:
  - PAT only in `login --pat` argv and child env,
  - `PROTON_PASS_AGENT_REASON` + `PROTON_PASS_SESSION_DIR` on every call,
  - field-reads only (no `--output json` on `item view`),
  - values resolved, empty field skipped, unknown item warns,
  - cache hit/miss/TTL, malformed cfg never raises.
- `plugin.yaml` parses and declares the expected schema.

## 11. Distribution

1. `hermes plugins validate . --install-deps` green.
2. Publish to `github.com/Spheraz/hermes-protonpass`.
3. Direct install: `hermes plugins install Spheraz/hermes-protonpass`.
4. Optional later: catalog submission PR (pinned full SHA) to
   `NousResearch/hermes-agent` `plugin-catalog/`.
