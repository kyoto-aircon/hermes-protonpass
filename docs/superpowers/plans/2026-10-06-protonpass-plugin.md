# hermes-protonpass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax.

**Goal:** Ship a Hermes secret-source plugin that resolves `ppass://` references from Proton
Pass (`pass-cli`) into environment variables at startup, configurable from the Plugins UI.

**Architecture:** One `ProtonPassSource(SecretSource)` (mapped shape, `ppass` scheme) plus a
`plugin.yaml` whose `config_schema` drives the Desktop/TUI settings form. `register(ctx)`
captures `ctx` so `fetch()` can read gear-form settings lazily; the source is enabled when
configured and honors an explicit `enabled` flag. Resolution shells out to `pass-cli` through
`run_secret_cli` (minimal env, field-level reads only), with a TTL disk cache.

**Tech Stack:** Python 3 stdlib only; pytest; Hermes `agent.secret_sources` ABC + conformance kit.

**Spec:** `docs/superpowers/specs/2026-10-06-protonpass-plugin-design.md`

## Global Constraints

- Python stdlib only at runtime (no third-party runtime deps).
- `requires_hermes: ">=0.21.5"`, `manifest_version: 2`, `api_version: 1`, `kind: backend`.
- Source attributes: `name="protonpass"`, `label="Proton Pass"`, `shape="mapped"`,
  `scheme="ppass"`, `token_env_key="pat_env"`,
  `default_token_env="PROTON_PASS_PERSONAL_ACCESS_TOKEN"`, `override_existing_default=True`.
- Never run `pass-cli item view --output json` (totp/passkey leak on agent sessions).
- PAT appears on argv only in `pass-cli login --pat <PAT>`; child env always carries the PAT,
  `PROTON_PASS_AGENT_REASON`, and `PROTON_PASS_SESSION_DIR`.
- `fetch()` must never raise and never prompt; malformed cfg yields a `FetchResult`.
- Tests add the installed Hermes tree to `sys.path` via `conftest.py` (env override
  `HERMES_AGENT_DIR`).

---

### Task 1: Scaffold + test harness

**Files:** Create `.gitignore`, `LICENSE`, `pytest.ini`, `conftest.py`, `tests/__init__.py`

- [ ] Write `.gitignore` (`__pycache__/`, `*.pyc`, `.pytest_cache/`, `*.egg-info/`, `.venv/`).
- [ ] Write MIT `LICENSE`.
- [ ] Write `pytest.ini` (`testpaths = tests`, `python_files = test_*.py`).
- [ ] Write `conftest.py` adding `$HERMES_AGENT_DIR` (default the local install path) to `sys.path`.
- [ ] Run `python -m pytest -q` → collects 0 tests, exit 5 is acceptable pre-tests; commit.

### Task 2: `plugin.yaml` manifest

**Files:** Create `plugin.yaml`; Test `tests/test_plugin_manifest.py`

- [ ] Test: YAML loads; `name == "protonpass"`, `kind == "backend"`, `requires_hermes` set;
  `config_schema` has keys `pat,vault,env_map,cache_ttl_seconds,binary_path,timeout_seconds,override_existing,enabled`;
  `pat` has `type: secret` + `env: PROTON_PASS_PERSONAL_ACCESS_TOKEN`.
- [ ] Write `plugin.yaml` per spec §9.
- [ ] Run test → PASS; commit.

### Task 3: Source skeleton + conformance

**Files:** Create `__init__.py`; Test `tests/test_conformance.py`

- [ ] Test: `ProtonPassSourceConformance(SecretSourceConformance)` with a `source` fixture
  returning `ProtonPassSource()` (no ctx).
- [ ] Implement class attrs, `__init__`, `_gear`, `is_enabled`, `override_existing`,
  `token_env`, `fetch_timeout_seconds`, `config_schema`, and a fast-path `fetch` that returns
  ok-empty when there are no refs; `register(ctx)` stub.
- [ ] Run conformance → PASS; commit.

### Task 4: Ref parsing + config merge

**Files:** Modify `__init__.py`; Test `tests/test_config.py`

- [ ] Tests: `_parse_ref` for both forms, URL-decoding, malformed cases; `_validate_references`
  warnings; `_merged_refs` union with YAML winning; `is_enabled` matrix (unconfigured false,
  explicit true/false, gear-configured true).
- [ ] Implement `_Ref`, `_parse_ref`, `_validate_references`, `_merged_refs`, `_pick_str`,
  `_pick_value`.
- [ ] Run → PASS; commit.

### Task 5: pass-cli runner + fake shim

**Files:** Modify `__init__.py`; Create `tests/fake_pass_cli.py`, `tests/conftest.py`
(fixture `fake_pass`); Test `tests/test_cli.py`

- [ ] Fixture writes `fake_pass_cli.py` + platform wrapper (`.cmd`/`.sh`), returns paths and a
  `read_log()` helper. Fake logs `{argv, pat, session_dir, reason}` per call; serves field
  values; exits non-zero on unknown item; exits 3 if `--output json` appears.
- [ ] Tests: `find_pass_cli`, `_login` idempotency, PAT only in login argv, reason+session on
  every call, no `--output json`.
- [ ] Implement `find_pass_cli`, `_child_extra_env`, `_session_dir`, `_run`, `_login`,
  `_read_field`, `_classify_pass_error`.
- [ ] Run → PASS; commit.

### Task 6: Full `fetch()` flow

**Files:** Modify `__init__.py`; Test `tests/test_fetch.py`

- [ ] Tests: no PAT + refs → `NOT_CONFIGURED`; missing binary → `BINARY_MISSING`; success maps
  values; empty field skipped with warning; unknown item warns but resolves the rest; expiry
  re-login retry; malformed cfg returns `FetchResult`.
- [ ] Implement the full `fetch` flow (spec §5).
- [ ] Run → PASS; commit.

### Task 7: Disk cache

**Files:** Modify `__init__.py`; Test `tests/test_cache.py`

- [ ] Tests: second fetch with same refs performs no CLI calls; `cache_ttl_seconds: 0` disables;
  ref change busts cache; only complete pulls cached; stale served on NETWORK only.
- [ ] Implement cache key + lookup/store + stale fallback; `clear_caches`.
- [ ] Run → PASS; commit.

### Task 8: `hermes protonpass status`

**Files:** Modify `__init__.py`; Test `tests/test_status.py`

- [ ] Test: `_status_command` output includes enabled/binary/refs; never prints a PAT value
  (inject a sentinel token and assert absence).
- [ ] Implement `_setup_cli` + `_status_command`; wire into `register`.
- [ ] Run → PASS; commit.

### Task 9: README

**Files:** Create `README.md`

- [ ] Install, PAT creation (Viewer role), both config surfaces, ref format, status, security.

### Task 10: Validate + publish

- [ ] `python -m pytest -q` all green.
- [ ] `hermes plugins validate . --install-deps` green.
- [ ] Local install smoke test (`hermes plugins install <local path>`), confirm `hermes protonpass status`.
- [ ] `gh repo create epicawesomesauce/hermes-protonpass --public --source . --push` (confirm first).
