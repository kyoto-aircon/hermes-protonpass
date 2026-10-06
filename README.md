# hermes-protonpass

Proton Pass **secret source** plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

It resolves mapped `ppass://` references through the official Proton Pass CLI
(`pass-cli`) into environment variables at process startup — the same model as
the bundled 1Password source, but for Proton Pass.

> **Scope.** This plugin covers *startup secret hydration* (`hermes secrets`).
> The browser-autofill credential vault (`hermes vault`) is a separate,
> core-owned subsystem with no plugin seam; it ships its own Proton Pass backend
> upstream. This plugin is complementary.

## Requirements

- Hermes Agent `>= 0.21.5`
- The official Proton Pass CLI (`pass-cli`) installed and on `PATH`
  - Windows: bundled with the Proton Pass desktop app
    (`%LOCALAPPDATA%\Programs\ProtonPass\pass-cli.exe`)
  - Or pin it with the `binary_path` setting / `secrets.protonpass.binary_path`
- A Proton Pass **personal access token** (PAT):
  Proton Pass → Settings → API access (`https://account.proton.me/pass/api-access`).
  A read-only `Viewer` grant on the target vault is recommended.

## Install

```bash
hermes plugins install epicawesomesauce/hermes-protonpass
```

Then configure it from the Hermes UI: **Capabilities → Plugins → Proton Pass → gear**.
The plugin is enabled automatically once a reference map is present.

## Configuration

There are two config surfaces. They are merged for `fetch()` with
**YAML winning per key** (`secrets.protonpass` > plugin settings > defaults).

### 1. Plugin settings form (recommended)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `pat` | secret | — | PAT, stored in `.env` as `PROTON_PASS_PERSONAL_ACCESS_TOKEN` |
| `vault` | string | `Personal` | Default vault for 2-segment references |
| `env_map` | dict | `{}` | Map of `ENV_VAR → ppass://…` reference |
| `cache_ttl_seconds` | int | `300` | Disk cache TTL; `0` disables caching |
| `binary_path` | string | `""` | Pin `pass-cli`; empty = search `PATH` |
| `timeout_seconds` | int | `120` | Fetch wall-clock budget |
| `override_existing` | bool | `true` | Overwrite existing `.env`/shell values |
| `enabled` | bool | `true` | Master switch |

### 2. `~/.hermes/config.yaml`

```yaml
secrets:
  protonpass:
    enabled: true
    # optional: point at a non-default token variable
    # pat_env: PROTON_PASS_PERSONAL_ACCESS_TOKEN
    vault: Personal
    env:
      OPENAI_API_KEY: ppass://Personal/OpenAI/password
      GITHUB_TOKEN: ppass://Personal/GitHub/password
```

## Reference format

```
ppass://<vault>/<item-title>/<field>    # explicit vault
ppass://<item-title>/<field>            # uses the configured default vault
```

Common fields: `password`, `username`, `email`, `urls`, `totp_uri`.
URL-encode item titles containing `/` or spaces (e.g. `My%20Item`).

## Security

- The PAT travels on **argv only** for `pass-cli login --pat` and in the child
  environment; it is never logged or printed.
- Field reads use `pass-cli item view --field …` exclusively — **never**
  `--output json` on `item view`, which would expose `totp_uri`/passkeys on
  agent sessions.
- Every call carries the mandatory `PROTON_PASS_AGENT_REASON` audit marker and
  an isolated `PROTON_PASS_SESSION_DIR`.
- `fetch()` never raises and never prompts; a failure surfaces as a status line
  and the rest of the startup continues.

## Status

```bash
hermes protonpass status
```

Read-only: shows enablement, whether the token is set (never its value), the
resolved `pass-cli`, default vault, reference count, cache age, and the last
fetch result.

## Development

```bash
python -m pytest
```

Tests run against your installed Hermes Agent tree; set `HERMES_AGENT_DIR` to
override its location.

## License

MIT — see [LICENSE](LICENSE).
