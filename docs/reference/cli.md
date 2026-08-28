---
title: "CLI reference"
weight: 30
---

# CLI reference

The `sovereign` command, its subcommands, and its flags. Verified against
`cmd/sovereign/main.go`.

Build and run:

```bash
CGO_ENABLED=0 go build -o sovereign ./cmd/sovereign
./sovereign serve --config config.yml
```

## Commands

| Command | Purpose |
|:--------|:--------|
| `sovereign serve` | Run the identity HTTP server (the default workload). |
| `sovereign version` | Print the build version. |

## Flags

Flags are persistent, so they apply to every subcommand.

| Flag | Default | Purpose |
|:-----|:--------|:--------|
| `--config` | `config.yml` | Path to the YAML config file. |
| `--addr` | `:8080` | Listen address (`host:port`). |

> The listen default is **`:8080`** (HTTP). When `tls.enabled` is set you
> typically front the server with TLS on `:443` via certmagic; the `--addr`
> default itself does not change.

## Precedence

A **flag** beats an **environment variable**, which beats the **config
file**, which beats the built-in **default**:

```text
flag  >  environment variable (SOVEREIGN_*)  >  config file  >  default
```

For example, the listen address is resolved in this order:

1. `--addr :9090`
2. `SOVEREIGN_ADDR=:9090`
3. (no `addr` config key exists — `--addr` is flag/env only)
4. default `:8080`

See the [environment variable reference](environment.md) and the
[configuration reference](configuration.md).
