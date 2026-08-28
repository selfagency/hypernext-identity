---
title: "Configuration reference"
weight: 10
---

# Configuration reference

Every `config.yml` key that the server actually reads, its default, and its
effect. This page is verified against `internal/server/config.go` (the
`Config` struct + `Validate()`), **not** against `config.example.yml` — the
example file may contain commented, illustrative keys that are not yet
implemented, and only the keys below are read into the program.

```yaml
# Minimal config.yml
domain: example.com
data_dir: ./data
```

## Top-level

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `domain` | string | — (**required**) | Apex domain. Tenants resolve on subdomains; the identity host is derived as `id.<domain>`. |
| `identity_host` | string | `""` | Explicit identity host. The router currently derives the identity host as `id.<domain>` internally; set this only if you also override routing. |
| `data_dir` | string | — (**required**) | Directory for SQLite files, blobs, keys, and the cert cache. Created if missing (mode `0750`). |

## `storage`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `storage.backend` | string | `fs` | `fs` (local filesystem under `data_dir/blobs`) or `s3` (S3-compatible). Any other value is rejected. |
| `storage.s3.endpoint` | string | `""` | S3 endpoint URL. **Required** when `backend = s3`. |
| `storage.s3.bucket` | string | `""` | Bucket name. |
| `storage.s3.access_key` | string | `""` | Access key. |
| `storage.s3.secret_key` | string | `""` | Secret key. |
| `storage.s3.region` | string | `""` | Region (if your endpoint needs it). |

`storage.s3` (the whole block) is required when `storage.backend = s3`; the
server fails to start with `storage.s3 is required when backend=s3` otherwise.

## `sqlite`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `sqlite.mode` | string | `per_tenant` | `per_tenant` (one DB per tenant) or `single`. Any other value is rejected. |
| `sqlite.single.path` | string | `""` | Database path when `sqlite.mode = single`. |

> The account-data store opened at startup is `data_dir/identity.db`. The
> `sqlite.mode` / `sqlite.single.path` keys select the tenant-data layout; see
> [Architecture](../explanation/architecture.md) for how the two relate.

## `tls`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `tls.enabled` | bool | `false` | Enable ACME-managed TLS (certmagic). |
| `tls.email` | string | `""` | Contact email for ACME registration. |

## `ipfs`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `ipfs.enabled` | bool | `false` | Enable the optional IPFS pinning **client** (talks to a Kubo RPC at `127.0.0.1:5001`). No standalone endpoint; no embedded node. |

## `atproto`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `atproto.did_method` | string | `""` | DID method for new atproto accounts (`plc` or `web`). |

## `backup`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `backup.cron_expr` | string | `""` | Cron expression for scheduled backups. Empty disables the scheduler. |

## `log`

| Key | Type | Default | Purpose |
|:----|:-----|:--------|:--------|
| `log.level` | string | `info` | `debug`, `info`, `warn`, or `error`. |
| `log.format` | string | `text` | Log output format. |

## Full example

```yaml
domain: example.com
data_dir: ./data

storage:
  backend: fs            # or s3
  # s3:
  #   endpoint: https://s3.example.com
  #   bucket: sovereign
  #   access_key: ...
  #   secret_key: ...
  #   region: us-east-1

sqlite:
  mode: per_tenant       # or single
  # single:
  #   path: ./data/tenants.db

tls:
  enabled: false
  email: admin@example.com

ipfs:
  enabled: false

atproto:
  did_method: plc

backup:
  cron_expr: ""          # e.g. "0 3 * * *" for a nightly 03:00 backup

log:
  level: info
  format: text
```

Every key above can also be set via an environment variable — see the
[environment variable reference](environment.md). The listen address and
config-file path are CLI flags, not config keys — see the
[CLI reference](cli.md).
