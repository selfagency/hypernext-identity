---
title: "Environment variables"
weight: 20
---

# Environment variables

Configuration can be supplied through environment variables instead of (or in
addition to) `config.yml`. The prefix is **`SOVEREIGN_`**, and nested config
keys map to uppercase with underscores. Verified against `initConfig` in
`cmd/sovereign/main.go` (Viper: `SetEnvPrefix("SOVEREIGN")` +
`AutomaticEnv()` + a `.`/`-` → `_` replacer).

Mapping rule:

```text
config key:        storage.backend
environment var:   SOVEREIGN_STORAGE_BACKEND
```

Precedence: **flag > environment variable > config file > default.**

## Supported variables

These map to keys in the `Config` struct (`internal/server/config.go`) and are
resolved when the config is unmarshalled.

| Config key | Environment variable |
|:-----------|:---------------------|
| `domain` | `SOVEREIGN_DOMAIN` |
| `identity_host` | `SOVEREIGN_IDENTITY_HOST` |
| `data_dir` | `SOVEREIGN_DATA_DIR` |
| `storage.backend` | `SOVEREIGN_STORAGE_BACKEND` |
| `storage.s3.endpoint` | `SOVEREIGN_STORAGE_S3_ENDPOINT` |
| `storage.s3.bucket` | `SOVEREIGN_STORAGE_S3_BUCKET` |
| `storage.s3.access_key` | `SOVEREIGN_STORAGE_S3_ACCESS_KEY` |
| `storage.s3.secret_key` | `SOVEREIGN_STORAGE_S3_SECRET_KEY` |
| `storage.s3.region` | `SOVEREIGN_STORAGE_S3_REGION` |
| `sqlite.mode` | `SOVEREIGN_SQLITE_MODE` |
| `sqlite.single.path` | `SOVEREIGN_SQLITE_SINGLE_PATH` |
| `tls.enabled` | `SOVEREIGN_TLS_ENABLED` |
| `tls.email` | `SOVEREIGN_TLS_EMAIL` |
| `ipfs.enabled` | `SOVEREIGN_IPFS_ENABLED` |
| `atproto.did_method` | `SOVEREIGN_ATPROTO_DID_METHOD` |
| `backup.cron_expr` | `SOVEREIGN_BACKUP_CRON_EXPR` |
| `log.level` | `SOVEREIGN_LOG_LEVEL` |
| `log.format` | `SOVEREIGN_LOG_FORMAT` |

## CLI-only variables

The two persistent flags are bound to Viper, so they also accept an
environment override. They are **not** config-file keys.

| Flag | Environment variable |
|:-----|:---------------------|
| `--config` | `SOVEREIGN_CONFIG` |
| `--addr` | `SOVEREIGN_ADDR` |

## Notes

* Booleans (`tls.enabled`, `ipfs.enabled`) accept the usual truthy/falsey
  strings (`true`/`false`, `1`/`0`).
* `SOVEREIGN_CONFIG` only takes effect if the `--config` flag was not passed
  (flag beats env). If neither is set, the default `config.yml` is used.
* Environment variables only take effect for keys the program actually reads.
  Every key above is read; a `SOVEREIGN_*` variable for a key that does not
  exist in `Config` is silently ignored.
