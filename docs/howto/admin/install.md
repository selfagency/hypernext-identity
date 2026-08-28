---
title: "Install Sovereign"
weight: 10
---

# Install Sovereign

This guide gets a Sovereign binary built and running on your machine or a
small VPS. It assumes you can edit a YAML file and run shell commands. It does
**not** assume systems or cryptography expertise.

> **What you get at the end:** a running `sovereign` process serving the live
> HTTP routes on your chosen address, including the OIDC/WebAuthn sign-in
> flow and the admin surface on the identity host (`id.<domain>`). Account
> provisioning and the admin UI are covered in the
> [admin how-to](_index.md).

## Prerequisites

| Requirement | Why | Check |
|:------------|:----|:------|
| Go (see `go.mod`) | build the binary | `go version` |
| A domain you control | tenants resolve on subdomains | — |
| A machine to run it on | any Linux/macOS host or VPS | — |

No database server, no cache, no message queue — SQLite and the filesystem are
built in (see [ADR 0001](../../explanation/design-decisions/0001-single-binary-sqlite.md)).

## 1. Get the source and build

```bash
git clone https://github.com/selfagency/sovereign.git
cd sovereign

# Static binary, no CGO (portable, no C toolchain needed).
CGO_ENABLED=0 go build -o sovereign ./cmd/sovereign
```

Or use the task runner:

```bash
task build   # produces ./sovereign
```

Verify:

```bash
./sovereign version
```

## 2. Configure

Copy the example config and edit it:

```bash
cp config.example.yml config.yml
```

The **two required keys** are `domain` and `data_dir`:

```yaml
domain: example.com     # your apex domain
data_dir: ./data        # SQLite, blobs, keys, cert cache
```

Everything else has a working default. See the
[configuration reference](../../reference/configuration.md) for every key —
and note that `config.example.yml` may show commented keys that are not yet
implemented; the reference page lists only what the server actually reads.

> **`config.yml` is git-ignored** because it can hold secrets (S3 keys). Keep
> it out of version control.

## 3. Run

```bash
./sovereign serve --config config.yml
# or choose the listen address:
./sovereign serve --config config.yml --addr :8080
```

The server:

1. creates `data_dir` if missing,
2. opens the account store at `data_dir/identity.db` (running migrations),
3. builds the blob backend (`fs` under `data_dir/blobs`, or S3),
4. mounts the [live routes](../../reference/api/_index.md),
5. listens on `--addr` (default `:8080`) with graceful shutdown on
   `SIGINT`/`SIGTERM`.

## 4. Verify it is up

```bash
curl http://localhost:8080/.well-known/nodeinfo
```

You should get a NodeInfo document advertising `sovereign`. (WebFinger and the
tenant routes need a real Host header for a known tenant; NodeInfo is the
simplest liveness check.)

## 5. Point DNS at it (for real use)

For tenants to resolve, you need a **wildcard DNS record** so
`alice.example.com`, `bob.example.com`, … all reach the server:

```text
*.example.com   A   <your-server-ip>
example.com     A   <your-server-ip>
```

Tenant hosts are derived from the request `Host` header; without wildcard DNS,
only the apex domain reaches the server. TLS (for HTTPS) uses ACME — see
[`tls.enabled`](../../reference/configuration.md#tls).

## Running as a service (optional)

A minimal `systemd` unit:

```ini
[Unit]
Description=Sovereign identity server
After=network.target

[Service]
ExecStart=/usr/local/bin/sovereign serve --config /etc/sovereign/config.yml
Restart=on-failure
# Run unprivileged; data_dir must be writable by this user.
User=sovereign

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|:--------|:-------------|:----|
| `config: domain is required` | missing `domain` | set it in `config.yml` |
| `config: storage.s3 is required when backend=s3` | `backend: s3` without the `s3` block | add `storage.s3.*` or use `backend: fs` |
| `read config: …` on startup | `--config` points at a missing file | pass a real path, or omit `--config` to use defaults |
| tenant routes `404` | Host header not a known tenant | create the tenant; check wildcard DNS |

## Next steps

* [Configuration reference](../../reference/configuration.md) — every key.
* [HTTP API reference](../../reference/api/_index.md) — the live routes.
* [Architecture](../../explanation/architecture.md) — how it fits together.
