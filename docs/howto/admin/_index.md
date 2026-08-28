---
title: "Administrator how-to"
weight: 10
---

# Administrator how-to guides

Guides for the person who **installs and operates** a Sovereign server.
These assume you can edit a YAML file and run a command, but they do **not**
assume you are a systems or cryptography expert. Wherever a decision is
needed, the guide says what to choose and why.

## Available now

* **[Install Sovereign](install.md)** — build the binary, configure
  `config.yml`, run the server, and point DNS at it.
* **Admin surface** — the identity host (`id.<domain>`) serves the admin
  routes `/admin/backup` and `/admin/moderation/takedown`, protected by an
  admin bearer token. The first user created is the instance admin; admins
  can add users and grant admin access.

## Reference you will need

* [Configuration reference](../../reference/configuration.md) — every key the
  server reads, its default, and its effect.
* [Environment variables](../../reference/environment.md) — the `SOVEREIGN_*`
  overrides.
* [CLI reference](../../reference/cli.md) — `serve`, `version`, and flags.

## Not yet available (feature not mounted)

These operations depend on subsystems that are implemented but **not yet
wired** to a live route, so there is no honest admin guide for them yet. They
are tracked on the [status page](../../explanation/status.md):

| Guide | Blocked on |
|:------|:-----------|
| Add and manage tenants | tenant-provisioning surface |
| Set up TLS wildcard (DNS-01) | ACME verification |

> Each of these will be written the moment its handler is mounted and has an
> e2e test — not before.
