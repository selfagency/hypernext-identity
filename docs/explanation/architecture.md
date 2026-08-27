---
title: "Architecture"
weight: 10
---

# Architecture

> **Status: scaffold.** This page is expanded in the implementation phases.
> What follows is the load-bearing shape that the documentation depends on.

Sovereign is a **single Go process** that owns identity, auth, storage,
protocol adapters, and personal data for many tenants.

```text
                         ┌─────────────────────────────────────┐
   HTTPS (wildcard cert) │            sovereign                │
  ─────────────────────► │                                     │
   alice.example.com     │  tenant middleware                  │
                         │   │ host → tenant_id                │
                         │   ▼                                 │
                         │  ┌─────────────┐   ┌──────────────┐ │
                         │  │  protocol   │   │   storage    │ │
                         │  │  adapters   │──▶│  (Prefixed   │ │
                         │  │ solid / rs  │   │   per tenant)│ │
                         │  │ xrpc / …    │   └──────────────┘ │
                         │  └─────────────┘          │         │
                         │        │                  ▼         │
                         │        │            fs or S3        │
                         │        ▼                           │
                         │  ┌─────────────┐                   │
                         │  │   SQLite    │  (per-tenant, WAL)│
                         │  │ (accounts,  │                   │
                         │  │  keys, …)   │                   │
                         │  └─────────────┘                   │
                         └─────────────────────────────────────┘
```

Load-bearing principles, each enforced in code and tests:

* **One binary, no required external services** — see
  [ADR 0001](design-decisions/0001-single-binary-sqlite.md).
* **Host-derived tenancy** — the tenant is resolved from the request host,
  never trusted from client input.
* **Escape-proof tenant isolation** — every store query and object key is
  scoped by `tenant_id`; see
  [ADR 0002](design-decisions/0002-shared-bucket-tenant-prefixes.md).
* **Adapters in `wiring/`** — protocol packages declare interfaces; the
  `wiring/` package binds them to the concrete stores. See `AGENTS.md`.

For the repo layout and the package-by-package map, see
[AGENTS.md](https://github.com/selfagency/sovereign/blob/main/AGENTS.md).
