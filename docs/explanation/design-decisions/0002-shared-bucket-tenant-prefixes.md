---
title: "ADR 0002: Shared object bucket with tenant prefixes"
weight: 2
---

# ADR 0002: Shared object bucket with tenant prefixes

* **Status:** Accepted
* **Date:** 2026-08

## Context

Sovereign is multi-tenant: many tenants (handles like `alice.example.com`)
share one server. Protocol blobs — Solid, remoteStorage, and atproto blobs —
need object storage. The filesystem backend already namespaces by tenant
under `data_dir/blobs`; the S3-compatible backend needed an equivalent
isolation model that does not require provisioning a bucket per tenant.

The hard requirement is **escape-proof tenant isolation**: no tenant may read
or write another tenant's objects, and no crafted key may traverse outside a
tenant's namespace (for example via `..`).

## Decision

Use **one shared bucket** for the S3 backend, with every object key scoped
under a **tenant prefix** (`<tenant_id>/…`). The filesystem backend mirrors
this with a per-tenant directory under `data_dir/blobs`.

All object keys are passed through a strict sanitizer that:

* rejects any key containing `..` or path separators that escape the tenant
  prefix,
* joins and then **re-verifies** the final key still begins with the tenant
  prefix (defense in depth), and
* treats tenant/account IDs from the client as untrusted until checked
  against the authenticated principal.

## Alternatives considered

* **One bucket per tenant** — rejected: operationally heavy (bucket
  provisioning, IAM, and lifecycle per tenant) and unnecessary when prefix
  isolation is enforced correctly.
* **Trusting client-supplied keys after `path.Join`** — rejected: bare
  `path.Join` on an attacker-controlled key is exactly the path-traversal
  bug this ADR exists to prevent.

## Consequences

* **Good:** one bucket to create, back up, and set policy on; tenant
  isolation is enforced in one place (the storage layer) and is testable.
* **Cost:** isolation is a software guarantee, not a bucket boundary, so the
  sanitizer and the cross-tenant negative tests are **non-negotiable** and
  must never be weakened.
* **Rule for contributors:** every store query and every route touching
  tenant data is scoped by `tenant_id`, and any new key-handling code must
  reuse the existing sanitizer. See `AGENTS.md` ("Tenant-scoping",
  "SSRF-sensitive code").
