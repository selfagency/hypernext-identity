---
title: "Project status & capabilities"
weight: 20
---

# Project status & capabilities

This page is the **honest** list of what Sovereign does today. It exists so
the rest of the documentation can never quietly over-promise.

Every row is labeled:

* **Shipped** — a **live route** in `internal/server/server.go` **and** a
  backing test that runs in CI.
* **Partial** — a named subset works and is tested; the gap is stated.
* **Planned** — designed, not built (or built but **not mounted** on the live
  server, so unreachable over HTTP).

The `README.md` capability table is a summary of this page, and the
`task docs-claims` gate fails the build if a README "Shipped" claim has no
live route or backing test. If you update one, update the other.

> **"Mounted" vs. "in the codebase."** Several subsystems below are fully
> implemented and unit-tested as Go packages, but their `http.Handler` is
> **not mounted** on the live mux. They are therefore unreachable over HTTP
> and are labeled Partial, not Shipped. Wiring them is tracked work (see the
> note at the bottom of this page).

## Identity & sign-in

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| Access tokens | **Shipped** | `internal/auth/access_token.go` | Signed, short-lived; validated by the live Solid/remoteStorage routes. |
| Accounts & migrations | **Shipped** | `internal/store` | Versioned SQLite migrations; accounts table. |
| OIDC provider | Partial | `internal/auth` | Provider + token issuance exist as a package, but the provider handler is **not yet mounted** — no live discovery/authorize/token endpoints. |
| WebAuthn / passkeys | Partial | `internal/auth/webauthn.go` | Registration/assertion logic present; no HTTP handlers or session flow mounted. |

> **Consequence:** there is currently **no end-to-end human sign-in flow**.
> OIDC and WebAuthn are real code, but until they are mounted you cannot log
> in through the browser. Tokens for the live data routes are exercised in
> tests.

## Data protocols (live routes)

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| remoteStorage | Partial | route `/rs/` | Core read/write with tenant-prefixed isolation + bearer token check. Not the full spec surface. |
| Solid Pod (LDP) | Partial | route `/solid/` | LDP reads/writes, WebID, and ownership ACL. Not full Solid conformance (no notifications, etc.). |
| atproto XRPC | Partial | route `/xrpc/` | Two reads only (`resolveHandle`, `getProfile`). **Not a full PDS.** The repo/commit-signing and blob code in `internal/protocols/atproto` (`repo.go`, `blob.go`) is implemented and unit-tested but **not wired** to any endpoint — there are no `com.atproto.repo.*`, `com.atproto.sync.*`, or session routes. |

## Discovery & proofs (live routes)

These routes are live. They are keyed off the request **host** and the global
store — they do **not** resolve a per-tenant store.

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| WebFinger | **Shipped** | route `/.well-known/webfinger` | Host-derived resource lookup. |
| NodeInfo | **Shipped** | route `/.well-known/nodeinfo` | Software/protocol advertisement. |
| Public SSH/PGP key hosting (+ WKD path) | **Shipped** | routes `/keys`, `/.well-known/openpgpkey/` | Served from the store; private-key material rejected. |
| Keyoxide-style public proofs | **Shipped** | route `/.well-known/proofs` | Public identity proofs. |
| Profile (h-card / actor / DID doc) | Partial | route `/profile/` | Content-negotiated; document-type coverage varies. |
| ActivityPub | Partial | `internal/protocols/activitypub` | Actor document + HTTP-signature verification only; **not** a federated inbox/outbox server. |

## Platform

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| Multi-tenant, host-derived tenancy | **Shipped** | `internal/tenant` | Subdomain-per-tenant resolution via middleware. |
| Tenant-isolated blob storage | **Shipped** | `internal/storage` (`Prefixed`) | Shared FS/S3 with escape-proof tenant prefixes (ADR 0002). |
| Single binary, pure-Go SQLite | **Shipped** | `cmd/sovereign` | No CGO; `modernc.org/sqlite` (ADR 0001). |
| S3-compatible blob backend | **Shipped** | `internal/storage` (s3) | S3-compatible endpoint support. |
| Backup / restore | Partial | `internal/backup` | Scheduled backups exist; the admin config handler is **not mounted** and the restore path is in progress. |
| Moderation (takedown) | Partial | `internal/moderation` | Takedown handler + audit log exist as a package; **not mounted** on the live mux. |
| IndieAuth | Planned | — | A bridge type exists but is constructed and discarded; not wired. |
| IPFS pinning (broker) | Planned | `internal/protocols/ipfspin` | Optional client only; no embedded node, no standalone endpoint. |

## Live HTTP surface

Exactly these route prefixes are mounted today (see `internal/server/server.go`):

```text
/rs/
/solid/
/.well-known/webfinger
/.well-known/nodeinfo
/profile/
/keys
/.well-known/openpgpkey/
/.well-known/proofs
/xrpc/
```

Anything not on this list is not reachable over HTTP, regardless of whether
the package exists.

## How to read "Partial"

"Partial" is not a hedge — it is a precise claim that the named subset works
and is tested, and the named remainder does not yet. The remainder is tracked
in the phased plan and on each section's index page.

> **Not-yet-mounted subsystems** (OIDC provider, WebAuthn, admin backup,
> moderation takedown, IndieAuth) are implemented and unit-tested but have no
> live route. Wiring them is deliberate, staged work — not an oversight — and
> is the prerequisite for the corresponding user/admin documentation.
