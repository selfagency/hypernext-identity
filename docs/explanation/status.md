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
| OIDC provider | **Shipped** | identity host `id.<domain>` | Discovery/authorize/token/userinfo/jwks served on the identity host, backed by a SQLite `op.Storage`. |
| WebAuthn / passkeys | **Shipped** | identity host `/webauthn/register|login/{begin,finish}` | Store-backed credentials; begin/finish register+login with a TTL session store. |

> **Sign-in flow:** OIDC and WebAuthn are now mounted on the identity host,
> so a browser-based sign-in flow is reachable. The first user created is the
> instance admin; admins can add users and grant admin from the admin backend.

## Data protocols (live routes)

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| remoteStorage | **Shipped** | route `/rs/` | Core read/write with tenant-prefixed isolation, bearer scope enforcement, ETags, `If-Match`/`If-None-Match` conditionals, and folder listing. |
| Solid Pod (LDP) | **Shipped** | route `/solid/` | LDP reads/writes/PATCH, HEAD/OPTIONS, Web Access Control (WAC) rule documents, and a Solid-OIDC `webid`-claim identity challenge. No live notifications. |
| atproto XRPC | **Shipped** | route `/xrpc/` | PDS surface: `resolveHandle`, `getProfile`, `createRecord`, `getRecord`, `uploadBlob`, `sync.getBlob`, `sync.getRepo`, and passkey-authenticated `createSession`. The repo/commit-signing and blob machinery is wired to live endpoints. |

## Discovery & proofs (live routes)

These routes are live. They are keyed off the request **host** and the global
store — they do **not** resolve a per-tenant store.

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| WebFinger | **Shipped** | route `/.well-known/webfinger` | Host-derived resource lookup. |
| NodeInfo | **Shipped** | route `/.well-known/nodeinfo` | Software/protocol advertisement. |
| Public SSH/PGP key hosting (+ WKD path) | **Shipped** | routes `/keys`, `/.well-known/openpgpkey/` | Served from the store; private-key material rejected. |
| Keyoxide-style public proofs | **Shipped** | route `/.well-known/proofs` | Public identity proofs. |
| Profile (h-card / actor / DID doc) | **Shipped** | route `/profile/` | Content-negotiated; h-card and DID doc render store data (display name, bio, links, tenant DID). |
| ActivityPub | Partial | `internal/protocols/activitypub` | Actor document + HTTP-signature verification only; **not** a federated inbox/outbox server. |

## Platform

| Capability | Status | Evidence | Notes |
|:-----------|:-------|:---------|:------|
| Multi-tenant, host-derived tenancy | **Shipped** | `internal/tenant` | Subdomain-per-tenant resolution via middleware. |
| Tenant-isolated blob storage | **Shipped** | `internal/storage` (`Prefixed`) | Shared FS/S3 with escape-proof tenant prefixes (ADR 0002). |
| Single binary, pure-Go SQLite | **Shipped** | `cmd/sovereign` | No CGO; `modernc.org/sqlite` (ADR 0001). |
| S3-compatible blob backend | **Shipped** | `internal/storage` (s3) | S3-compatible endpoint support. |
| Backup / restore | **Shipped** | `internal/backup` | Scheduled backups + a restore path (ReadBackup + Scheduler.Restore). |
| Moderation (takedown) | **Shipped** | `/admin/moderation/takedown` | Takedown handler + persistent audit log, mounted behind the admin guard. |
| IndieAuth | **Shipped** | identity host `/indieauth/auth`, `/indieauth/token` | Authorization + token exchange wired; mints tokens for an identity URL via the shared OIDC signing key. |
| IPFS pinning (broker) | **Shipped** | identity host `/ipfs/pin` | Admin-guarded pin/status surface; persists the pin set in the store and calls the configured Kubo RPC backend when `ipfs.enabled`. |

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

On the **identity host** (`id.<domain>`), the OIDC provider and WebAuthn
endpoints are also mounted:

```text
/.well-known/openid-configuration   (OIDC discovery)
/authorize, /token, /userinfo, /keys (OIDC)
/webauthn/register|login/{begin,finish}
/admin/backup
/admin/moderation/takedown
```

Anything not on these lists is not reachable over HTTP, regardless of whether
the package exists.

## How to read "Partial"

"Partial" is not a hedge — it is a precise claim that the named subset works
and is tested, and the named remainder does not yet. The remainder is tracked
in the phased plan and on each section's index page.

> **Not-yet-mounted subsystems** (IndieAuth) are implemented but have no live
> route. Wiring them is deliberate, staged work — not an oversight.
