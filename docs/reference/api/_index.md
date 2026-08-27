---
title: "HTTP API"
weight: 40
---

# HTTP API reference

Sovereign's HTTP surface. This section documents **only the live, mounted
routes** — exactly the nine prefixes wired in `internal/server/server.go`.
Endpoints that exist as Go packages but are not mounted (OIDC, WebAuthn,
admin, moderation) are **not** documented here as if they were callable; they
are listed under [Not yet mounted](#not-yet-mounted) and on the
[status page](../../explanation/status.md).

All tenant-scoped routes pass through tenant middleware: the request `Host`
resolves to a tenant, and the tenant's storage is prefix-isolated. Unknown
hosts are rejected.

## Live routes

| Prefix | Protocol / purpose | Auth | Detail |
|:-------|:-------------------|:-----|:-------|
| `/rs/` | remoteStorage read/write | bearer token | [remotestorage](remotestorage.md) |
| `/solid/` | Solid LDP + WebID + ACL | token (subject) | [solid](solid.md) |
| `/xrpc/` | atproto XRPC reads | varies | [atproto](atproto.md) |
| `/.well-known/webfinger` | WebFinger lookup | none | [discovery](discovery.md) |
| `/.well-known/nodeinfo` | NodeInfo advertisement | none | [discovery](discovery.md) |
| `/profile/` | content-negotiated profile | none | [discovery](discovery.md) |
| `/keys` | public SSH/PGP keys | none | [keys-and-proofs](keys-and-proofs.md) |
| `/.well-known/openpgpkey/` | OpenPGP WKD lookup | none | [keys-and-proofs](keys-and-proofs.md) |
| `/.well-known/proofs` | Keyoxide-style identity proofs | none | [keys-and-proofs](keys-and-proofs.md) |

## Conventions

* **Errors** are returned with a non-2xx status and a short plain-text or
  JSON body. 4xx means the client is wrong (unknown host, bad token, missing
  resource); 5xx means the server is at fault.
* **Tenant isolation:** a request to `alice.example.com` can never read or
  write `bob.example.com` data. This is enforced at the storage layer
  (prefixing) and covered by e2e tests.
* **Content negotiation:** `/profile/` selects a representation from the
  `Accept` header (HTML h-card, ActivityStreams actor, or DID document).

## Not yet mounted

The following are implemented and unit-tested as packages, but have **no
mounted route** and are therefore unreachable over HTTP today. Do not build
against them yet.

| Subsystem | Package | What is missing |
|:----------|:--------|:----------------|
| OIDC provider | `internal/auth` | discovery/authorize/token/jwks routes |
| WebAuthn passkeys | `internal/auth/webauthn.go` | begin/finish register+login routes |
| Admin backup config | `internal/admin` | the admin route + auth guard |
| Moderation takedown | `internal/moderation` | the admin route + auth guard |
| IndieAuth | `internal/protocols/indieauth` | the bridge is constructed and discarded |

These are documented (with their planned shapes) once they are mounted. See
the [status page](../../explanation/status.md) for the wiring plan.
