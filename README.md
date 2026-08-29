# Sovereign

Sovereign is a self-hosted, multi-tenant **identity and personal-data
server**. It gives each tenant a real home on the open web — an identity, a
personal data store, and public keys — served from **one static Go binary
with SQLite and no required external services**. You can run it on a low-cost
VPS.

It is built for people who want to **own their identity and data** and for
the administrators who run a server for them — without needing to be a
systems or cryptography expert.

> **Status: early development.** Sovereign is under active construction. The
> capability table below is kept honest by a CI gate that fails the build if
> a capability marked **Shipped** has no live route **and** backing test. Do
> not rely on a capability until it is marked Shipped. See
> [Project status & capabilities](docs/explanation/status.md).

## What Sovereign gives a tenant

| Capability | Status | Live route / evidence |
|:-----------|:-------|:----------------------|
| Host-derived multi-tenancy | **Shipped** | `internal/tenant` |
| Tenant-isolated blob storage (fs / S3) | **Shipped** | `internal/storage` |
| Single binary, pure-Go SQLite (no CGO) | **Shipped** | `cmd/sovereign` |
| Versioned schema migrations + accounts | **Shipped** | `internal/store` |
| Signed, short-lived access tokens | **Shipped** | `internal/auth/access_token.go` |
| WebFinger | **Shipped** | `/.well-known/webfinger` |
| NodeInfo | **Shipped** | `/.well-known/nodeinfo` |
| Public SSH/PGP key hosting (+ WKD path) | **Shipped** | `/keys`, `/.well-known/openpgpkey/` |
| Keyoxide-style public identity proofs | **Shipped** | `/.well-known/proofs` |
| Solid Pod (LDP + PATCH + Solid-OIDC) | **Partial** | `/solid/` — WAC not enforced |
| remoteStorage (core read/write + conditionals + folder listing) | **Shipped** | `/rs/` |
| AT Protocol PDS (repo writes, blobs, sync, sessions) | **Partial** | `/xrpc/` — mounted with nil Backend/RepoFactory/SigningKey (non-functional as wired) |
| Profile (content-negotiated h-card / actor / DID doc) | **Shipped** | `/profile/` |
| ActivityPub (actor document) | **Partial** | `/profile/` actor doc; HTTP-signature verification not wired |
| OIDC provider | **Shipped** | identity host `id.<domain>` — discovery/authorize/token/userinfo/jwks |
| WebAuthn / passkey sign-in | **Shipped** | identity host `/webauthn/register\|login/{begin,finish}` |
| Admin user creation + magic-link invites | **Shipped** | identity host `/admin/users` (admin-guarded) |
| Magic-link redemption + user panel | **Shipped** | identity host `/invite/{token}`, `/panel` |
| Admin moderation (takedown) | **Shipped** | identity host `/admin/moderation/takedown` (admin-guarded) |
| Admin backup config | **Not wired** | identity host `/admin/backup` — Apply is a no-op; Scheduler not wired |
| Backup / restore | **Not wired** | `internal/backup` — Scheduler + destinations not wired |
| IndieAuth | **Shipped** | identity host `/indieauth/auth`, `/indieauth/token` |
| IPFS pinning (Kubo RPC broker) | **Partial** | identity host `/ipfs/pin` (admin-guarded) — Kubo RPC wired; PSA client mode not wired |

Legend — **Shipped**: implemented, wired into the running server, and covered by
a backing test in CI. **Partial**: wired but a named subset is missing or not
enforced; the gap is stated. **Not wired**: package-complete and unit-tested in
isolation, but not mounted on the live server (unreachable over HTTP).

<!--
  claims — machine-readable anchors for `task docs-claims`.
  Format per line:  slug | kind | value
    kind=route  → the literal route prefix must appear in internal/server/server.go
    kind=pkg    → the package dir must contain at least one *_test.go
  Every "Shipped" row above MUST have a matching entry here.
-->
<!-- claims
multi-tenant-host-derived | pkg | internal/tenant
tenant-isolated-blob-storage | pkg | internal/storage
single-binary-sqlite | pkg | cmd/sovereign
versioned-migrations-accounts | pkg | internal/store
signed-access-tokens | pkg | internal/auth
webfinger | route | /.well-known/webfinger
nodeinfo | route | /.well-known/nodeinfo
public-key-hosting | route | /.well-known/openpgpkey/
identity-proofs | route | /.well-known/proofs
remotestorage | route | /rs/
profile | route | /profile/
oidc-provider | pkg | internal/auth
webauthn-passkeys | pkg | internal/auth
admin-user-invites | pkg | internal/admin
magic-link-panel | pkg | internal/admin
admin-moderation | pkg | internal/moderation
indieauth | pkg | internal/protocols/indieauth
claims -->

## Quickstart (administrator)

```bash
# 1. Build the single static binary.
CGO_ENABLED=0 go build -o sovereign ./cmd/sovereign

# 2. Copy and edit the example config.
cp config.example.yml config.yml
#    Set `domain:` to your apex domain (e.g. example.com).

# 3. Run.
./sovereign serve --config config.yml
```

Then read the [install guide](docs/howto/admin/install.md) and the
[configuration reference](docs/reference/configuration.md).

## Documentation

The full documentation lives in [`docs/`](docs/_index.md) and renders both on
GitHub and as a Hugo site. It is organized by who you are:

* **Administrator** — install, configure, back up, moderate →
  [docs/howto/admin](docs/howto/admin/_index.md)
* **End user** — manage your account, keys, proofs, data →
  [docs/howto/user](docs/howto/user/_index.md)
* **Developer / contributor** — build, test, extend →
  [docs/howto/developer](docs/howto/developer/_index.md)
* **Reference** — config, env vars, CLI, HTTP API →
  [docs/reference](docs/reference/_index.md)
* **Explanation** — architecture, status, design decisions →
  [docs/explanation](docs/explanation/_index.md)
* **Tutorials** — guided first successes →
  [docs/tutorials](docs/tutorials/_index.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The short version: tests are
mandatory (TDD), the coverage gate is 80%, and `task lint test vet` must pass
before anything is considered done.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## License

[GPL-3.0-or-later](LICENSE)
