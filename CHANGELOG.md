# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-1.0 notice.** Sovereign is in early development (`0.x`). Breaking
> changes may ship in any minor release. Each breaking change is called out
> explicitly under **Changed** with a migration note.

## [Unreleased]

### Added

* Documentation site (Hugo + Geekdoc) under `docs/`, with a
  documentation-as-code CI gate (`task docs-verify`) that lints Markdown,
  checks links, builds the site, and verifies that every capability the
  README marks "Shipped" has a live route and a backing test.
* Root `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and this changelog.

### Changed

* **Capability status (truthful docs):** the README capability table now
  distinguishes **Shipped** (implemented, wired into the running server, and
  covered by a backing test) from **Not wired** (package-complete and
  unit-tested in isolation, but not mounted on the live server). The following
  are **not** wired and must not be relied on over HTTP: `internal/setup`
  (first-run setup), `internal/licenses` (license reporting), `internal/keys`
  (key parsing/fingerprinting), `internal/protocols/chatfederation` (Matrix/
  XMPP localpart normalization), ActivityPub HTTP-signature verification,
  `solid.WACChecker` (Web Access Control is not enforced), `backup.Scheduler`
  + destinations (scheduled backup/restore), `ipfspin.NewPSAClient`
  (pinning-service API mode), and `moderation.ToSGate` (ToS enforcement). The
  atproto PDS is mounted at `/xrpc/` but with a nil Backend/RepoFactory/
  SigningKey, so it is non-functional as wired. The admin backup config form
  (`/admin/backup`) is mounted but its Apply callback is a no-op.
* **BREAKING (project identity):** renamed the project from
  `hypernext-identity` to **Sovereign**. Module path is
  `github.com/selfagency/sovereign`; binary is `cmd/sovereign`.
* **BREAKING (configuration):** the environment-variable prefix is now
  `SOVEREIGN_` (e.g. `SOVEREIGN_STORAGE_BACKEND`), and the config file flag
  is `SOVEREIGN_CONFIG` / `--config`. Update any deployment environment
  accordingly. See [Environment variable reference](docs/reference/environment.md).
* **BREAKING (strict config):** startup now fails on unknown or removed
  config keys. Operators MUST remove the following keys from `config.yml`
  (or startup aborts):
  - `identity_host`
  - `sqlite.mode` and `sqlite.single.path` (the whole `sqlite:` block)
  - `tls.*` (all keys under `tls:`)
  - `atproto.*` (all keys under `atproto:`)
  - `backup.*` (all keys under `backup:`)
  `ipfs.enabled` remains a valid key and is wired (gates the admin
  `/ipfs/pin` broker); do not remove it.
* **BREAKING (client-secret invalidation):** all existing plaintext client
  secrets are invalidated on upgrade. Operators MUST re-register each
  affected client via `sovereign clients set-secret <id>` (prints a new
  secret once — capture it). Affected client IDs are logged at WARN during
  migration.
* **Refresh-token grace:** existing refresh tokens survive the upgrade
  (grace). New tokens carry a 30-day expiry and rotation/reuse detection.
  No operator action is required for existing sessions. Clients MUST use
  single-flight refresh semantics (one in-flight refresh per token; retry
  only on a confirmed network error). Family revocation on reuse is
  intended (RFC 9700).

### Fixed

* Race in the in-memory auth store (`auth.MemoryStore`) — now concurrency-safe
  and covered by race tests.
* Refresh tokens are stored hashed; access tokens are signed and short-lived.
* Versioned SQLite schema migrations and the `accounts` table.
* Tenant storage is prefix-isolated with path-traversal rejection.
* Ownership-based ACLs for tenant resources.

## Release notes

Release notes for each tagged version are published on the
[GitHub releases page](https://github.com/selfagency/sovereign/releases).

[Unreleased]: https://github.com/selfagency/sovereign/compare/HEAD
