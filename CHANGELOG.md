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

* **BREAKING (project identity):** renamed the project from
  `hypernext-identity` to **Sovereign**. Module path is
  `github.com/selfagency/sovereign`; binary is `cmd/sovereign`.
* **BREAKING (configuration):** the environment-variable prefix is now
  `SOVEREIGN_` (e.g. `SOVEREIGN_STORAGE_BACKEND`), and the config file flag
  is `SOVEREIGN_CONFIG` / `--config`. Update any deployment environment
  accordingly. See [Environment variable reference](docs/reference/environment.md).

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
