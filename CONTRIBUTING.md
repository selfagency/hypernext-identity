# Contributing to Sovereign

Thank you for helping build Sovereign. This document describes how we work.
It is deliberately strict — Sovereign is identity and security software, and
the bar for correctness is high.

## The short version

* All code changes follow **TDD**: a failing test is written first, then the
  code that makes it pass.
* The **coverage gate is 80%** aggregate, and it is enforced in CI.
* **`task lint test vet` must pass** before any PR is considered done. Not
  "mostly passes." Not "passes on my machine." Passes.
* Documentation changes must pass `task docs-verify` (lint + links + Hugo
  build + claims check).

## Prerequisites

* Go (see `go.mod` for the version)
* [Task](https://taskfile.dev) (the task runner)
* `golangci-lint` for `task lint`
* `govulncheck` for `task vulncheck`
* Hugo (extended) for `task docs` / `task docs-verify`

## Project layout

```text
cmd/sovereign/        the single binary (entrypoint, CLI)
internal/
  server/             HTTP server, router, config
  wiring/             dependency injection / protocol adapters
  tenant/             host → tenant resolution
  storage/            blob store (fs, S3, tenant prefixing)
  store/              SQLite: accounts, migrations
  auth/               tokens, OIDC provider, WebAuthn
  protocols/          activitypub, remotestorage, solid, atproto, ...
  moderation/         takedown, ToS, audit
  admin/              admin handlers
  backup/             scheduled backups
  hyperlink/          self-service authorization
docs/                 documentation (Hugo + Geekdoc)
scripts/              CI/docs gate scripts
```

See [Architecture](docs/explanation/architecture.md) for the rationale.

## Development workflow

```bash
task build        # CGO_ENABLED=0 go build ./...
task test         # go test ./... -race -cover
task coverage     # aggregate coverage gate (>= 80%)
task lint         # golangci-lint run ./...
task vet          # go vet ./...
task vulncheck    # govulncheck ./...
task docs-verify  # documentation gates
```

## Testing

Sovereign has three test tiers. New behavior must land with the appropriate
tier(s):

| Tier | Location | Naming | Purpose |
|:-----|:---------|:-------|:--------|
| Unit | package-local | `*_test.go` | logic, boundaries, error paths |
| Integration | package-local | `*_integration_test.go` | adapters against real backends |
| E2E | `test/e2e/` | `*_test.go` | full HTTP request/response through the live mux |

Rules:

* **No mocks of our own types.** Use fakes and in-memory implementations.
* **Race detector always on** (`go test -race`).
* **Concurrency and race-path tests are required** for anything shared across
  goroutines (e.g. `auth.NewMemoryStore()`).
* **Cross-tenant isolation must have an e2e test** for any new tenant-scoped
  behavior.

## Documentation changes

Documentation is code. It is reviewed, versioned, and gated.

* Source Markdown lives in [`docs/`](docs/_index.md) and must be
  **GitHub-friendly** (readable raw, relative links that work on github.com).
* The same source is built into a Hugo site (`task docs`).
* **Never overstate capability.** A feature is "Shipped" only if it has a
  live route **and** a backing test — and the `task docs-claims` gate will
  fail the build if you claim otherwise.
* Follow the [Documentation authoring policy](docs/howto/developer/documentation.md).

## Commit style

* Present tense, imperative, ≤ 72 char subject.
* Reference the issue: `Fixes #NN`.
* Squash-merge to `main` with a clean history.

## Reporting security issues

**Do not open a public issue.** See [SECURITY.md](SECURITY.md).
