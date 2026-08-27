---
title: "Build, test & extend"
weight: 10
---

# Build, test & extend Sovereign

The contributor workflow. Everything here runs locally with the tools in
[CONTRIBUTING.md](../../../CONTRIBUTING.md).

## Build

```bash
task build    # CGO_ENABLED=0 go build -o sovereign ./cmd/sovereign
```

## Test

```bash
task test       # go test ./... -race -cover
task coverage   # enforce the >= 80% aggregate gate
task lint       # golangci-lint run ./...
task vet        # go vet ./...
task vulncheck  # govulncheck ./...
```

`task` with no arguments runs **lint + test + build** — the same bar CI
enforces.

### Test tiers

| Tier | Location | Runs with | Purpose |
|:-----|:---------|:----------|:--------|
| Unit | package `*_test.go` | `task test` | logic, boundaries, error paths |
| Integration | `*_integration_test.go` | `task test` | adapters against real backends |
| E2E | `test/e2e/*_test.go` | `task test` | full HTTP through the live mux |

Rules (enforced in review):

* **TDD** — failing test first, then the code.
* **No mocks of our own types** — use fakes / in-memory implementations.
* **Race detector always on** (`-race`). Shared state needs a race test (see
  `internal/auth` for the `MemoryStore` example).
* **Cross-tenant behavior needs an e2e test** proving isolation.

## Extend: adding a live route

The honest path from "package exists" to "shipped feature":

1. **Write the handler** in its protocol package, depending on _interfaces_
   (e.g. a `TokenValidator`), not concrete stores.
2. **Bind it in `wiring/`** — adapters that satisfy those interfaces against
   the real stores live here (see `AGENTS.md` boundary rules).
3. **Mount it** in `internal/server/server.go`'s `buildRouter`.
4. **Add an e2e test** in `test/e2e/` exercising the route through the mux,
   including a cross-tenant isolation case if it touches tenant data.
5. **Document it** in `docs/reference/api/`, and only then mark it Shipped in
   the README + [status page](../../explanation/status.md) with a matching
   `claims` entry. `task docs-claims` will verify the route is mounted.

Steps 3–5 are what turns a unit-tested package into a _reachable, advertised_
capability. A package that skips step 3 is exactly the "implemented but not
mounted" state described on the status page.

## Documentation

Docs are code. Before opening a PR that touches Markdown:

```bash
task docs-verify   # lint + links + claims + Hugo build
task docs-serve    # preview the site at http://127.0.0.1:1313
```

See the [documentation authoring policy](documentation.md).

## Boundary rules (from AGENTS.md)

* Protocol packages declare interfaces; `wiring/` binds them to stores.
* `RequireSelf` and any future admin guard are **distinct** — one never
  implicitly satisfies the other.
* The tenant is always resolved from the request host, never from
  client-supplied path or body.
