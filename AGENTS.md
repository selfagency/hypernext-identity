# AGENTS.md — Sovereign

Guidance for AI agents (and humans) working in this repo. Read this before
making changes. When in doubt, prefer pattern already used elsewhere in
 codebase over inventing new one.

## What this project is

Single-binary Go server that owns **identity, auth, storage, protocol
adapters, and personal data** for Sovereign tenants. It is a self-contained
project; `hypernext` is a separate service that interacts with Sovereign.
Do not add publishing/federation-timeline features here — see "Out of
scope" below.

- Module: `github.com/selfagency/sovereign`
- Go: 1.27, `CGO_ENABLED=0` always (pure-Go SQLite via `modernc.org/sqlite`)
- License: GPL-3.0-or-later — new files need no header, but new
  dependencies must be compatible (see Licensing)
- Deployment target: one process, low-cost VPS, no mandatory external
  daemon (IPFS, S3, etc. are optional/pluggable, never required)

## Repo layout

```
cmd/sovereign/   main() — cobra CLI entrypoint
internal/
  server/                 HTTP server assembly, router wiring, config
  store/                  SQLite persistence (accounts, tenants, keys, proofs, profile)
  authstore/              OIDC/auth-specific persistence (tokens, signing keys)
  auth/                   OIDC provider (zitadel/oidc), WebAuthn
  storage/                blob backend: fs.go, s3.go — Backend interface
  tenant/                 host → tenant resolution middleware
  wiring/                 adapters binding stores to protocol interfaces
  endpoints/              small standalone HTTP handlers (keys, proofs)
  keys/                   SSH/PGP public key parsing & validation
  proofs/                 public proof (Keyoxide-style) verification
  protocols/<name>/       one package per protocol/spec (see below)
  admin/, setup/, backup/, jobs/, moderation/, licenses/, identity/, web/
migrations/               SQL migrations (currently empty — see below)
scripts/coverage-gate.sh  enforces 80% coverage in pre-commit
```

`internal/protocols/` currently has: `activitypub` (actor doc + HTTP
signature verification only — NOT full AP server), `atproto` (XRPC/PDS),
`chatfederation` (Matrix/XMPP localpart normalization), `hyperlink`
(link-in-bio), `indieauth` `ipfspin` (broker client, no embedded node),
`nodeinfo` `remotestorage` `solid` `webfinger` `wellknown`.

## In scope vs out of scope

Keep this boundary. If change starts to implement full ActivityPub
federation, Matrix/XMPP/IRC server, embedded IPFS node, weblog/pastebin/
statuslog content, or smart-contract/gas logic — stop and flag it; that
belongs in `hypernext` or was explicitly rejected. See project
memory / addendum docs for full accepted/rejected list (Web3 did:pkh +
SIWE + ENS yes; did:ethr, Solana/Bitcoin did:pkh, Ceramic, Arweave/Filecoin,
smart contracts no; OIDC-as-upstream-IdP for Matrix/XMPP yes; IRC deferred;
SCIM deferred; SSH publishing deferred).

## Core conventions (follow existing files, don't reinvent)

- **Package doc comment** at top of primary file in each package
  explaining its one job (see `wiring/wiring.go` `keys/pgp.go`).
- **Error style:** lowercase, prefixed `"<pkg>: message"`wrapped with
  `fmt.Errorf("...: %w", err)`. No panics in request-path code.
- **Interface satisfaction assertions:** `var _ SomeInterface = (*Impl)(nil)`
  right after type, as in `wiring.go`.
- **Fail closed, defense in depth:** see `keys/pgp.go` — check armor
  type first, parse, then re-check for private-key material even though
   type check should have caught it. Apply this pattern anywhere
  untrusted input is parsed (SSH keys, PGP keys, SIWE messages, proof
  fetches).
- **Adapters live in `wiring/`**, not inline in `server/`. If protocol
  package needs `TokenValidator`/`ACLChecker`/similar, define
  interface in protocol package and implement it in `wiring/`.
- **Tenant-scoping:** every store query and every route that touches
  tenant data must be scoped by `tenant_id`. Never trust client-supplied
  tenant/account ID without checking it against authenticated
  principal. Self-service routes need `RequireSelf(resourceOwnerID)`-style
  checks, not `RequireAdmin()`.
- **Public vs private data:** anything served on unauthenticated route
  (`.well-known/*` `/keys` `/profile/*`hyperlink pages, proof status)
  must be reviewed for what it leaks. Never expose internal errors,
  private key material, raw stack traces, or unpublished-tenant existence
  on public endpoints.
- **SSRF-sensitive code** (proof verification, ENS RPC, any fetch of
  user-supplied URL/domain) must resolve DNS and reject loopback/private/
  link-local/multicast/cloud-metadata ranges, cap redirects, cap body size,
  use strict timeout, and run in background/scheduler — not
  synchronously in request path. See `internal/proofs/verify.go` for
   existing pattern before adding new proof service types.
- **No `CGO_ENABLED=1` dependency** ever, without explicit discussion.
  This is why SQLite is `modernc.org/sqlite`not `mattn/go-sqlite3`.

## Testing (TDD is mandatory, not optional)

- Write failing test first for new behavior; this project's whole
  addendum plan is organized as TDD phases per feature.
- Tests are colocated: `foo.go` + `foo_test.go` in same package.
  Table-driven tests preferred. Real fixtures over mocks where feasible
  (e.g. real `ssh-keygen`/`gpg --export --armor` output in `keys/testdata/`
   real MinIO container in CI for S3 backend contract suite).
- Race detector is part of normal test run: `task test` runs
  `go test ./... -race -cover`.
- **Coverage gate is 80%**, enforced by `scripts/coverage-gate.sh` in
  pre-commit and mirrored in CI (Codacy + Codecov uploads). Don't drop it.
- Security-relevant packages (auth, keys, proofs, storage path handling,
  web3/SIWE when added) need explicit negative tests: malformed input,
  oversized input, private-key-material rejection, SSRF targets, IDOR
  across tenants/accounts, concurrent/race conditions on shared state
  (e.g. nonce consumption).
- End-to-end tests live in `internal/server/e2e_test.go` +
  `e2e_harness_test.go` — extend harness rather than building
  parallel one.

## Local workflow

```
task lint     # golangci-lint run ./...  (gofumpt, gci, staticcheck, gosec, revive, gocritic, ...)
task test     # go test ./... -race -cover
task vet      # go vet ./...
task vulncheck# govulncheck
task build    # CGO_ENABLED=0 go build -o sovereign ./cmd/sovereign
task fmt      # golangci-lint run --fix ./...
task hooks    # pre-commit run --all-files
```

Run `task lint test vet` (or `task`which chains lint → test → build)
before considering any change done. Pre-commit hooks additionally run
gitleaks (secret scanning), detect-private-key, and coverage gate —
don't bypass them with `--no-verify` without very good reason stated in
 commit message.

`.golangci.yml` has narrow, justified exclusions (test files, one storage
path-traversal false positive, one interface-implementation file). Don't
add broad new exclusions to silence real finding — fix finding,
add narrowly-scoped, commented exclusion matching existing style.

## Dependencies

- Check `go.mod` before adding new dependency — many needs may already
  be covered (`zitadel/oidc` for OIDC, `go-webauthn` for passkeys,
  `ProtonMail/go-crypto` for PGP, `golang.org/x/crypto/ssh` for SSH keys,
  `bluesky-social/indigo` for atproto, `minio-go` for S3).
- New dependencies must be:
  1. Actively maintained (check recent commits/releases before adding).
  2. License-compatible with GPL-3.0-or-later (avoid anything with
     GPL-incompatible or unclear terms).
  3. CGO-free, or addition must be explicitly discussed first.
  4. Justified over hand-rolling — but also justified over pulling huge
     transitive graph for small need (this is why ENS resolution is
     planned as hand-rolled JSON-RPC rather than pulling `go-ethereum`).
- `internal/licenses/report.go` generates third-party license reporting —
  keep it in sync when deps change, and CI/pre-commit should fail on
  unknown or disallowed licenses.
- Before writing code against unfamiliar package's API, verify
  actual API surface for pinned version (via `go doc`vendored
  source, or Context7) rather than assuming from memory or older docs.
  Several packages in addendum plans (`siwe-go` `ssi-sdk/did/pkh`
  `go-crypto` internals like `PrimarySelfSignature()`) have had API
  guesses flagged as needing verification — verify, don't assume.

## Config & migrations

- `config.example.yml` is source of truth for config shape; keep it in
  sync with `internal/server/config.go` when adding options. Comment new
  options with their default and when to change them.
- `migrations/` exists but is currently empty — store currently
  creates schema directly (see `store/store.go`). If/when migration
  runner is introduced, number migrations sequentially and never edit
  migration that has shipped; add new one instead.
- Multi-tenant SQLite defaults to `per_tenant` mode (one file per tenant,
  WAL) to isolate write contention; `single` mode exists for small
  deployments. Don't assume one mode when writing store code — check
  `sqlite.mode` handling.

## Security posture (non-negotiable)

- PII redaction discipline applies to logs and error messages, not
  AI-facing workflows — never log key material, tokens, or full proof
  claim payloads at info level.
- Never store private keys (SSH or PGP) — reject on detection, don't
  refuse to display them.
- Any new public HTTP endpoint needs: explicit content-type, explicit
  cache headers where relevant, explicit 404 behavior for unknown
  tenant/handle, and look at what happens when resource is
  unpublished/revoked/expired.
- Any new authenticated endpoint needs IDOR test proving account
  cannot read/write account B's or tenant A's data via tenant B's session.
- Treat destructive operations (schema drops, bulk deletes, force-pushes,
  volume/service teardown) as requiring explicit human approval — this
  matches operator's standing directive across all tooling, not
  chat actions.

## When extending toward the addendum roadmap

 accepted addendum scope (Web3 did:pkh/SIWE/ENS, Matrix/XMPP OIDC
federation, Hyperlink profile pages, Keyoxide-style public proofs, public
SSH/PGP key hosting) is partially implemented already (`hyperlink`
`proofs` `keys` `chatfederation` localpart normalization exist). Before
adding new pieces:

1. Confirm corresponding TDD phase/test list from plan and write
   those tests first.
2. Confirm data model (SQLite schema) matches or deliberately extends
    plan — check `store/` for existing tables before adding new ones.
3. Confirm route placement doesn't collide with tenant/subdomain routing
   ambiguities already flagged (e.g. `<handle>.keys` vs
   `tenant.example/<handle>.keys` needs real decision, not guess).
4. Keep instance-admin and tenant-self-service authorization paths
   separate and explicit — never let general admin access imply
   self-service resource access without explicit, audited override.
