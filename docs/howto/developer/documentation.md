---
title: "Documentation"
weight: 10
---

# Documentation authoring policy

Sovereign's documentation is **code**: it is reviewed, versioned, tested, and
gated in CI exactly like the server. This page is the contract every doc
change must satisfy. Run `task docs-verify` before opening a PR that touches
`docs/`, `README.md`, or any other Markdown.

## The one non-negotiable rule

> **Never overstate capability.** A feature is described as **Shipped** only
> if it has a live route **and** a backing test. If it is partially built, say
> exactly what works and what does not. If it is designed but not built, mark
> it **Planned**.

This is not a style preference — it is enforced. The `task docs-claims` gate
parses the README capability table and fails the build if a "Shipped" claim
has no live route in `internal/server/server.go` or no backing `*_test.go`.

## The three status labels

| Label | Meaning | May appear in docs as… |
|:------|:--------|:-----------------------|
| **Shipped** | Live route + backing test in CI | A documented, supported capability |
| **Partial** | A named subset works and is tested | Works, but state the gap explicitly |
| **Planned** | Designed, not built | Roadmap only — never as a how-to |

When in doubt, label **down**. It is always safe to call a Shipped feature
Partial; it is never acceptable to call a Partial feature Shipped.

## Structure (who is this for?)

Documentation is organized by audience and by the
[Diátaxis](https://diataxis.fr) quadrant it serves:

| Location | Quadrant | Audience | Purpose |
|:---------|:---------|:---------|:--------|
| `docs/tutorials/` | Tutorial | newcomer | guided first success |
| `docs/howto/admin/` | How-to | administrator | install, configure, operate |
| `docs/howto/user/` | How-to | end user | account, keys, proofs, data |
| `docs/howto/developer/` | How-to | contributor | build, test, extend |
| `docs/reference/` | Reference | all | config, env, CLI, API |
| `docs/explanation/` | Explanation | all | architecture, status, ADRs |

Put a page where its _reader_ looks for it, not where its _author_ thinks of
it. A page that is "how do I do X" belongs in `howto/`; a page that is "what
is X and why" belongs in `explanation/`.

## Writing rules

1. **GitHub-first.** All source Markdown must render correctly on github.com.
   Use relative links (`../reference/configuration.md`), fenced code blocks,
   and pipe tables. The Hugo build renders the same files; do not rely on
   Hugo-only shortcodes for essential content.
2. **Link, don't duplicate.** State a fact once and link to it. Config
   defaults live in `docs/reference/configuration.md` — link to them rather
   than restating them where they can drift.
3. **Tested commands only.** Every shell command in a doc must be a command
   that exists (`task …`, `go …`, `curl …`). If you write `task foo`, `foo`
   must be a real task in `Taskfile.yml`.
4. **Name the version/mount state.** When you document an endpoint or a
   config key, say whether it is live. Example: "not yet mounted on the live
   mux" for a package that exists but is unreachable.
5. **No aspirational API.** Do not document request/response shapes for
   endpoints that are not wired. Document the live surface; put the roadmap
   on the [status page](../../explanation/status.md).

## Templates

Use the templates in [`docs/_templates/`](../../_templates/) (excluded from the
published site): `tutorial.md`, `howto.md`, `reference.md`, `adr.md`.

## The gates

`task docs-verify` runs, in order:

| Task | What it enforces |
|:-----|:-----------------|
| `docs-lint` | Markdown formatting (rumdl, when installed) |
| `docs-links` | every relative link resolves to a real file |
| `docs-claims` | every "Shipped" claim has a live route + test |
| `docs` | the Hugo site builds cleanly (`hugo --minify`) |

A red gate blocks the PR. Do not suppress a gate to make a doc pass — fix the
doc, or fix the claim.

## Adding a "Shipped" capability

1. Implement the route in `internal/server/server.go` and back it with tests.
2. Add the row to the README capability table.
3. Add a matching line to the README `claims` block
   (`slug | route | /prefix/` and/or `slug | pkg | internal/…`).
4. `task docs-claims` must pass.
