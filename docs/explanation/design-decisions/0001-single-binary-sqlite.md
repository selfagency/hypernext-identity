---
title: "ADR 0001: Single Go binary, pure-Go SQLite, no CGO"
weight: 1
---

# ADR 0001: Single Go binary, pure-Go SQLite, no CGO

* **Status:** Accepted
* **Date:** 2026-08

## Context

Sovereign is operated by administrators who are **not** systems or
cryptography experts. Every external runtime dependency (a separate database
server, a key-management daemon, a message broker) is another thing a
non-specialist has to install, secure, back up, and keep alive. The project
also targets cheap, single-VPS deployment.

Cross-compilation matters: the release pipeline builds for
`linux/darwin/windows` on `amd64/arm64` from a single CI job. Any cgo
dependency breaks that matrix or forces per-OS toolchains.

## Decision

Sovereign is a **single, statically-linked Go binary** with
`CGO_ENABLED=0` always. Persistence is **SQLite via the pure-Go driver
`modernc.org/sqlite`** (not `mattn/go-sqlite3`, which needs cgo). Optional
capabilities (S3-compatible blob storage, IPFS pinning) are **pluggable and
never required** — the server runs fully self-contained out of the box.

## Alternatives considered

* **Postgres/MySQL as the default store** — rejected: requires a separate
  server process and admin burden; overkill for the target deployment size.
  The store layer is kept behind interfaces so a network database could be
  added later without changing protocol code.
* **cgo SQLite (`mattn/go-sqlite3`)** — rejected: breaks the static
  cross-compile matrix and the "copy one binary" install story.

## Consequences

* **Good:** one-file install, trivial backup (copy the data dir), a clean
  cross-compile release matrix, and a low operational floor.
* **Cost:** `modernc.org/sqlite` is slower than cgo SQLite under heavy write
  load. This is accepted for the target scale and is mitigated by the
  default `per_tenant` SQLite mode, which isolates write contention.
* **Rule for contributors:** no `CGO_ENABLED=1` dependency is ever added
  without explicit discussion. See `AGENTS.md`.
