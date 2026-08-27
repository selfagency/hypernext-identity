---
title: "Sovereign Documentation"
geekdocNav: false
geekdocAnchor: false
cascade:
  - target:
      path: "/_templates/**"
    build:
      list: never
      publishResources: false
      render: never
---

# Sovereign Documentation

Sovereign is a self-hosted, multi-tenant identity and personal-data server.
It is distributed as a **single Go binary with SQLite** and **no required
external services**, so a non-specialist administrator can run it on a
low-cost VPS.

This documentation is organized by what you are trying to do. Pick the row
that matches you.

| I am a… | Start here |
|:--------|:-----------|
| **Server administrator** (installing or operating Sovereign) | [Admin how-to guides](howto/admin/) |
| **End user** (I have an account on someone's Sovereign server) | [User how-to guides](howto/user/) |
| **Developer / integrator** (building on or contributing to Sovereign) | [Developer how-to guides](howto/developer/) |
| Looking up a **config flag, endpoint, or env var** | [Reference](reference/) |
| Trying to **understand why** Sovereign is built the way it is | [Explanation](explanation/) |
| Brand new and want a **guided first setup** | [Tutorials](tutorials/) |

## The four doc types

This site follows the [Diátaxis](https://diataxis.fr/) model. Each page is
exactly one of these four kinds:

* **Tutorials** — a guided, hands-on first success. Learning-oriented.
* **How-to guides** — steps to accomplish a specific task. Goal-oriented.
* **Reference** — precise, factual lookup (config keys, endpoints, flags).
* **Explanation** — background, context, and design decisions.

If you are contributing documentation, read
[CONTRIBUTING.md](https://github.com/selfagency/sovereign/blob/main/CONTRIBUTING.md)
and the [page templates](https://github.com/selfagency/sovereign/tree/main/docs/_templates)
before writing.

## A note on honesty

Sovereign is under active development. Every capability in these docs is
labeled with its real status — **shipped**, **partial**, or **planned** — and
that label is checked in CI against the actual code and tests. If a page
claims a feature works, there is a test proving it. See
[Project status & capabilities](explanation/status.md).
