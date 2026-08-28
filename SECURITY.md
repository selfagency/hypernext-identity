# Security Policy

Sovereign is identity and personal-data software. We take security reports
seriously and will respond promptly.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Please report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/selfagency/sovereign/security/advisories/new)
for this repository.

Include, where possible:

* A description of the vulnerability and its impact.
* Steps to reproduce, or a proof of concept.
* The affected version or commit.
* Any suggested remediation, if you have one.

## What to expect

* **Acknowledgement** within 72 hours.
* **Assessment and a remediation plan** — we will confirm scope and severity
  and tell you whether it is accepted.
* **Coordinated disclosure** — we ask that you give us reasonable time to
  ship a fix before any public disclosure. We will credit you in the release
  notes unless you prefer otherwise.

## Scope

In scope:

* Authentication and token handling (access tokens, refresh tokens, OIDC,
  WebAuthn).
* Tenant isolation and cross-tenant data access.
* Authorization (ownership ACLs, self-service vs. admin boundaries).
* Storage path traversal and blob-store isolation.
* The live HTTP surface (see
  [Project status](docs/explanation/status.md) for what is actually mounted).

Out of scope (currently **not** part of the attack surface because not wired
into the live server): the IndieAuth bridge. Please still report issues you
find in that code — but note it is not reachable over HTTP today.

## Security design notes

* Access tokens are **signed and short-lived**; refresh tokens are stored
  **hashed**, never in plaintext.
* Tenant storage is **prefix-isolated**; path traversal is rejected at the
  storage layer.
* Cross-tenant isolation is enforced by ownership ACLs and covered by e2e
  tests.
* The dependency tree is scanned with `govulncheck` (`task vulncheck`).
