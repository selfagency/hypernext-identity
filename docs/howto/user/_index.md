---
title: "User how-to"
weight: 20
---

# User how-to guides

Guides for people who **have an account** on a Sovereign server run by
someone else.

> **No user-facing sign-in or account UI is mounted yet.** The OIDC provider
> and WebAuthn passkey handlers exist as code but are
> [not yet wired to a live route](../../explanation/status.md), so there is no
> browser sign-in flow to document. The guides below are listed so you can see
> what is coming; each will be published only when the underlying flow is live
> and tested.

## Coming when sign-in ships

| Guide | Blocked on |
|:------|:-----------|
| Sign in with a passkey | WebAuthn handler mount |
| Manage your profile and handle | OIDC/session flow |
| Use your Solid Pod | Solid-OIDC identity challenge |
| Use your account on the AT Protocol | atproto session management |

## Available without sign-in (public data)

These endpoints serve a tenant's **public** data and need no account session —
you can read them with a browser or `curl` today:

* **Public keys** — `https://<you>.<domain>/keys`, `<handle>.keys`,
  `<handle>.gpg`. See [keys & proofs](../../reference/api/keys-and-proofs.md).
* **Identity proofs** — `https://<you>.<domain>/.well-known/proofs`.
* **Profile** — `https://<you>.<domain>/profile/` (content-negotiated).
