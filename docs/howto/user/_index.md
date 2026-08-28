---
title: "User how-to"
weight: 20
---

# User how-to guides

Guides for people who **have an account** on a Sovereign server run by
someone else.

> **Sign-in is live on the identity host.** The OIDC provider and WebAuthn
> passkey endpoints are mounted at `id.<domain>` (see the
> [status page](../../explanation/status.md)), so a browser sign-in flow is
> reachable. The guides below are listed so you can see what is coming; each
> will be published only when the underlying flow is fully documented and
> tested.

## Coming when sign-in ships

| Guide | Blocked on |
|:------|:-----------|
| Sign in with a passkey | full WebAuthn UI + docs |
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
