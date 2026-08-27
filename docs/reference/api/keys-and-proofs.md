---
title: "Keys & proofs"
weight: 50
---

# Public keys & identity proofs

Public (unauthenticated) endpoints for a tenant's public keys and verified
identity proofs. Verified against `internal/endpoints/endpoints.go`. The
tenant is derived from the request **Host** (set by tenant middleware) — never
from the URL path, so a path cannot spoof another tenant.

## Public key hosting

### `GET /keys`

A human-readable HTML page listing the tenant's public keys (type,
fingerprint, active/revoked).

### `GET /<anything>.keys` — SSH public keys

Plaintext list of the tenant's **active** SSH public keys, one per line
(GitHub/GitLab `.keys` convention). Revoked keys are excluded.

```bash
curl https://alice.example.com/alice.keys
# → ssh-ed25519 AAAA… alice@example.com
```

### `GET /<anything>.gpg` — OpenPGP public keys

Plaintext list of the tenant's **active** PGP public keys. Revoked keys are
excluded.

### `GET /.well-known/openpgpkey/hu/<hash>` — Web Key Directory

[OpenPGP Web Key Directory](https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service)
lookup. Serves the tenant's first active PGP key as
`application/pgp-keys`.

> **Current limitation:** the z-base-32 localpart hash in the path is parsed
> but not yet matched to a specific key — the endpoint returns the tenant's
> first active PGP key regardless of hash. Per-user WKD addressing is future
> work. Returns `404` if the tenant has no active PGP key.

## Identity proofs — `GET /.well-known/proofs`

Machine-readable, Keyoxide-style verified identity claims for the tenant, as
JSON. Claims come from the store's verified-proof records.

```bash
curl https://alice.example.com/.well-known/proofs
```

```json
{
  "anchor": { "type": "pgp", "value": "<fingerprint>" },
  "claims": [
    {
      "service": "github",
      "location": "https://github.com/alice/…",
      "status": "verified",
      "verifiedAt": "2026-08-27T00:00:00Z"
    }
  ]
}
```

| Field | Meaning |
|:------|:--------|
| `anchor.type` / `anchor.value` | The proof anchor (e.g. a PGP fingerprint) the claims bind to. Empty until a claim exists. |
| `claims[].service` | The service the claim is about (e.g. `github`). |
| `claims[].location` | The URL where the proof lives. |
| `claims[].status` | `verified`, `pending`, etc. |
| `claims[].verifiedAt` | RFC 3339 timestamp of last verification (omitted if never checked). |

> Proof **verification** (fetching the claim location and checking it) is
> performed by the proofs subsystem with SSRF hardening; this endpoint only
> serves the recorded results. Verification runs are not triggered by `GET`.
