---
title: "Solid Pod"
weight: 20
---

# Solid Pod (`/solid/`)

Serves Linked Data Platform (LDP) reads and writes for the tenant resolved
from the request host, with WebID-derived agents and an ownership ACL.
Verified against `internal/protocols/solid/ldp.go`.

> **Status: Partial.** LDP `GET`/`PUT`/`POST`/`DELETE`, container listings as
> Turtle, and an ownership-based ACL work and are tested. This is **not** a
> spec-conformant Solid Pod: there are no live notifications, no `PATCH`
> (despite being advertised in `Allow`), no WAC rule documents, and no
> Solid-OIDC identity challenge. The ACL is **ownership-based** (see below),
> not full Web Access Control.

## Base URL

```text
https://<tenant>.<domain>/solid/<path>
```

The tenant is resolved from the **Host header**. Unknown host → `404`.

## Agents and authentication

The authenticated **agent** is derived from an optional bearer token:

```http
Authorization: Bearer <token>
```

* A valid token's subject becomes the agent's WebID.
* A missing or invalid token falls back to the **public agent** (anonymous).

Authentication never fails the request by itself — it only changes *who is
asking*. Whether the request is allowed is decided by the ACL.

## Access control (ownership ACL)

The ACL is **ownership-based** (`internal/wiring.ACLChecker`): the tenant who
owns the resource can read and write it. It is not yet a full WAC
implementation with per-resource rule documents.

| Check | Public agent | Owning agent |
|:------|:-------------|:-------------|
| `CanRead` | per ACL (default deny for private data) | allowed |
| `CanWrite` | denied | allowed |

A disallowed request → `403 forbidden`.

## Methods

| Method | Path | ACL | Success | Notes |
|:-------|:-----|:----|:--------|:------|
| `GET` | `/solid/<path>` | `CanRead` | `200` + body | Resource bytes; `Content-Type` from storage. |
| `GET` | `/solid/<path>/` | `CanRead` | `200` + Turtle | **Container** (trailing slash): lists children as Turtle with `Link: <...#BasicContainer>; rel="type"`. |
| `PUT` | `/solid/<path>` | `CanWrite` | `201` | Store/replace a resource. |
| `POST` | `/solid/<path>` | `CanWrite` | `201` | Create a child resource. |
| `DELETE` | `/solid/<path>` | `CanWrite` | `204` | Delete a resource. Missing → `404`. |

Other methods → `405`. The `Allow` header advertises
`GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE`, but `PATCH`, `HEAD`, and
`OPTIONS` are **not** handled and return `405`.

## Containers and slash semantics

A trailing slash denotes an LDP **BasicContainer** (Solid Protocol §3.1 URI
slash semantics). `GET` on a container returns a Turtle listing:

```turtle
@prefix ldp: <http://www.w3.org/ns/ldp#>.

</documents> a ldp:BasicContainer.
</documents/note.txt> a ldp:Resource.
```

## Example

```bash
# Write a resource as the owning tenant.
curl -X PUT https://alice.example.com/solid/documents/note.txt \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H "Content-Type: text/plain" \
  --data "hello pod"
# → 201 Created

# Read the container listing.
curl https://alice.example.com/solid/documents/ \
  -H "Authorization: Bearer $ALICE_TOKEN"
# → 200 OK, text/turtle
```

## Known gaps (tracked)

* No `PATCH` (advertised but `405`).
* No WebID profile document route on this prefix (see `/profile/`).
* No WAC rule documents; ACL is ownership-only.
* No live Solid notifications.
