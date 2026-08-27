---
title: "remoteStorage"
weight: 10
---

# remoteStorage (`/rs/`)

Implements the core read/write surface of the
[remoteStorage](https://remotestorage.io/) protocol (draft-dejong) for the
tenant resolved from the request host. Verified against
`internal/protocols/remotestorage/handler.go`.

> **Status: Partial.** Core GET/PUT/DELETE with bearer-scope enforcement,
> CORS, and strong ETags works and is tested. Directory-listing metadata,
> `If-None-Match`/`If-Match` conditional handling, and the full spec surface
> are not yet implemented.

## Base URL

```text
https://<tenant>.<domain>/rs/<path>
```

The tenant is resolved from the **Host header** by middleware — never from
the path. A request to an unknown host returns `404`.

## Authentication

All non-`OPTIONS` requests require a bearer token:

```http
Authorization: Bearer <token>
```

The token is validated (`internal/wiring.TokenValidator`) and yields a set of
**scopes**. Missing or invalid token → `401 unauthorized`.

## Scopes

Scopes are hierarchical; `rw` implies `r`.

| Scope | Allows |
|:------|:-------|
| `r` | `GET` |
| `rw` | `GET`, `PUT`, `DELETE` |

A request that lacks the required scope → `403 forbidden`.

## Methods

| Method | Path | Scope | Success | Notes |
|:-------|:-----|:------|:--------|:------|
| `GET` | `/rs/<path>` | `r` | `200` + body | Streams the blob; `Content-Type` from storage. Missing key → `404`. |
| `PUT` | `/rs/<path>` | `rw` | `200` + `ETag` | Stores the body; returns a strong `ETag` (SHA-256 of content). |
| `DELETE` | `/rs/<path>` | `rw` | `200` | Deletes the key. Missing key → `404`. |
| `OPTIONS` | `/rs/<path>` | — | `200` | CORS preflight. No token required. |

Other methods → `405 method not allowed`.

## CORS

remoteStorage clients are cross-origin by design, so the handler sets:

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type, If-Match, If-None-Match
```

## ETag / caching

`PUT` returns a strong `ETag` computed as the hex SHA-256 of the stored body,
quoted (`"<hex>"`). `If-Match` / `If-None-Match` conditional semantics are
**accepted in the CORS header list but not yet enforced** by the handler.

## Example

```bash
# Store a document.
curl -X PUT https://alice.example.com/rs/documents/note.txt \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/plain" \
  --data "hello sovereign"
# → 200 OK, ETag: "<sha256>"

# Read it back.
curl https://alice.example.com/rs/documents/note.txt \
  -H "Authorization: Bearer $TOKEN"
# → 200 OK, hello sovereign
```

## Tenant isolation

The storage key is the request path with the leading `/` removed, stored under
the tenant's prefix on the shared backend (`storage.Prefixed`). One tenant's
`/rs/` tree is unreachable from another tenant's host.
