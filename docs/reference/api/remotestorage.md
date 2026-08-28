---
title: "remoteStorage"
weight: 10
---

# remoteStorage (`/rs/`)

Implements the core read/write surface of the
[remoteStorage](https://remotestorage.io/) protocol (draft-dejong) for the
tenant resolved from the request host. Verified against
`internal/protocols/remotestorage/handler.go`.

> **Status: Shipped.** Core GET/PUT/DELETE with bearer-scope enforcement,
> CORS, strong ETags, `If-Match`/`If-None-Match` conditional handling, and
> folder listing all work and are tested.

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
| `GET` | `/rs/<path>` | `r` | `200` + body | Streams the blob; `Content-Type` from storage. Missing key → `404`. Emits a strong `ETag`; honors `If-None-Match` (→ `304` on hit). |
| `GET` | `/rs/<path>/` | `r` | `200` + JSON-LD | **Folder listing** (trailing slash): direct children with `ETag`, `Content-Type`, `Content-Length`. |
| `PUT` | `/rs/<path>` | `rw` | `200` + `ETag` | Stores the body; returns a strong `ETag` (SHA-256 of content). Enforces `If-Match`/`If-None-Match` (→ `412` on mismatch). |
| `DELETE` | `/rs/<path>` | `rw` | `200` | Deletes the key. Missing key → `404`. Enforces `If-Match`/`If-None-Match`. |
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

`PUT` and `GET` return a strong `ETag` computed as the hex SHA-256 of the
body, quoted (`"<hex>"`). Conditional requests are enforced:

* `If-None-Match: <etag>` on `GET` → `304 Not Modified` when the current
  ETag matches.
* `If-Match: <etag>` on `PUT`/`DELETE` → `412 Precondition Failed` when the
  current ETag does not match.
* `If-None-Match: *` on `PUT` → `412` when the resource already exists
  (create-only semantics).
* `If-Match: *` on `PUT`/`DELETE` → `412` when the resource does not exist.

ETag lists may use weak `W/` prefixes or `*`.

## Folder listing

`GET` on a path with a trailing slash returns a remoteStorage
folder-description JSON-LD document listing the **direct children** of that
folder, each with its `ETag`, `Content-Type`, and `Content-Length`:

```json
{
  "@context": "http://remotestorage.io/spec/folder-description",
  "items": {
    "a.txt": { "ETag": "\"<sha256>\"", "Content-Type": "text/plain", "Content-Length": 5 }
  }
}
```

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
