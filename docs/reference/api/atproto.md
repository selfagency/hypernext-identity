---
title: "AT Protocol (XRPC)"
weight: 30
---

# AT Protocol (`/xrpc/`)

A **small subset** of atproto XRPC reads, served from the tenant store.
Verified against `internal/protocols/atproto/xrpc_server.go`.

> **Status: Partial — this is NOT a full PDS.** Only the two methods below are
> dispatched. There is no repo sync, no `com.atproto.server.*` session
> management, no record writes, and no firehose. Any other method returns
> `501 MethodNotImplemented`. The `atproto` package also contains an XRPC
> **client** (`xrpc.go`) used internally to call _other_ servers; that is
> separate from the server surface documented here.

## Base URL

```text
https://<tenant>.<domain>/xrpc/<method>
```

## Methods

### `com.atproto.identity.resolveHandle`

Resolve a handle to its DID.

```http
GET /xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com
```

| Query param | Required | Purpose |
|:------------|:---------|:--------|
| `handle` | yes | The handle to resolve. |

Responses:

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"did": "did:plc:…"}` | Handle found. If the tenant has no DID, falls back to `did:web:<handle>`. |
| `400` | `InvalidRequest` | Missing `handle`. |
| `404` | `HandleNotFound` | No tenant with that handle. |

### `app.bsky.actor.getProfile`

Return a minimal actor profile.

```http
GET /xrpc/app.bsky.actor.getProfile?actor=alice.example.com
```

| Query param | Required | Purpose |
|:------------|:---------|:--------|
| `actor` | yes | A handle (a `did:` value is treated best-effort as the lookup key). |

Responses:

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"did","handle","displayName"}` | Actor found. `displayName` currently mirrors the handle. |
| `400` | `InvalidRequest` | Missing `actor`. |
| `404` | `ActorNotFound` | No tenant with that handle. |

## Error shape

All errors are XRPC-style JSON:

```json
{ "error": "HandleNotFound", "message": "handle not found" }
```

Unknown methods return `501` with `MethodNotImplemented`.

## Example

```bash
curl "https://example.com/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com"
# → {"did":"did:web:alice.example.com"}
```

## Not implemented (non-exhaustive)

`com.atproto.server.*` (sessions), `com.atproto.repo.*` (records, sync),
`com.atproto.sync.*`, feeds, and every other lexicon. These are the
difference between "a few reads" and "a PDS," and they are future work.

> The `atproto` package does contain a durable MST **repo** with commit
> signing (`repo.go`) and a content-addressed **blob store** (`blob.go`), both
> unit-tested. But they are a **library, not a server**: nothing mounts them,
> so there is no `createRecord`/`uploadBlob`/firehose over HTTP. Building the
> PDS surface means wiring that existing machinery into `/xrpc/` endpoints.
