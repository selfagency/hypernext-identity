---
title: "AT Protocol (XRPC)"
weight: 30
---

# AT Protocol (`/xrpc/`)

A **small subset** of atproto XRPC reads, served from the tenant store.
Verified against `internal/protocols/atproto/xrpc_server.go`.

> **Status: Shipped.** The PDS surface is mounted: `resolveHandle`, `getProfile`,
> `createRecord`, `getRecord`, `uploadBlob`, `sync.getBlob`, `sync.getRepo`,
> and passkey-authenticated `createSession`. The repo/commit-signing and blob
> machinery is wired to live endpoints.

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

### `com.atproto.repo.createRecord`

Write a record to the repo and commit it.

```http
POST /xrpc/com.atproto.repo.createRecord
```

Body: `{"repo":"<did>","collection":"<nsid>","record":{…}}`

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"uri","cid","commit"}` | Record written and committed. |
| `400` | `InvalidRequest`/`InvalidRecord` | Bad body or record. |

### `com.atproto.repo.getRecord`

Read a record back from the repo.

```http
GET /xrpc/com.atproto.repo.getRecord?repo=<did>&collection=<nsid>&rkey=<rkey>
```

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"uri","value"}` | Record found. |
| `404` | `RecordNotFound` | No such record. |

### `com.atproto.repo.uploadBlob`

Store a blob (content-addressed by SHA-256).

```http
POST /xrpc/com.atproto.repo.uploadBlob
```

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"blob":{"ref":{"$link":"<cid>"},"mimeType","size"}}` | Blob stored. |

### `com.atproto.sync.getBlob`

Fetch a stored blob by CID.

```http
GET /xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>
```

| Status | Body | When |
|:-------|:-----|:------|
| `200` | blob bytes | Blob found. |
| `404` | `BlobNotFound` | No such blob. |

### `com.atproto.sync.getRepo`

Export the repo as a CAR (v1).

```http
GET /xrpc/com.atproto.sync.getRepo?did=<did>
```

| Status | Body | When |
|:-------|:-----|:------|
| `200` | CAR bytes | Repo exported. |
| `404` | `RepoNotFound` | No repo for the DID. |

### `com.atproto.server.createSession`

Mint an atproto session from a passkey-authenticated access token.

```http
POST /xrpc/com.atproto.server.createSession
```

Body: `{"accessJwt":"<validated access token>"}`

| Status | Body | When |
|:-------|:-----|:------|
| `200` | `{"accessJwt","refreshJwt","did","handle"}` | Session minted. |
| `401` | `AuthenticationRequired` | Invalid access token. |
