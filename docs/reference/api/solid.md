---
title: "Solid Pod"
weight: 20
---

# Solid Pod (`/solid/`)

Serves Linked Data Platform (LDP) reads and writes for the tenant resolved
from the request host, with WebID-derived agents and an ownership ACL.
Verified against `internal/protocols/solid/ldp.go`.

> **Status: Shipped.** LDP `GET`/`PUT`/`POST`/`PATCH`/`DELETE`, `HEAD`,
> `OPTIONS`, container listings as Turtle, Web Access Control (WAC) rule
> documents, and a Solid-OIDC `webid`-claim identity challenge all work and
> are tested. The ACL is WAC-based with an ownership fallback.

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

## Access control (WAC + ownership fallback)

The ACL is **Web Access Control** (`internal/protocols/solid.WACChecker`): it
evaluates `.acl` rule documents (Turtle) and falls back to the ownership-based
checker when no ACL resource exists. Supported ACL predicates: `acl:agent`,
`acl:agentClass` (`acl:AuthenticatedAgent`), `acl:accessTo`, and `acl:mode`.

| Check | Public agent | Owning agent | ACL-granted agent |
|:------|:-------------|:-------------|:------------------|
| `CanRead` | per ACL (default deny for private data) | allowed | allowed |
| `CanWrite` | denied | allowed | allowed |

A disallowed request → `403 forbidden`.

## Methods

| Method | Path | ACL | Success | Notes |
|:-------|:-----|:----|:--------|:------|
| `GET` | `/solid/<path>` | `CanRead` | `200` + body | Resource bytes; `Content-Type` from storage. |
| `GET` | `/solid/<path>/` | `CanRead` | `200` + Turtle | **Container** (trailing slash): lists children as Turtle with `Link: <...#BasicContainer>; rel="type"`. |
| `HEAD` | `/solid/<path>` | `CanRead` | `200` | Headers only, no body. |
| `OPTIONS` | `/solid/<path>` | — | `204` | Advertises `Allow` (incl. `PATCH`) and `Accept-Patch`. |
| `PUT` | `/solid/<path>` | `CanWrite` | `201` | Store/replace a resource. |
| `POST` | `/solid/<path>` | `CanWrite` | `201` | Create a child resource. |
| `PATCH` | `/solid/<path>` | `CanWrite` | `204` | Apply a SPARQL-update `INSERT DATA`/`DELETE DATA` patch to an RDF resource. |
| `DELETE` | `/solid/<path>` | `CanWrite` | `204` | Delete a resource. Missing → `404`. |

Other methods → `405`. The `Allow` header advertises
`GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE`, all of which are now handled.

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

* No live notifications.
* No WebID profile document route on this prefix (see `/profile/`).
* PATCH supports the SPARQL-update `INSERT DATA`/`DELETE DATA` subset (no
  `WHERE` clauses, graph patterns, `FILTER`, or blank nodes).
* No live Solid notifications.
