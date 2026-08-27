---
title: "Discovery: WebFinger, NodeInfo, Profile"
weight: 40
---

# Discovery endpoints

Host-level discovery: WebFinger, NodeInfo, and the content-negotiated
profile. Verified against `internal/protocols/webfinger`,
`internal/protocols/nodeinfo`, and the profile wiring in
`internal/server/server.go`.

## WebFinger — `/.well-known/webfinger`

[RFC 7033](https://www.rfc-editor.org/rfc/rfc7033) WebFinger. This is the
connective tissue: one identity, one set of `.well-known` links resolved
per protocol. The tenant is resolved from the request host.

```http
GET /.well-known/webfinger?resource=acct:alice@example.com
```

| Query param | Required | Purpose |
|:------------|:---------|:--------|
| `resource` | yes | The resource to describe (e.g. `acct:alice@example.com`). |

Responses:

| Status | When |
|:-------|:-----|
| `200` `application/jrd+json` | Resource described (see below). |
| `400` | Missing `resource` parameter. |
| `404` | Unknown host / no tenant in context. |

A `200` JRD echoes the `subject`, adds the tenant handle as an alias, and
carries links for each protocol:

```json
{
  "subject": "acct:alice@example.com",
  "aliases": ["https://alice.example.com"],
  "links": [
    { "rel": "http://tools.ietf.org/id/draft-dejong-remotestorage", "href": "https://example.com/rs/" },
    { "rel": "self", "type": "application/activity+json", "href": "https://example.com/profile/" },
    { "rel": "http://openid.net/specs/connect/1.0/issuer", "href": "https://id.example.com" }
  ]
}
```

> The OIDC `issuer` link is advertised for discovery, but the OIDC provider
> endpoints themselves are [not yet mounted](../../explanation/status.md). The
> link resolves once the provider is wired.

## NodeInfo — `/.well-known/nodeinfo`

[NodeInfo](https://nodeinfo.diaspora.software/) software advertisement.
Reports the software name/version and the protocols this server speaks.

```http
GET /.well-known/nodeinfo
```

Advertises `sovereign` and the protocols `solid`, `remotestorage`, and
`atproto`, with `openRegistrations: false` (accounts are provisioned, not
self-service today).

## Profile — `/profile/`

Content-negotiated profile document. The representation is selected from the
`Accept` header:

| Accept | Representation |
|:-------|:---------------|
| `text/html` (default) | HTML h-card |
| `application/activity+json` | ActivityStreams actor |
| `application/did+json` | DID document (`did:web:<host>`) |

```bash
# HTML h-card.
curl https://alice.example.com/profile/

# ActivityPub actor.
curl -H "Accept: application/activity+json" https://alice.example.com/profile/

# DID document.
curl -H "Accept: application/did+json" https://alice.example.com/profile/
```

> **Status: Partial.** The h-card and DID document are minimal (the DID doc is
> `{"id": "did:web:<host>"}`); the actor document is served by the
> `activitypub` package. Richer profile data is future work.
