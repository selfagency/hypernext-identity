package atproto

import (
	"context"

	"github.com/bluesky-social/indigo/xrpc"
)

// XRPCClient wraps the indigo XRPC client for making atproto calls.
type XRPCClient struct {
	c *xrpc.Client
}

// NewXRPCClient builds an XRPC client for a host.
func NewXRPCClient(host string) *XRPCClient {
	return &XRPCClient{c: &xrpc.Client{Host: host}}
}

// ResolveHandle calls com.atproto.identity.resolveHandle.
func (x *XRPCClient) ResolveHandle(ctx context.Context, handle string) (string, error) {
	var out struct {
		Did string `json:"did"`
	}
	err := x.c.Do(ctx, xrpc.Query, "", "com.atproto.identity.resolveHandle",
		map[string]any{"handle": handle}, nil, &out)
	if err != nil {
		return "", err
	}
	return out.Did, nil
}

// GetProfile calls app.bsky.actor.getProfile.
func (x *XRPCClient) GetProfile(ctx context.Context, actor string) (map[string]any, error) {
	var out map[string]any
	err := x.c.Do(ctx, xrpc.Query, "", "app.bsky.actor.getProfile",
		map[string]any{"actor": actor}, nil, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}
