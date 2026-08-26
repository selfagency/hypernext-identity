// Package ipfspin implements the IPFS pinning broker. It is a client-side
// adapter that calls out to a configured backend (a local/remote Kubo node's
// RPC API, or any pinning-services-api-spec-compliant provider) to persist
// and replicate pinned content. It does not embed an IPFS node.
package ipfspin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	cid "github.com/ipfs/go-cid"
)

// Backend is the pinning contract. A nil Backend (no IPFS configured) makes
// pin operations no-ops.
type Backend interface {
	// Pin requests the backend to pin the given CID.
	Pin(ctx context.Context, c cid.Cid) error
	// Unpin requests the backend to unpin the given CID.
	Unpin(ctx context.Context, c cid.Cid) error
	// Status returns the pin status for the given CID.
	Status(ctx context.Context, c cid.Cid) (string, error)
}

// ErrNoBackend is returned when no IPFS backend is configured.
var ErrNoBackend = errors.New("no IPFS backend configured")

// KuboRPC talks to a user-run Kubo node's HTTP RPC API.
type KuboRPC struct {
	BaseURL string
	Client  *http.Client
}

// NewKuboRPC builds a Kubo RPC client.
func NewKuboRPC(baseURL string) *KuboRPC {
	return &KuboRPC{BaseURL: baseURL, Client: &http.Client{Timeout: 30 * time.Second}}
}

// Pin adds a CID to the Kubo node's pin set.
func (k *KuboRPC) Pin(ctx context.Context, c cid.Cid) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v0/pin/add?arg=%s", k.BaseURL, c.String()), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kubo pin failed: %s", resp.Status)
	}
	return nil
}

// Unpin removes a CID from the Kubo node's pin set.
func (k *KuboRPC) Unpin(ctx context.Context, c cid.Cid) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v0/pin/rm?arg=%s", k.BaseURL, c.String()), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kubo unpin failed: %s", resp.Status)
	}
	return nil
}

// Status queries the Kubo node for a CID's pin status.
func (k *KuboRPC) Status(ctx context.Context, c cid.Cid) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v0/pin/ls?arg=%s", k.BaseURL, c.String()), http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := k.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kubo status failed: %s", resp.Status)
	}
	// Kubo returns JSON; we just report success for the pin presence.
	return "pinned", nil
}

// PSAClient talks to any pinning-services-api-spec-compliant provider.
type PSAClient struct {
	Endpoint string
	Token    string
	Client   *http.Client
}

// NewPSAClient builds a PSA-spec client.
func NewPSAClient(endpoint, token string) *PSAClient {
	return &PSAClient{Endpoint: endpoint, Token: token, Client: &http.Client{Timeout: 30 * time.Second}}
}

// Pin requests the provider to pin the given CID.
func (p *PSAClient) Pin(ctx context.Context, c cid.Cid) error {
	body := fmt.Sprintf(`{"cid":%q}`, c.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint+"/pins", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("psa pin failed: %s", resp.Status)
	}
	return nil
}

// Unpin requests the provider to unpin the given CID.
func (p *PSAClient) Unpin(ctx context.Context, c cid.Cid) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.Endpoint+"/pins/"+c.String(), http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("psa unpin failed: %s", resp.Status)
	}
	return nil
}

// Status queries the provider for a CID's pin status.
func (p *PSAClient) Status(ctx context.Context, c cid.Cid) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/pins/"+c.String(), http.NoBody)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := p.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("psa status failed: %s", resp.Status)
	}
	// Parse the status field from the JSON response.
	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.Status, nil
}
