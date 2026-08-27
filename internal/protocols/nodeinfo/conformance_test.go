package nodeinfo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSpecConformanceNodeInfo verifies the NodeInfo 2.1 document matches the
// schema exactly: version, software, protocols, services, openRegistrations,
// usage. https://nodeinfo.diaspora.software/protocol.html
func TestSpecConformanceNodeInfo(t *testing.T) {
	h := Handler(Config{
		SoftwareName:      "sovereign",
		SoftwareVersion:   "0.1.0",
		Protocols:         []string{"solid", "remotestorage", "atproto"},
		OpenRegistrations: false,
		TotalUsers:        3,
	})
	req := httptest.NewRequest("GET", "/.well-known/nodeinfo", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	assertNodeInfoVersion(t, raw)
	assertNodeInfoSoftware(t, raw)
	assertNodeInfoProtocols(t, raw)
	assertNodeInfoServices(t, raw)
	assertNodeInfoUsage(t, raw)
}

func assertNodeInfoVersion(t *testing.T, raw map[string]any) {
	t.Helper()
	if raw["version"] != "2.1" {
		t.Fatalf("version = %v, want 2.1", raw["version"])
	}
}

func assertNodeInfoSoftware(t *testing.T, raw map[string]any) {
	t.Helper()
	software, ok := raw["software"].(map[string]any)
	if !ok {
		t.Fatalf("software not an object: %v", raw["software"])
	}
	if software["name"] != "sovereign" || software["version"] != "0.1.0" {
		t.Fatalf("software = %v", software)
	}
}

func assertNodeInfoProtocols(t *testing.T, raw map[string]any) {
	t.Helper()
	protocols, ok := raw["protocols"].([]any)
	if !ok || len(protocols) != 3 {
		t.Fatalf("protocols = %v, want 3", raw["protocols"])
	}
}

func assertNodeInfoServices(t *testing.T, raw map[string]any) {
	t.Helper()
	services, ok := raw["services"].(map[string]any)
	if !ok {
		t.Fatalf("services not an object: %v", raw["services"])
	}
	if _, ok := services["inbound"].([]any); !ok {
		t.Fatalf("services.inbound not an array: %v", services["inbound"])
	}
	if _, ok := services["outbound"].([]any); !ok {
		t.Fatalf("services.outbound not an array: %v", services["outbound"])
	}
	if raw["openRegistrations"] != false {
		t.Fatalf("openRegistrations = %v, want false", raw["openRegistrations"])
	}
}

func assertNodeInfoUsage(t *testing.T, raw map[string]any) {
	t.Helper()
	usage, ok := raw["usage"].(map[string]any)
	if !ok {
		t.Fatalf("usage not an object: %v", raw["usage"])
	}
	users, ok := usage["users"].(map[string]any)
	if !ok {
		t.Fatalf("usage.users not an object: %v", usage["users"])
	}
	if users["total"] != float64(3) {
		t.Fatalf("usage.users.total = %v, want 3", users["total"])
	}
}
