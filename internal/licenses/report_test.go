package licenses

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGoMod writes a test go.mod file.
func writeGoMod(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFromGoMod verifies direct dependency parsing.
func TestFromGoMod(t *testing.T) {
	path := writeGoMod(t, `module example.com/test

go 1.27

require (
	github.com/zitadel/oidc/v3 v3.49.2
	github.com/robfig/cron/v3 v3.0.1
	github.com/unknown/mod v1.0.0
)
`)
	deps, err := FromGoMod(path)
	if err != nil {
		t.Fatalf("FromGoMod: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("deps = %d, want 3", len(deps))
	}
	// Sorted by path.
	if deps[0].Path != "github.com/robfig/cron/v3" {
		t.Fatalf("first dep = %s", deps[0].Path)
	}
	if deps[0].License != "MIT" {
		t.Fatalf("cron license = %s, want MIT", deps[0].License)
	}
	if deps[1].License != "unknown" {
		t.Fatalf("unknown license = %s, want unknown", deps[1].License)
	}
}

// TestFromGoModMissingFile verifies a missing go.mod errors.
func TestFromGoModMissingFile(t *testing.T) {
	if _, err := FromGoMod("/nonexistent/go.mod"); err == nil {
		t.Fatal("expected error for missing go.mod")
	}
}

// TestRenderMarkdown verifies the markdown table.
func TestRenderMarkdown(t *testing.T) {
	deps := []Dependency{
		{Path: "github.com/zitadel/oidc/v3", Version: "v3.49.2", License: "Apache-2.0"},
		{Path: "github.com/robfig/cron/v3", Version: "v3.0.1", License: "MIT"},
	}
	md := RenderMarkdown(deps)
	if !strings.Contains(md, "# Third-Party Licenses") {
		t.Fatalf("missing header: %q", md)
	}
	if !strings.Contains(md, "| github.com/zitadel/oidc/v3 | v3.49.2 | Apache-2.0 |") {
		t.Fatalf("missing oidc row: %q", md)
	}
	if !strings.Contains(md, "| github.com/robfig/cron/v3 | v3.0.1 | MIT |") {
		t.Fatalf("missing cron row: %q", md)
	}
}

// TestLicenseFor verifies known license lookup.
func TestLicenseFor(t *testing.T) {
	if LicenseFor("github.com/zitadel/oidc/v3") != "Apache-2.0" {
		t.Fatal("oidc license mismatch")
	}
	if LicenseFor("github.com/robfig/cron/v3") != "MIT" {
		t.Fatal("cron license mismatch")
	}
	if LicenseFor("github.com/unknown/mod") != "unknown" {
		t.Fatal("unknown license mismatch")
	}
}

// TestGenerate verifies the full generation path.
func TestGenerate(t *testing.T) {
	path := writeGoMod(t, `module example.com/test

go 1.27

require github.com/zitadel/oidc/v3 v3.49.2
`)
	md, err := Generate(path)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(md, "github.com/zitadel/oidc/v3") {
		t.Fatalf("missing oidc in report: %q", md)
	}
}
