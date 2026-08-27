// Package licenses generates a THIRD_PARTY_LICENSES.md report from the Go
// module graph. It lists each direct dependency with its module path, version,
// and license, so operators can verify license compliance before shipping.
package licenses

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Dependency is a single module dependency.
type Dependency struct {
	// Path is the module path (e.g. github.com/zitadel/oidc/v3).
	Path string
	// Version is the module version.
	Version string
	// License is the SPDX license identifier (best-effort).
	License string
}

// Report is the license report.
type Report struct {
	// Dependencies are the direct dependencies.
	Dependencies []Dependency
}

// knownLicenses maps well-known module prefixes to their licenses. This is a
// best-effort static map; the go-licenses tool is the authoritative source.
var knownLicenses = map[string]string{
	"github.com/bluesky-social/indigo": "Apache-2.0",
	"github.com/go-webauthn/webauthn":  "BSD-3-Clause",
	"github.com/ipfs/go-cid":           "Apache-2.0",
	"github.com/minio/minio-go/v7":     "Apache-2.0",
	"github.com/robfig/cron/v3":        "MIT",
	"github.com/zitadel/oidc/v3":       "Apache-2.0",
	"go.hacdias.com/indielib":          "MIT",
}

// LicenseFor returns the known license for a module path, or "unknown".
func LicenseFor(path string) string {
	if l, ok := knownLicenses[path]; ok {
		return l
	}
	return "unknown"
}

// FromGoMod reads the direct dependencies from a go.mod file.
func FromGoMod(path string) ([]Dependency, error) {
	// #nosec G304 -- path is a caller-provided go.mod path, not user input.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	inRequire := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if isRequireBoundary(line, &inRequire) {
			continue
		}
		if dep, ok := parseRequireLine(line, inRequire); ok {
			deps = append(deps, dep)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(deps, func(i, j int) bool { return deps[i].Path < deps[j].Path })
	return deps, nil
}

// isRequireBoundary handles the "require (" ... ")" block delimiters and
// returns true if the line was a boundary (not a dependency).
func isRequireBoundary(line string, inRequire *bool) bool {
	if line == "require (" {
		*inRequire = true
		return true
	}
	if *inRequire && line == ")" {
		*inRequire = false
		return true
	}
	return false
}

// parseRequireLine parses a single dependency line. It handles both block
// lines ("github.com/x v1.0.0") and single-line requires
// ("require github.com/x v1.0.0").
func parseRequireLine(line string, inRequire bool) (Dependency, bool) {
	if !inRequire && strings.HasPrefix(line, "require ") {
		line = strings.TrimPrefix(line, "require ")
	}
	if !inRequire && !strings.HasPrefix(line, "github.com/") && !strings.HasPrefix(line, "go.hacdias.com/") {
		return Dependency{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Dependency{}, false
	}
	return Dependency{
		Path:    fields[0],
		Version: fields[1],
		License: LicenseFor(fields[0]),
	}, true
}

// RenderMarkdown renders the report as a markdown table.
func RenderMarkdown(deps []Dependency) string {
	var sb strings.Builder
	sb.WriteString("# Third-Party Licenses\n\n")
	sb.WriteString("This project depends on the following third-party modules.\n\n")
	sb.WriteString("| Module | Version | License |\n")
	sb.WriteString("|--------|---------|---------|\n")
	for _, d := range deps {
		fmt.Fprintf(&sb, "| %s | %s | %s |\n", d.Path, d.Version, d.License)
	}
	return sb.String()
}

// Generate runs `go list -m all` and renders the report. It is the
// production path; FromGoMod is the testable subset.
func Generate(goModPath string) (string, error) {
	deps, err := FromGoMod(goModPath)
	if err != nil {
		return "", err
	}
	return RenderMarkdown(deps), nil
}

// RunGoList executes `go list -m all` in a directory (used by the CLI).
func RunGoList(ctx context.Context, dir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "all")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n"), nil
}
