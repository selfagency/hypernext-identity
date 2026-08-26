# Hypernext Identity Server — dev tasks
# Requires: go 1.27+, golangci-lint, govulncheck, pre-commit

.PHONY: all build test lint vet vulncheck fmt hooks install-hooks clean

all: lint test build

# Build a static binary (no CGO)
build:
	CGO_ENABLED=0 go build -o hypernext-identity ./cmd/hypernext-identity

# Run all tests
test:
	go test ./... -race -cover

# Lint + auto-format (gofumpt, gci, staticcheck, gosec, etc.)
lint:
	golangci-lint run ./...

# go vet
vet:
	go vet ./...

# Vulnerability scan (SAST)
vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

# Format all Go files in place
fmt:
	golangci-lint run --fix ./...

# Run all pre-commit hooks on all files
hooks:
	pre-commit run --all-files

# Install pre-commit git hooks
install-hooks:
	pre-commit install

clean:
	rm -f hypernext-identity
