package main

import (
	"errors"
	"testing"
)

// TestRunHelp verifies run() succeeds with --help.
func TestRunHelp(t *testing.T) {
	if err := run([]string{"--help"}); err != nil {
		t.Fatalf("run(--help) = %v, want nil", err)
	}
}

// TestRunMissingConfig verifies run() errors when the config file is missing.
func TestRunMissingConfig(t *testing.T) {
	if err := run([]string{"--config", "/nonexistent/config.yml"}); err == nil {
		t.Fatal("expected error for missing config")
	}
}

// TestRunMainHelp verifies runMain returns 0 with --help.
func TestRunMainHelp(t *testing.T) {
	if code := runMain([]string{"--help"}); code != 0 {
		t.Fatalf("runMain(--help) = %d, want 0", code)
	}
}

// TestRunMainError verifies runMain returns 1 when run() errors.
func TestRunMainError(t *testing.T) {
	orig := runFn
	runFn = func([]string) error { return errors.New("boom") }
	defer func() { runFn = orig }()

	if code := runMain([]string{"x"}); code != 1 {
		t.Fatalf("runMain with error = %d, want 1", code)
	}
}
