package main

import (
	"errors"
	"testing"
)

// TestRunNoArgs verifies run() succeeds with no arguments (skeleton CLI).
func TestRunNoArgs(t *testing.T) {
	if err := run(nil); err != nil {
		t.Fatalf("run(nil) = %v, want nil", err)
	}
	if err := run([]string{}); err != nil {
		t.Fatalf("run([]) = %v, want nil", err)
	}
}

// TestRunMainNoArgs verifies runMain returns 0 with no arguments.
func TestRunMainNoArgs(t *testing.T) {
	if code := runMain(nil); code != 0 {
		t.Fatalf("runMain(nil) = %d, want 0", code)
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
