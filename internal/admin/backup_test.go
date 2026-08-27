package admin

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestBackupHandlerGet verifies the form is served.
func TestBackupHandlerGet(t *testing.T) {
	h := &BackupHandler{Apply: func(BackupConfig) error { return nil }}
	req := httptest.NewRequest("GET", "/admin/backup", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "schedule") {
		t.Fatalf("form missing schedule field: %q", rec.Body.String())
	}
}

// TestBackupHandlerPost verifies a valid POST applies the config.
func TestBackupHandlerPost(t *testing.T) {
	var applied BackupConfig
	h := &BackupHandler{Apply: func(cfg BackupConfig) error {
		applied = cfg
		return nil
	}}
	form := url.Values{
		"schedule":    {"0 2 * * *"},
		"destination": {"fs"},
		"prefix":      {"backups"},
	}
	req := httptest.NewRequest("POST", "/admin/backup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if applied.Schedule != "0 2 * * *" || applied.Destination != "fs" || applied.Prefix != "backups" {
		t.Fatalf("applied = %+v", applied)
	}
}

// TestBackupHandlerPostError verifies an Apply error returns 400.
func TestBackupHandlerPostError(t *testing.T) {
	h := &BackupHandler{Apply: func(BackupConfig) error { return errors.New("bad config") }}
	form := url.Values{"schedule": {"x"}, "destination": {"fs"}, "prefix": {"p"}}
	req := httptest.NewRequest("POST", "/admin/backup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestBackupHandlerMethodNotAllowed verifies unsupported methods are rejected.
func TestBackupHandlerMethodNotAllowed(t *testing.T) {
	h := &BackupHandler{Apply: func(BackupConfig) error { return nil }}
	req := httptest.NewRequest("DELETE", "/admin/backup", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

// TestValidateBackupConfig verifies config validation.
func TestValidateBackupConfig(t *testing.T) {
	// Valid.
	if err := ValidateBackupConfig(BackupConfig{Schedule: "0 2 * * *", Destination: "fs", Prefix: "backups"}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	// Empty schedule.
	if err := ValidateBackupConfig(BackupConfig{Schedule: "", Destination: "fs", Prefix: "p"}); err == nil {
		t.Fatal("expected error for empty schedule")
	}
	// Invalid destination.
	if err := ValidateBackupConfig(BackupConfig{Schedule: "0 2 * * *", Destination: "gcs", Prefix: "p"}); err == nil {
		t.Fatal("expected error for invalid destination")
	}
	// Empty prefix.
	if err := ValidateBackupConfig(BackupConfig{Schedule: "0 2 * * *", Destination: "fs", Prefix: ""}); err == nil {
		t.Fatal("expected error for empty prefix")
	}
}

// TestEncodeJSON verifies JSON encoding.
func TestEncodeJSON(t *testing.T) {
	b, err := EncodeJSON(BackupConfig{Schedule: "0 2 * * *", Destination: "s3", Prefix: "backups"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"schedule":"0 2 * * *"`) {
		t.Fatalf("json = %s", b)
	}
}
