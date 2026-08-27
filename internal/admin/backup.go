// Package admin implements the admin UI wiring for backup configuration.
// It exposes a minimal HTTP form for setting the backup schedule and
// destination, and validates the input before applying it.
package admin

import (
	"encoding/json"
	"net/http"

	"github.com/hypernext/identity/internal/backup"
)

// BackupConfig is the admin-facing backup configuration form.
type BackupConfig struct {
	Schedule string `json:"schedule"`
	// Destination is "fs" or "s3".
	Destination string `json:"destination"`
	// Prefix is the backup path prefix (e.g. "backups").
	Prefix string `json:"prefix"`
}

// BackupHandler serves the backup configuration form.
type BackupHandler struct {
	// Apply persists the config. The storage phase wires a real store.
	Apply func(cfg BackupConfig) error
}

// ServeHTTP handles GET (form) and POST (apply) for backup config.
func (h *BackupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<form method="post">
			<label>Schedule (cron): <input name="schedule" value="0 2 * * *"></label>
			<label>Destination: <select name="destination"><option value="fs">Filesystem</option><option value="s3">S3</option></select></label>
			<label>Prefix: <input name="prefix" value="backups"></label>
			<button type="submit">Save</button>
		</form>`))
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		cfg := BackupConfig{
			Schedule:    r.FormValue("schedule"),
			Destination: r.FormValue("destination"),
			Prefix:      r.FormValue("prefix"),
		}
		if err := h.Apply(cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("saved"))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ValidateBackupConfig validates a backup config against the scheduler.
func ValidateBackupConfig(cfg BackupConfig) error {
	if cfg.Schedule == "" {
		return backup.ErrEmptySchedule
	}
	if cfg.Destination != "fs" && cfg.Destination != "s3" {
		return backup.ErrInvalidDestination
	}
	if cfg.Prefix == "" {
		return backup.ErrEmptyPrefix
	}
	return nil
}

// JSONConfig is the JSON representation for API clients.
type JSONConfig struct {
	Schedule    string `json:"schedule"`
	Destination string `json:"destination"`
	Prefix      string `json:"prefix"`
}

// EncodeJSON marshals a config to JSON.
func EncodeJSON(cfg BackupConfig) ([]byte, error) {
	return json.Marshal(JSONConfig(cfg))
}
