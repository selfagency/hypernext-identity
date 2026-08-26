// Package nodeinfo implements the NodeInfo protocol for fediverse
// discovery (https://nodeinfo.diaspora.software/).
package nodeinfo

import (
	"encoding/json"
	"net/http"
)

// Version is the NodeInfo schema version served.
const Version = "2.1"

// Software describes the server software.
type Software struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Usage describes server usage statistics.
type Usage struct {
	Users Users `json:"users"`
}

// Users describes user counts.
type Users struct {
	Total int `json:"total"`
}

// NodeInfo is the NodeInfo 2.1 document.
type NodeInfo struct {
	Version           string   `json:"version"`
	Software          Software `json:"software"`
	Protocols         []string `json:"protocols"`
	Services          Services `json:"services"`
	OpenRegistrations bool     `json:"openRegistrations"`
	Usage             Usage    `json:"usage"`
}

// Services lists inbound/outbound services.
type Services struct {
	Inbound  []string `json:"inbound"`
	Outbound []string `json:"outbound"`
}

// Config holds the NodeInfo document content.
type Config struct {
	SoftwareName      string
	SoftwareVersion   string
	Protocols         []string
	OpenRegistrations bool
	TotalUsers        int
}

// Handler serves the NodeInfo 2.1 document.
func Handler(cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc := NodeInfo{
			Version: Version,
			Software: Software{
				Name:    cfg.SoftwareName,
				Version: cfg.SoftwareVersion,
			},
			Protocols:         cfg.Protocols,
			Services:          Services{Inbound: []string{}, Outbound: []string{}},
			OpenRegistrations: cfg.OpenRegistrations,
			Usage:             Usage{},
		}
		doc.Usage.Users.Total = cfg.TotalUsers

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			http.Error(w, "encoding error", http.StatusInternalServerError)
		}
	}
}
