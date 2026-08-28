package hyperlink

import (
	"encoding/json"
	"html/template"
	"net/http"
	"strings"
)

// Profile is the public profile page data.
type Profile struct {
	DisplayName string
	Bio         string
	AvatarURL   string
	Handle      string
	Published   bool
	Links       []Link
}

// Renderer renders the public profile page with content negotiation:
// Accept: text/html -> rendered page; Accept: application/json -> JSON.
type Renderer struct {
	// GetProfile loads the profile for a handle. Returns nil if unpublished
	// or not found (caller renders a uniform 404).
	GetProfile func(handle string) (*Profile, error)
}

// ServeHTTP serves the public profile page.
func (r *Renderer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	handle := strings.TrimPrefix(req.URL.Path, "/")
	handle = strings.TrimSuffix(handle, "/")
	if handle == "" {
		http.NotFound(w, req)
		return
	}
	profile, err := r.GetProfile(handle)
	if err != nil || profile == nil || !profile.Published {
		// Uniform 404 for unpublished/unknown — no tenant-enumeration signal.
		http.NotFound(w, req)
		return
	}

	// Content negotiation.
	if acceptsJSON(req.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(profile)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=60")
	_ = RenderHTML(w, profile)
}

// acceptsJSON reports whether the Accept header prefers JSON.
func acceptsJSON(accept string) bool {
	return strings.Contains(accept, "application/json")
}

// RenderHTML renders the profile page with h-card microformats2 markup.
func RenderHTML(w http.ResponseWriter, p *Profile) error {
	tmpl := template.Must(template.New("profile").Parse(profileTemplate))
	return tmpl.Execute(w, p)
}

const profileTemplate = `<!DOCTYPE html>
<html>
<head><title>{{.DisplayName}}</title></head>
<body>
<div class="h-card">
  {{if .AvatarURL}}<img class="u-photo" src="{{.AvatarURL}}" alt="">{{end}}
  <h1 class="p-name">{{.DisplayName}}</h1>
  <a class="u-url" href="https://{{.Handle}}/">{{.Handle}}</a>
  {{if .Bio}}<p class="p-note">{{.Bio}}</p>{{end}}
</div>
<ul class="links">
{{range .Links}}{{if .Visible}}
  <li><a href="{{.URL}}" rel="me">{{.Label}}</a></li>
{{end}}{{end}}
</ul>
</body>
</html>`
