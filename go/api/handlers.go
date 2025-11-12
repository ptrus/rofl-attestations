package api

import (
	"bytes"
	_ "embed"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

//go:embed index.html
var indexHTML []byte

// serveIndex serves the main HTML page.
func (s *Server) serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write(indexHTML)
}

// handleGetApps returns all apps as HTML fragments.
func (s *Server) handleGetApps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	apps, err := s.db.GetAllApps(ctx)
	if err != nil {
		http.Error(w, "Failed to load apps", http.StatusInternalServerError)
		return
	}

	// Generate HTML for each app with their deployments.
	var buf bytes.Buffer
	verified := 0
	totalDeployments := 0
	for _, app := range apps {
		// Get deployments for this app
		deps, err := s.db.GetDeploymentsByAppID(ctx, app.ID)
		if err != nil {
			s.logger.Error("failed to get deployments", "app_id", app.ID, "error", err)
			deps = nil // Continue with empty deployments
		}

		html, err := s.renderAppCard(app, deps)
		if err != nil {
			s.logger.Error("failed to render app card", "app_id", app.ID, "error", err)
			continue
		}
		buf.WriteString(html)
		buf.WriteString("\n")

		// Count verified apps (at least one deployment verified)
		hasVerified := false
		for _, dep := range deps {
			if dep.Status == "verified" {
				hasVerified = true
			}
		}
		if hasVerified {
			verified++
		}

		totalDeployments += len(deps)
	}

	// Update stats using hx-swap-oob to avoid accumulating scripts in DOM
	statsHTML := fmt.Sprintf(`
<div id="total-apps" hx-swap-oob="true">%d</div>
<div id="verified-apps" hx-swap-oob="true">%d</div>
<div id="deployments" hx-swap-oob="true">%d</div>
`, len(apps), verified, totalDeployments)

	buf.WriteString(statsHTML)

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write(buf.Bytes())
}

// handleGetApp returns a single app's details.
func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	idStr := chi.URLParam(r, "id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid app ID", http.StatusBadRequest)
		return
	}

	app, err := s.db.GetAppByID(ctx, id)
	if err != nil {
		http.Error(w, "App not found", http.StatusNotFound)
		return
	}

	// Get deployments for this app
	deps, err := s.db.GetDeploymentsByAppID(ctx, id)
	if err != nil {
		s.logger.Error("failed to get deployments", "app_id", id, "error", err)
		deps = nil // Continue with empty deployments
	}

	html, err := s.renderAppCard(app, deps)
	if err != nil {
		http.Error(w, "Failed to render app", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write([]byte(html))
}
