package api

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

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

// VerifyRequest represents the verification request payload.
type VerifyRequest struct {
	GitHubURL      string `json:"github_url"`
	GitRef         string `json:"git_ref"`
	DeploymentName string `json:"deployment_name"`
}

// VerifyResponse represents the verification response.
type VerifyResponse struct {
	TaskID string `json:"task_id"`
}

// handleVerify handles POST /api/verify - submits job to backend and returns task info.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.GitHubURL == "" || req.DeploymentName == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if req.GitRef == "" {
		req.GitRef = "main"
	}

	// Get backend URL from config
	backendURL := s.cfg.Worker.BackendURL
	if backendURL == "" {
		http.Error(w, "Backend verification service not configured", http.StatusServiceUnavailable)
		return
	}

	// Submit to backend
	taskID, err := s.submitToBackend(ctx, backendURL, req.GitHubURL, req.GitRef, req.DeploymentName)
	if err != nil {
		s.logger.Error("failed to submit verification", "error", err)
		http.Error(w, fmt.Sprintf("Failed to submit verification: %v", err), http.StatusInternalServerError)
		return
	}

	// Return task ID
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(VerifyResponse{
		TaskID: taskID,
	})
}

// submitToBackend submits a verification job to the backend.
func (s *Server) submitToBackend(ctx context.Context, backendURL, repoURL, ref, deploymentName string) (string, error) {
	reqBody := map[string]string{
		"repository_url":  repoURL,
		"ref":             ref,
		"deployment_name": deploymentName,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/rofl/verify_deployments", backendURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication if available
	if s.authClient != nil {
		token, err := s.authClient.GetToken(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get auth token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		TaskID string `json:"task_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.TaskID, nil
}

// handleVerifyResults proxies the polling request to the backend.
func (s *Server) handleVerifyResults(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	taskID := chi.URLParam(r, "task_id")

	if taskID == "" {
		http.Error(w, "Missing task_id", http.StatusBadRequest)
		return
	}

	backendURL := s.cfg.Worker.BackendURL
	if backendURL == "" {
		http.Error(w, "Backend verification service not configured", http.StatusServiceUnavailable)
		return
	}

	// Proxy request to backend
	url := fmt.Sprintf("%s/rofl/verify_deployments/%s/results", backendURL, taskID)
	proxyReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// Add authentication if available
	if s.authClient != nil {
		token, err := s.authClient.GetToken(ctx)
		if err != nil {
			s.logger.Error("failed to get auth token for polling", "error", err)
			http.Error(w, "Failed to authenticate", http.StatusInternalServerError)
			return
		}
		proxyReq.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		s.logger.Error("failed to poll backend", "error", err)
		http.Error(w, "Failed to contact backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response status and body
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
