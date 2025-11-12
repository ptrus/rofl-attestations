// Package worker implements periodic verification of ROFL applications.
package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ptrus/rofl-attestations/config"
	"github.com/ptrus/rofl-attestations/db"
	"github.com/ptrus/rofl-attestations/models"
	"github.com/ptrus/rofl-attestations/rofl"
)

// Worker handles periodic verification of ROFL apps.
type Worker struct {
	cfg        *config.WorkerConfig
	db         *db.DB
	logger     *slog.Logger
	client     *http.Client
	authClient *AuthClient
}

// VerifyDeploymentsRequest represents the request to verify_deployments endpoint.
type VerifyDeploymentsRequest struct {
	RepositoryURL  string `json:"repository_url"`
	Ref            string `json:"ref"`
	DeploymentName string `json:"deployment_name"`
}

// VerifyDeploymentsResponse represents the response from verify_deployments endpoint.
type VerifyDeploymentsResponse struct {
	TaskID string `json:"task_id"`
}

// VerifyDeploymentsResult represents the polling result.
type VerifyDeploymentsResult struct {
	Status    string `json:"status,omitempty"` // "in_progress" when 202
	Verified  bool   `json:"verified"`
	CommitSHA string `json:"commit_sha"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Err       string `json:"err"`
}

// New creates a new worker instance.
func New(cfg *config.WorkerConfig, database *db.DB, logger *slog.Logger) (*Worker, error) {
	var authClient *AuthClient
	var err error

	// Initialize auth client if private key is provided
	if cfg.PrivateKey != "" {
		authClient, err = NewAuthClient(
			cfg.BackendURL,
			cfg.PrivateKey,
			cfg.SIWEDomain,
			cfg.ChainID,
			logger,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth client: %w", err)
		}
		logger.Info("authentication enabled", "address", authClient.address.Hex())
	} else {
		logger.Warn("no private key configured, running without authentication")
	}

	return &Worker{
		cfg:        cfg,
		db:         database,
		logger:     logger,
		authClient: authClient,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Start begins the continuous verification loop, cycling through apps one by one.
func (w *Worker) Start(ctx context.Context) error {
	if !w.cfg.Enabled {
		w.logger.Info("worker disabled, skipping periodic verification")
		return nil
	}

	w.logger.Info("starting verification worker",
		"app_interval", w.cfg.AppInterval,
		"backend_url", w.cfg.BackendURL)

	appInterval := time.Duration(w.cfg.AppInterval) * time.Minute

	for {
		// Check context before starting a new cycle
		if ctx.Err() != nil {
			w.logger.Info("worker stopped")
			return ctx.Err()
		}

		w.logger.Info("starting verification cycle")

		// Get all apps
		apps, err := w.db.GetAllApps(ctx)
		if err != nil {
			w.logger.Error("failed to get apps", "error", err)
			// Wait before retrying
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(appInterval):
				continue
			}
		}

		if len(apps) == 0 {
			w.logger.Info("no apps to verify, waiting before next cycle")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(appInterval):
				continue
			}
		}

		w.logger.Info("verifying apps one by one", "count", len(apps))

		// Process each app one at a time
		for i, app := range apps {
			if ctx.Err() != nil {
				w.logger.Info("context cancelled, stopping verification cycle")
				return ctx.Err()
			}

			w.logger.Info("processing app",
				"app_id", app.ID,
				"progress", fmt.Sprintf("%d/%d", i+1, len(apps)))

			if err := w.verifyApp(ctx, app); err != nil {
				w.logger.Error("failed to verify app",
					"app_id", app.ID,
					"github_url", app.GitHubURL,
					"error", err)
			}

			// Wait before processing next app
			if i < len(apps)-1 {
				w.logger.Info("waiting before next app", "duration", appInterval)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(appInterval):
					// Continue to next app
				}
			}
		}

		w.logger.Info("verification cycle completed, waiting before next cycle", "duration", appInterval)

		// Wait before starting the next cycle to avoid hammering the backend
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(appInterval):
			// Continue to next cycle
		}
	}
}

// verifyApp verifies a single app by checking all its deployments.
func (w *Worker) verifyApp(ctx context.Context, app *models.App) error {
	w.logger.Info("verifying app", "app_id", app.ID, "github_url", app.GitHubURL)

	// Fetch latest rofl.yaml from GitHub
	if err := w.fetchRoflYAML(ctx, app); err != nil {
		w.logger.Error("failed to fetch rofl.yaml", "app_id", app.ID, "error", err)
		return fmt.Errorf("failed to fetch rofl.yaml: %w", err)
	}

	// Parse rofl.yaml to get deployments
	if !app.RoflYAML.Valid || app.RoflYAML.String == "" {
		w.logger.Warn("app has no rofl.yaml, skipping", "app_id", app.ID)
		return nil
	}

	manifest, err := rofl.Parse([]byte(app.RoflYAML.String))
	if err != nil {
		return fmt.Errorf("failed to parse rofl.yaml: %w", err)
	}

	if len(manifest.Deployments) == 0 {
		w.logger.Warn("app has no deployments, skipping", "app_id", app.ID)
		return nil
	}

	// Verify each deployment
	var lastErr error
	for deploymentName := range manifest.Deployments {
		w.logger.Info("verifying deployment",
			"app_id", app.ID,
			"deployment", deploymentName)

		if err := w.verifyDeployment(ctx, app, deploymentName); err != nil {
			w.logger.Error("deployment verification failed",
				"app_id", app.ID,
				"deployment", deploymentName,
				"error", err)
			lastErr = err
		}
	}

	return lastErr
}

// fetchRoflYAML fetches the rofl.yaml file from GitHub and updates the database.
func (w *Worker) fetchRoflYAML(ctx context.Context, app *models.App) error {
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com%s/%s/rofl.yaml",
		app.GitHubURL[len("https://github.com"):],
		app.GitRef)

	w.logger.Debug("fetching rofl.yaml", "url", rawURL)

	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	roflYAML, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}

	if err := w.db.UpdateAppRoflYAML(ctx, app.ID, string(roflYAML)); err != nil {
		return fmt.Errorf("failed to update db: %w", err)
	}

	app.RoflYAML.String = string(roflYAML)
	app.RoflYAML.Valid = true

	w.logger.Debug("successfully fetched rofl.yaml", "size", len(roflYAML))
	return nil
}

// verifyDeployment submits a verification request for a specific deployment and polls for results.
func (w *Worker) verifyDeployment(ctx context.Context, app *models.App, deploymentName string) error {
	// Submit verification request
	taskID, err := w.submitVerification(ctx, app.GitHubURL, app.GitRef, deploymentName)
	if err != nil {
		// Update deployment status to failed
		updateErr := w.db.UpsertDeployment(ctx, app.ID, deploymentName, "", "failed",
			fmt.Sprintf("Failed to submit verification: %v", err))
		if updateErr != nil {
			w.logger.Error("failed to update deployment status", "error", updateErr)
		}
		return fmt.Errorf("failed to submit verification: %w", err)
	}

	w.logger.Info("verification task submitted",
		"app_id", app.ID,
		"deployment", deploymentName,
		"task_id", taskID)

	// Poll for results
	result, err := w.pollResults(ctx, taskID)
	if err != nil {
		// Update deployment status to failed
		updateErr := w.db.UpsertDeployment(ctx, app.ID, deploymentName, "", "failed",
			fmt.Sprintf("Failed to poll results: %v", err))
		if updateErr != nil {
			w.logger.Error("failed to update deployment status", "error", updateErr)
		}
		return fmt.Errorf("failed to poll results: %w", err)
	}

	// Update database with results
	status := "failed"
	var verificationMsg string
	if result.Verified {
		status = "verified"
		verificationMsg = "Built enclave identities MATCH on-chain measurements. Verification successful."
	} else {
		// Parse verification failure details
		verificationMsg = w.formatVerificationError(result)
	}

	// Use commit SHA from backend response
	commitSHA := result.CommitSHA

	if err := w.db.UpsertDeployment(ctx, app.ID, deploymentName, commitSHA, status, verificationMsg); err != nil {
		return fmt.Errorf("failed to update deployment verification: %w", err)
	}

	w.logger.Info("verification completed",
		"app_id", app.ID,
		"deployment", deploymentName,
		"status", status,
		"verified", result.Verified,
		"commit_sha", commitSHA)

	return nil
}

// formatVerificationError formats verification errors into user-friendly messages.
func (w *Worker) formatVerificationError(result *VerifyDeploymentsResult) string {
	// Check if it's a command failure
	if strings.Contains(result.Err, "exit status 1") || strings.Contains(result.Err, "command") {
		msg := "Verification failed: enclave measurements do not match on-chain deployments.\n\n"

		// Try to parse mismatched IDs from stderr
		mismatchedIDs := w.parseMismatchedIDs(result.Stderr + "\n" + result.Stdout)
		if len(mismatchedIDs) > 0 {
			msg += "Mismatched Enclave IDs:\n"
			for _, id := range mismatchedIDs {
				msg += fmt.Sprintf("  - %s\n", id)
			}
			msg += "\n"
		}

		// Add a hint about what this means
		msg += "This usually means the application was built with different code or build configuration than what's in the repository."

		return msg
	}

	// For other errors, use the error message
	if result.Err != "" {
		return result.Err
	}

	// Generic failure message
	return "Verification failed: enclave measurements do not match"
}

// parseMismatchedIDs attempts to extract enclave IDs from verification output.
func (w *Worker) parseMismatchedIDs(output string) []string {
	var ids []string

	// Look for patterns like "rofl1..." in the output
	// Common in oasis-cli output when showing mismatches
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		// Match lines containing enclave identifiers
		if strings.Contains(line, "rofl1") {
			// Extract rofl1... addresses
			words := strings.Fields(line)
			for _, word := range words {
				if strings.HasPrefix(word, "rofl1") && len(word) > 10 {
					// Clean up any trailing punctuation
					id := strings.TrimRight(word, ",.;:")
					ids = append(ids, id)
				}
			}
		}

		// Also look for explicit mismatch indicators
		if strings.Contains(strings.ToLower(line), "mismatch") ||
			strings.Contains(strings.ToLower(line), "expected") ||
			strings.Contains(strings.ToLower(line), "actual") {
			// This line might contain relevant info, keep it
			if strings.Contains(line, "rofl1") {
				words := strings.Fields(line)
				for _, word := range words {
					if strings.HasPrefix(word, "rofl1") && len(word) > 10 {
						id := strings.TrimRight(word, ",.;:")
						ids = append(ids, id)
					}
				}
			}
		}
	}

	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}

	return unique
}

// submitVerification submits a verification request to the backend.
func (w *Worker) submitVerification(ctx context.Context, repositoryURL, ref, deploymentName string) (string, error) {
	reqBody := VerifyDeploymentsRequest{
		RepositoryURL:  repositoryURL,
		Ref:            ref,
		DeploymentName: deploymentName,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/rofl/verify_deployments", w.cfg.BackendURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication if available
	if w.authClient != nil {
		token, err := w.authClient.GetToken(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get auth token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result VerifyDeploymentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.TaskID, nil
}

// pollResults polls for verification results until completion or timeout.
func (w *Worker) pollResults(ctx context.Context, taskID string) (*VerifyDeploymentsResult, error) {
	pollInterval := time.Duration(w.cfg.PollInterval) * time.Second
	timeout := time.Duration(w.cfg.PollTimeout) * time.Minute
	deadline := time.Now().Add(timeout)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("polling timeout after %v", timeout)
			}

			result, status, err := w.checkResults(ctx, taskID)
			if err != nil {
				return nil, fmt.Errorf("failed to check results: %w", err)
			}

			switch status {
			case http.StatusOK:
				// Task completed
				return result, nil
			case http.StatusAccepted:
				// Task still in progress, continue polling
				w.logger.Debug("task still in progress", "task_id", taskID)
				continue
			case http.StatusNotFound:
				return nil, fmt.Errorf("task not found or expired")
			default:
				return nil, fmt.Errorf("unexpected status code: %d", status)
			}
		}
	}
}

// checkResults makes a single request to check task results.
func (w *Worker) checkResults(ctx context.Context, taskID string) (*VerifyDeploymentsResult, int, error) {
	url := fmt.Sprintf("%s/rofl/verify_deployments/%s/results", w.cfg.BackendURL, taskID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication if available
	if w.authClient != nil {
		token, err := w.authClient.GetToken(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get auth token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}

	var result VerifyDeploymentsResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, resp.StatusCode, nil
}
