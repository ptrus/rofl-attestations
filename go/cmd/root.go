// Package cmd implements the CLI commands.
package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/ptrus/rofl-attestations/api"
	"github.com/ptrus/rofl-attestations/config"
	"github.com/ptrus/rofl-attestations/db"
	"github.com/ptrus/rofl-attestations/models"
	"github.com/ptrus/rofl-attestations/worker"
)

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use:   "rofl-registry",
		Short: "ROFL App Registry",
		Long:  `A registry and verification service for ROFL applications on Oasis Network.`,
		RunE:  run,
	}
	// httpClient is a shared HTTP client with timeout for safe external requests.
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "config file path")
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) error {
	// Setup logger.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Load configuration.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	logger.Info("loaded configuration", "listen_addr", cfg.Server.ListenAddr, "db_path", cfg.DB.Path)

	// Warn if debug mode is enabled
	if cfg.Debug {
		logger.Warn("⚠️  DEBUG MODE ENABLED - Using fake verification data for testing")
		logger.Warn("⚠️  DO NOT USE IN PRODUCTION - Debug data will mislead users")
	}

	// Initialize database.
	database, err := db.New(cfg.DB.Path)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	defer func() {
		_ = database.Close()
	}()

	if err := database.InitSchema(); err != nil {
		return fmt.Errorf("failed to initialize schema: %w", err)
	}

	logger.Info("database initialized")

	// Fetch apps registry from GitHub (or use local fallback).
	ctx := context.Background()
	apps, err := fetchAppsRegistry(ctx, logger, cfg.Apps.RegistryURL)
	if err != nil {
		logger.Warn("failed to fetch apps registry from GitHub, using local config fallback", "error", err)
		apps = cfg.Apps.GitHubRepos
	}

	// Seed apps from registry.
	for _, repo := range apps {
		// Upsert app - creates new or updates git_ref if URL already exists.
		if err := database.UpsertApp(ctx, repo.URL, repo.Ref); err != nil {
			logger.Error("failed to upsert app", "repo", repo.URL, "ref", repo.Ref, "error", err)
			continue
		}

		// Get the app to fetch rofl.yaml and potentially set debug data.
		app, err := database.GetAppByURL(ctx, repo.URL)
		if err != nil {
			logger.Error("failed to get app after upsert", "repo", repo.URL, "error", err)
			continue
		}

		logger.Info("app synced from config", "app_id", app.ID, "github_url", repo.URL, "ref", repo.Ref)

		// Fetch rofl.yaml from GitHub.
		if err := fetchRoflYAML(ctx, logger, database, app); err != nil {
			logger.Error("failed to fetch rofl.yaml", "app_id", app.ID, "github_url", repo.URL, "error", err)
		}

		// In debug mode, set first app as verified for testing.
		if cfg.Debug && app.ID == 1 {
			if err := setDebugVerification(ctx, logger, database, app); err != nil {
				logger.Error("failed to set debug verification", "app_id", app.ID, "error", err)
			}
		}
	}

	// Create API server.
	server, err := api.New(cfg, database, logger)
	if err != nil {
		return fmt.Errorf("failed to create API server: %w", err)
	}

	// Create verification worker.
	verificationWorker, err := worker.New(&cfg.Worker, database, logger)
	if err != nil {
		return fmt.Errorf("failed to create worker: %w", err)
	}

	// Setup signal handling.
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Use errgroup to manage server and worker goroutines.
	g, gCtx := errgroup.WithContext(sigCtx)

	// Start API server.
	g.Go(func() error {
		logger.Info("starting server")
		if err := server.Run(gCtx); err != nil {
			return fmt.Errorf("server error: %w", err)
		}
		return nil
	})

	// Start verification worker.
	g.Go(func() error {
		if err := verificationWorker.Start(gCtx); err != nil && err != context.Canceled {
			return fmt.Errorf("worker error: %w", err)
		}
		return nil
	})

	// Wait for all goroutines to complete or error.
	if err := g.Wait(); err != nil {
		logger.Error("service error", "error", err)
		return err
	}

	logger.Info("server stopped gracefully")
	return nil
}

// appsRegistryYAML represents the structure of apps.yaml.
type appsRegistryYAML struct {
	Apps []config.GitHubRepo `yaml:"apps"`
}

// fetchAppsRegistry fetches the apps registry from the configured URL.
func fetchAppsRegistry(ctx context.Context, logger *slog.Logger, registryURL string) ([]config.GitHubRepo, error) {
	logger.Info("fetching apps registry", "url", registryURL)

	// Create request with timeout context.
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, registryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Fetch apps.yaml.
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Limit response size to 1MB.
	const maxRegistrySize = 1 * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxRegistrySize)

	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}

	// Check if we hit the size limit.
	if int64(len(data)) >= maxRegistrySize {
		return nil, fmt.Errorf("apps.yaml exceeds maximum size of %d bytes", maxRegistrySize)
	}

	// Parse YAML.
	var registry appsRegistryYAML
	if err := yaml.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	logger.Info("successfully fetched apps registry", "count", len(registry.Apps))
	return registry.Apps, nil
}

// fetchRoflYAML fetches the rofl.yaml file from GitHub and updates the database.
func fetchRoflYAML(ctx context.Context, logger *slog.Logger, database *db.DB, app *models.App) error {
	// Construct raw GitHub URL for rofl.yaml.
	// https://github.com/oasisprotocol/wt3 -> https://raw.githubusercontent.com/oasisprotocol/wt3/master/rofl.yaml
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com%s/%s/rofl.yaml",
		app.GitHubURL[len("https://github.com"):],
		app.GitRef)

	logger.Info("fetching rofl.yaml", "github_url", app.GitHubURL, "ref", app.GitRef, "url", rawURL)

	// Create request with timeout context.
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Fetch rofl.yaml.
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Limit response size to 10MB to prevent memory exhaustion.
	const maxRoflYAMLSize = 10 * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxRoflYAMLSize)

	roflYAML, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read: %w", err)
	}

	// Check if we hit the size limit.
	if int64(len(roflYAML)) >= maxRoflYAMLSize {
		return fmt.Errorf("rofl.yaml exceeds maximum size of %d bytes", maxRoflYAMLSize)
	}

	// Update database with rofl.yaml content.
	err = database.UpdateAppRoflYAML(ctx, app.ID, string(roflYAML))
	if err != nil {
		return fmt.Errorf("failed to update db: %w", err)
	}

	logger.Info("successfully fetched rofl.yaml", "github_url", app.GitHubURL, "size", len(roflYAML))
	return nil
}

// setDebugVerification sets mock verification data for testing.
func setDebugVerification(ctx context.Context, logger *slog.Logger, database *db.DB, app *models.App) error {
	logger.Warn("⚠️  INSERTING FAKE DEBUG VERIFICATION DATA", "app_id", app.ID)

	// Use an obviously fake commit SHA for testing.
	commitSHA := "DEBUG0000000000FAKE"
	status := "verified"
	msg := "⚠️ DEBUG MODE: This is FAKE verification data for testing purposes only.\n\n" +
		"Built enclave identities MATCH on-chain measurements. Verification successful.\n\n" +
		"⚠️ WARNING: This verification was NOT performed by the backend and should not be trusted."

	// Create a debug verification for "mainnet" deployment
	err := database.UpsertDeployment(ctx, app.ID, "mainnet", commitSHA, status, msg)
	if err != nil {
		return fmt.Errorf("failed to update verification: %w", err)
	}

	logger.Warn("⚠️  FAKE DEBUG VERIFICATION INSERTED", "app_id", app.ID, "status", status, "deployment", "mainnet", "fake_commit", commitSHA)
	return nil
}
