// Package config provides configuration management for the ROFL registry.
package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config holds the application configuration.
type Config struct {
	Server ServerConfig `koanf:"server"`
	DB     DBConfig     `koanf:"db"`
	Apps   AppsConfig   `koanf:"apps"`
	Worker WorkerConfig `koanf:"worker"`
	Debug  bool         `koanf:"debug"` // Enable debug mode with mock data.
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	ListenAddr     string   `koanf:"listen_addr"`
	AllowedOrigins []string `koanf:"allowed_origins"` // CORS allowed origins (empty = same-origin only)
}

// DBConfig holds database configuration.
type DBConfig struct {
	Path string `koanf:"path"`
}

// GitHubRepo represents a GitHub repository with branch/tag/ref.
type GitHubRepo struct {
	URL string `koanf:"url"`
	Ref string `koanf:"ref"` // Branch, tag, or commit ref to verify.
}

// AppsConfig holds apps configuration.
type AppsConfig struct {
	RegistryURL string       `koanf:"registry_url"` // URL to fetch apps.yaml from (default: GitHub master)
	GitHubRepos []GitHubRepo `koanf:"github_repos"` // Fallback: local apps list (optional)
}

// WorkerConfig holds periodic verification worker configuration.
type WorkerConfig struct {
	Enabled      bool   `koanf:"enabled"`       // Enable periodic verification worker.
	BackendURL   string `koanf:"backend_url"`   // URL of rofl-app-backend service.
	AppInterval  int    `koanf:"app_interval"`  // Delay between apps in minutes (default: 1).
	PollInterval int    `koanf:"poll_interval"` // Poll interval in seconds (default: 5).
	PollTimeout  int    `koanf:"poll_timeout"`  // Poll timeout in minutes (default: 5).
	PrivateKey   string `koanf:"private_key"`   // Private key for SIWE authentication (hex string without 0x prefix).
	SIWEDomain   string `koanf:"siwe_domain"`   // Domain for SIWE messages (default: localhost).
	ChainID      int    `koanf:"chain_id"`      // Chain ID for SIWE (default: 0x5aff for testnet).
}

// Load loads configuration from file and environment variables.
func Load(configPath string) (*Config, error) {
	k := koanf.New(".")

	// Load from config file if provided
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// Load from environment variables (with ROFL_REGISTRY_ prefix)
	if err := k.Load(env.Provider("ROFL_REGISTRY_", "__", func(s string) string {
		return strings.ToLower(s)
	}), nil); err != nil {
		return nil, fmt.Errorf("failed to load env vars: %w", err)
	}

	cfg := &Config{}
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set defaults
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.DB.Path == "" {
		cfg.DB.Path = "rofl-registry.db"
	}
	if cfg.Apps.RegistryURL == "" {
		cfg.Apps.RegistryURL = "https://raw.githubusercontent.com/ptrus/rofl-attestations/master/apps.yaml"
	}
	if cfg.Worker.AppInterval == 0 {
		cfg.Worker.AppInterval = 1 // 1 minute between apps
	}
	if cfg.Worker.PollInterval == 0 {
		cfg.Worker.PollInterval = 5 // 5 seconds
	}
	if cfg.Worker.PollTimeout == 0 {
		cfg.Worker.PollTimeout = 5 // 5 minutes
	}
	if cfg.Worker.SIWEDomain == "" {
		cfg.Worker.SIWEDomain = "localhost"
	}
	if cfg.Worker.ChainID == 0 {
		cfg.Worker.ChainID = 0x5aff // Testnet
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate GitHub repository URLs (if provided as fallback)
	for i, repo := range c.Apps.GitHubRepos {
		if repo.URL == "" {
			return fmt.Errorf("apps.github_repos[%d]: URL cannot be empty", i)
		}
		if !strings.HasPrefix(repo.URL, "https://github.com/") {
			return fmt.Errorf("apps.github_repos[%d]: invalid GitHub URL %q (must start with https://github.com/)", i, repo.URL)
		}
		// Check URL has at least owner/repo format
		parts := strings.TrimPrefix(repo.URL, "https://github.com/")
		if parts == "" || !strings.Contains(parts, "/") {
			return fmt.Errorf("apps.github_repos[%d]: invalid GitHub URL %q (must be https://github.com/owner/repo)", i, repo.URL)
		}
		if repo.Ref == "" {
			return fmt.Errorf("apps.github_repos[%d]: ref cannot be empty", i)
		}
	}

	// Validate worker configuration if enabled
	if c.Worker.Enabled {
		if c.Worker.BackendURL == "" {
			return fmt.Errorf("worker.backend_url cannot be empty when worker is enabled")
		}
		if c.Worker.AppInterval <= 0 {
			return fmt.Errorf("worker.app_interval must be positive (got %d)", c.Worker.AppInterval)
		}
		if c.Worker.PollInterval <= 0 {
			return fmt.Errorf("worker.poll_interval must be positive (got %d)", c.Worker.PollInterval)
		}
		if c.Worker.PollTimeout <= 0 {
			return fmt.Errorf("worker.poll_timeout must be positive (got %d)", c.Worker.PollTimeout)
		}
	}

	return nil
}
