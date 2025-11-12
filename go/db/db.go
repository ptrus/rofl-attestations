// Package db provides database operations for the ROFL registry.
package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3" // SQLite driver.
)

// DB wraps the database connection.
type DB struct {
	*sql.DB
}

// New creates a new database connection.
func New(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Set busy timeout to avoid "database is locked" errors
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		return nil, fmt.Errorf("failed to set busy timeout: %w", err)
	}

	// Configure connection pool for concurrent access
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	return &DB{db}, nil
}

// InitSchema creates the database tables if they don't exist.
func (db *DB) InitSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS apps (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		github_url TEXT NOT NULL UNIQUE,
		git_ref TEXT NOT NULL,
		rofl_yaml TEXT,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_apps_github_url ON apps(github_url);

	CREATE TABLE IF NOT EXISTS deployments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_id INTEGER NOT NULL,
		deployment_name TEXT NOT NULL,
		commit_sha TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		verification_msg TEXT,
		last_verified DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE,
		UNIQUE(app_id, deployment_name)
	);

	CREATE INDEX IF NOT EXISTS idx_deployments_app_id ON deployments(app_id);
	CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status);

	CREATE TABLE IF NOT EXISTS verification_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		app_id INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		job_id TEXT,
		result TEXT,
		started_at DATETIME,
		completed_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_jobs_app_id ON verification_jobs(app_id);
	CREATE INDEX IF NOT EXISTS idx_jobs_status ON verification_jobs(status);
	CREATE INDEX IF NOT EXISTS idx_jobs_job_id ON verification_jobs(job_id);
	`

	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}
