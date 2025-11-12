package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ptrus/rofl-attestations/models"
)

// CreateApp creates a new app in the database.
func (db *DB) CreateApp(ctx context.Context, githubURL, gitRef string) (*models.App, error) {
	query := `
		INSERT INTO apps (github_url, git_ref)
		VALUES (?, ?)
		RETURNING id, github_url, git_ref, rofl_yaml, created_at, updated_at
	`

	app := &models.App{}
	err := db.QueryRowContext(ctx, query, githubURL, gitRef).Scan(
		&app.ID,
		&app.GitHubURL,
		&app.GitRef,
		&app.RoflYAML,
		&app.CreatedAt,
		&app.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create app: %w", err)
	}

	return app, nil
}

// UpsertApp creates a new app or updates git_ref if the app already exists.
func (db *DB) UpsertApp(ctx context.Context, githubURL, gitRef string) error {
	now := time.Now()
	query := `
		INSERT INTO apps (github_url, git_ref, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(github_url) DO UPDATE SET
			git_ref = excluded.git_ref,
			updated_at = excluded.updated_at
	`

	_, err := db.ExecContext(ctx, query, githubURL, gitRef, now)
	if err != nil {
		return fmt.Errorf("failed to upsert app: %w", err)
	}

	return nil
}

// GetAppByID retrieves an app by ID.
func (db *DB) GetAppByID(ctx context.Context, id int64) (*models.App, error) {
	query := `
		SELECT id, github_url, git_ref, rofl_yaml, created_at, updated_at
		FROM apps
		WHERE id = ?
	`

	app := &models.App{}
	err := db.QueryRowContext(ctx, query, id).Scan(
		&app.ID,
		&app.GitHubURL,
		&app.GitRef,
		&app.RoflYAML,
		&app.CreatedAt,
		&app.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("app not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	return app, nil
}

// GetAppByURL retrieves an app by GitHub URL.
func (db *DB) GetAppByURL(ctx context.Context, githubURL string) (*models.App, error) {
	query := `
		SELECT id, github_url, git_ref, rofl_yaml, created_at, updated_at
		FROM apps
		WHERE github_url = ?
	`

	app := &models.App{}
	err := db.QueryRowContext(ctx, query, githubURL).Scan(
		&app.ID,
		&app.GitHubURL,
		&app.GitRef,
		&app.RoflYAML,
		&app.CreatedAt,
		&app.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("app not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	return app, nil
}

// GetAllApps retrieves all apps.
func (db *DB) GetAllApps(ctx context.Context) ([]*models.App, error) {
	query := `
		SELECT id, github_url, git_ref, rofl_yaml, created_at, updated_at
		FROM apps
		ORDER BY id ASC
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query apps: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var apps []*models.App
	for rows.Next() {
		app := &models.App{}
		err := rows.Scan(
			&app.ID,
			&app.GitHubURL,
			&app.GitRef,
			&app.RoflYAML,
			&app.CreatedAt,
			&app.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan app: %w", err)
		}
		apps = append(apps, app)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return apps, nil
}

// UpsertDeployment creates or updates a deployment record.
func (db *DB) UpsertDeployment(ctx context.Context, appID int64, deploymentName, commitSHA, status, verificationMsg string) error {
	now := time.Now()
	query := `
		INSERT INTO deployments (app_id, deployment_name, commit_sha, status, verification_msg, last_verified)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(app_id, deployment_name) DO UPDATE SET
			commit_sha = excluded.commit_sha,
			status = excluded.status,
			verification_msg = excluded.verification_msg,
			last_verified = excluded.last_verified,
			updated_at = ?
	`

	_, err := db.ExecContext(ctx, query, appID, deploymentName, commitSHA, status, verificationMsg, now, now)
	if err != nil {
		return fmt.Errorf("failed to upsert deployment: %w", err)
	}

	return nil
}

// GetDeploymentsByAppID retrieves all deployments for an app.
func (db *DB) GetDeploymentsByAppID(ctx context.Context, appID int64) ([]*models.Deployment, error) {
	query := `
		SELECT id, app_id, deployment_name, commit_sha, status, verification_msg, last_verified, created_at, updated_at
		FROM deployments
		WHERE app_id = ?
		ORDER BY deployment_name ASC
	`

	rows, err := db.QueryContext(ctx, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to query deployments: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var deployments []*models.Deployment
	for rows.Next() {
		deployment := &models.Deployment{}
		err := rows.Scan(
			&deployment.ID,
			&deployment.AppID,
			&deployment.DeploymentName,
			&deployment.CommitSHA,
			&deployment.Status,
			&deployment.VerificationMsg,
			&deployment.LastVerified,
			&deployment.CreatedAt,
			&deployment.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan deployment: %w", err)
		}
		deployments = append(deployments, deployment)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return deployments, nil
}

// UpdateAppRoflYAML updates the rofl.yaml content of an app.
func (db *DB) UpdateAppRoflYAML(ctx context.Context, id int64, roflYAML string) error {
	query := `
		UPDATE apps
		SET rofl_yaml = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := db.ExecContext(ctx, query, roflYAML, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update rofl.yaml: %w", err)
	}

	return nil
}
