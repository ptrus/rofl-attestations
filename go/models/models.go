// Package models defines the data models for the ROFL registry.
package models

import (
	"database/sql"
	"time"
)

// VerificationStatus represents the status of app verification.
type VerificationStatus string

// Verification status constants.
const (
	StatusPending  VerificationStatus = "pending"
	StatusVerified VerificationStatus = "verified"
	StatusFailed   VerificationStatus = "failed"
)

// App represents a ROFL application in the registry.
type App struct {
	ID        int64          `json:"id"`
	GitHubURL string         `json:"github_url"` // e.g., https://github.com/oasisprotocol/wt3
	GitRef    string         `json:"git_ref"`    // Branch, tag, or commit ref to verify.
	RoflYAML  sql.NullString `json:"rofl_yaml"`  // Raw rofl.yaml content.
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Deployment represents a single deployment of an app (e.g., mainnet, testnet).
type Deployment struct {
	ID              int64              `json:"id"`
	AppID           int64              `json:"app_id"`
	DeploymentName  string             `json:"deployment_name"`  // e.g., "mainnet", "testnet"
	CommitSHA       sql.NullString     `json:"commit_sha"`       // Git commit SHA that was verified.
	Status          VerificationStatus `json:"status"`           // "pending", "verified", "failed"
	VerificationMsg sql.NullString     `json:"verification_msg"` // "Built enclave identities MATCH..." or error message.
	LastVerified    sql.NullTime       `json:"last_verified"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}

// VerificationJob represents a build/verification job from the external service.
type VerificationJob struct {
	ID          int64        `json:"id"`
	AppID       int64        `json:"app_id"`
	Status      string       `json:"status"` // "pending", "running", "completed", "failed"
	JobID       string       `json:"job_id"` // External build service job ID
	Result      string       `json:"result"` // Verification result message when completed
	StartedAt   sql.NullTime `json:"started_at"`
	CompletedAt sql.NullTime `json:"completed_at"`
	CreatedAt   time.Time    `json:"created_at"`
}
