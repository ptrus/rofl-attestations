package rofl

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// Test parsing rofl.yaml with object-style enclave IDs (Talos format).
func TestParseManifest_ObjectEnclaves(t *testing.T) {
	yamlContent := `
name: Test App
version: 0.1.0
deployments:
  mainnet:
    network: mainnet
    app_id: rofl1test123
    policy:
      enclaves:
        - id: jypB1qfYh2YpoXQbDglIxMxHA2wqOWpH68cLAhp0CBkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
        - id: v6N3N67EmLtKgCGuLia6+aw/ZtgB2ZxcfHQxu3Bn+c0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
  testnet:
    network: testnet
    app_id: rofl1test456
    policy:
      enclaves:
        - id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`

	manifest, err := Parse([]byte(yamlContent))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if manifest.Name != "Test App" {
		t.Errorf("Expected name 'Test App', got '%s'", manifest.Name)
	}

	if manifest.Version != "0.1.0" {
		t.Errorf("Expected version '0.1.0', got '%s'", manifest.Version)
	}

	if len(manifest.Deployments) != 2 {
		t.Fatalf("Expected 2 deployments, got %d", len(manifest.Deployments))
	}

	mainnet := manifest.Deployments["mainnet"]
	if mainnet == nil {
		t.Fatal("mainnet deployment is nil")
	}

	if mainnet.AppID != "rofl1test123" {
		t.Errorf("Expected AppID 'rofl1test123', got '%s'", mainnet.AppID)
	}

	if len(mainnet.Policy.Enclaves) != 2 {
		t.Fatalf("Expected 2 enclaves, got %d", len(mainnet.Policy.Enclaves))
	}

	expectedEnclaves := []string{
		"jypB1qfYh2YpoXQbDglIxMxHA2wqOWpH68cLAhp0CBkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		"v6N3N67EmLtKgCGuLia6+aw/ZtgB2ZxcfHQxu3Bn+c0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
	}

	for i, expected := range expectedEnclaves {
		if mainnet.Policy.Enclaves[i] != expected {
			t.Errorf("Enclave %d: expected '%s', got '%s'", i, expected, mainnet.Policy.Enclaves[i])
		}
	}
}

// Test parsing rofl.yaml with string-style enclave IDs (WT3 format).
func TestParseManifest_StringEnclaves(t *testing.T) {
	yamlContent := `
name: WT3
version: 1.0.0
deployments:
  mainnet:
    network: mainnet
    app_id: rofl1qzp3c6zt96r5c5sw0sljlvepwgg4u23atgh4legq
    policy:
      enclaves:
        - XoGWlUr9yeXME/6nPHIlASaS0/q4LZ2vExFbUoWrF9sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
        - 69jynVbbjXkNgoalE83L47POjbOMJ0yOcd+LrUkxOiEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`

	manifest, err := Parse([]byte(yamlContent))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if manifest.Name != "WT3" {
		t.Errorf("Expected name 'WT3', got '%s'", manifest.Name)
	}

	mainnet := manifest.Deployments["mainnet"]
	if mainnet == nil {
		t.Fatal("mainnet deployment is nil")
	}

	if len(mainnet.Policy.Enclaves) != 2 {
		t.Fatalf("Expected 2 enclaves, got %d", len(mainnet.Policy.Enclaves))
	}

	expectedEnclaves := []string{
		"XoGWlUr9yeXME/6nPHIlASaS0/q4LZ2vExFbUoWrF9sAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
		"69jynVbbjXkNgoalE83L47POjbOMJ0yOcd+LrUkxOiEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
	}

	for i, expected := range expectedEnclaves {
		if mainnet.Policy.Enclaves[i] != expected {
			t.Errorf("Enclave %d: expected '%s', got '%s'", i, expected, mainnet.Policy.Enclaves[i])
		}
	}
}

// Test parsing rofl.yaml with all fields.
func TestParseManifest_AllFields(t *testing.T) {
	yamlContent := `
name: Full App
version: 2.0.0
description: A test application
author: Test Author
homepage: https://example.com
repository: https://github.com/test/test
license: Apache-2.0
tee: TDX
kind: compute
resources:
  memory: 2048
  cpus: 4
  storage:
    kind: persistent
    size: 10240
artifacts:
  builder: ghcr.io/oasisprotocol/rofl-builder:test
  firmware: tdx-qgs.fd
  kernel: bzImage
  stage2: stage2.img
  container:
    runtime: runtime.tar.gz
    compose: docker-compose.yaml
deployments:
  mainnet:
    network: mainnet
    app_id: rofl1test
    policy:
      enclaves:
        - id: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
`

	manifest, err := Parse([]byte(yamlContent))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if manifest.Name != "Full App" {
		t.Errorf("Expected name 'Full App', got '%s'", manifest.Name)
	}

	if manifest.Description != "A test application" {
		t.Errorf("Expected description 'A test application', got '%s'", manifest.Description)
	}

	if manifest.Author != "Test Author" {
		t.Errorf("Expected author 'Test Author', got '%s'", manifest.Author)
	}

	if manifest.Homepage != "https://example.com" {
		t.Errorf("Expected homepage 'https://example.com', got '%s'", manifest.Homepage)
	}

	if manifest.Resources.Memory != 2048 {
		t.Errorf("Expected memory 2048, got %d", manifest.Resources.Memory)
	}

	if manifest.Resources.CPUs != 4 {
		t.Errorf("Expected cpus 4, got %f", manifest.Resources.CPUs)
	}

	if manifest.Artifacts.Builder != "ghcr.io/oasisprotocol/rofl-builder:test" {
		t.Errorf("Expected builder 'ghcr.io/oasisprotocol/rofl-builder:test', got '%s'", manifest.Artifacts.Builder)
	}

	if manifest.Artifacts.Container.Runtime != "runtime.tar.gz" {
		t.Errorf("Expected container runtime 'runtime.tar.gz', got '%s'", manifest.Artifacts.Container.Runtime)
	}
}

// Test EnclaveList custom unmarshaling directly.
func TestEnclaveList_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		expected []string
	}{
		{
			name: "string array format",
			yaml: `
- ABC123
- DEF456
`,
			expected: []string{"ABC123", "DEF456"},
		},
		{
			name: "object array format",
			yaml: `
- id: ABC123
- id: DEF456
`,
			expected: []string{"ABC123", "DEF456"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var list EnclaveList
			if err := yaml.Unmarshal([]byte(tt.yaml), &list); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if len(list) != len(tt.expected) {
				t.Fatalf("Expected %d enclaves, got %d", len(tt.expected), len(list))
			}

			for i, expected := range tt.expected {
				if list[i] != expected {
					t.Errorf("Enclave %d: expected '%s', got '%s'", i, expected, list[i])
				}
			}
		})
	}
}

// Test parsing with missing optional fields.
func TestParseManifest_MinimalFields(t *testing.T) {
	yamlContent := `
name: Minimal App
version: 1.0.0
deployments:
  mainnet:
    network: mainnet
    app_id: rofl1minimal
    policy:
      enclaves:
        - AAAA
`

	manifest, err := Parse([]byte(yamlContent))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if manifest.Name != "Minimal App" {
		t.Errorf("Expected name 'Minimal App', got '%s'", manifest.Name)
	}

	// Optional fields should be empty.
	if manifest.Description != "" {
		t.Errorf("Expected empty description, got '%s'", manifest.Description)
	}

	if manifest.Author != "" {
		t.Errorf("Expected empty author, got '%s'", manifest.Author)
	}
}
