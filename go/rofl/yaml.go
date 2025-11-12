// Package rofl provides utilities for parsing and working with ROFL manifests.
package rofl

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// Manifest represents a rofl.yaml file.
// Additional fields in the YAML will be ignored, not cause errors.
// Missing fields will have zero values (empty string, nil map, etc).
type Manifest struct {
	Name        string                 `yaml:"name"`
	Version     string                 `yaml:"version"`
	Description string                 `yaml:"description"`
	Author      string                 `yaml:"author"`
	License     string                 `yaml:"license"`
	TEE         string                 `yaml:"tee"`
	Kind        string                 `yaml:"kind"`
	Repository  string                 `yaml:"repository"`
	Homepage    string                 `yaml:"homepage"`
	Resources   Resources              `yaml:"resources"`
	Artifacts   Artifacts              `yaml:"artifacts"`
	Deployments map[string]*Deployment `yaml:"deployments"`
	// Note: We only parse fields we actually use.
	// Additional fields in rofl.yaml will not cause parsing errors.
}

// Resources represents the resource requirements.
type Resources struct {
	Memory  int     `yaml:"memory"`
	CPUs    float64 `yaml:"cpus"`
	Storage Storage `yaml:"storage"`
}

// Storage represents storage configuration.
type Storage struct {
	Kind string `yaml:"kind"`
	Size int    `yaml:"size"`
}

// Artifacts represents runtime binaries and components.
type Artifacts struct {
	Builder   string            `yaml:"builder"`
	Firmware  string            `yaml:"firmware"`
	Kernel    string            `yaml:"kernel"`
	Stage2    string            `yaml:"stage2"`
	Container ContainerArtifact `yaml:"container"`
}

// ContainerArtifact represents container-specific artifacts.
type ContainerArtifact struct {
	Runtime string `yaml:"runtime"`
	Compose string `yaml:"compose"`
}

// Policy represents the deployment policy.
type Policy struct {
	Enclaves EnclaveList `yaml:"enclaves"`
}

// EnclaveList is a custom type that can unmarshal both string arrays and object arrays.
type EnclaveList []string

// UnmarshalYAML implements custom unmarshaling for EnclaveList to handle both formats:
// 1. Plain strings: ["id1", "id2"]
// 2. Objects with id field: [{id: "id1"}, {id: "id2"}]
func (e *EnclaveList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try to unmarshal as array of strings first.
	var stringList []string
	if err := unmarshal(&stringList); err == nil {
		*e = stringList
		return nil
	}

	// If that fails, try to unmarshal as array of objects with id field.
	var objList []struct {
		ID string `yaml:"id"`
	}
	if err := unmarshal(&objList); err != nil {
		return err
	}

	// Extract the IDs from the objects.
	result := make([]string, 0, len(objList))
	for _, obj := range objList {
		result = append(result, obj.ID)
	}
	*e = result
	return nil
}

// Deployment represents a network deployment configuration.
type Deployment struct {
	Network string `yaml:"network"`
	AppID   string `yaml:"app_id"` // ROFL app ID.
	Policy  Policy `yaml:"policy"`
	// Additional fields may be present but are not parsed.
}

// Parse parses a rofl.yaml from bytes.
func Parse(data []byte) (*Manifest, error) {
	var manifest Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse rofl.yaml: %w", err)
	}
	return &manifest, nil
}
