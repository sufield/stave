// Package compliance reads compliance framework YAML checklists
// into normalized structs. Pure data transformation — no domain
// types, no control catalog awareness.
package compliance

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Framework holds a parsed compliance framework.
type Framework struct {
	Name    string  `yaml:"name"`
	Version string  `yaml:"version"`
	Source  string  `yaml:"source"`
	Checks  []Check `yaml:"checks"`

	// Legacy field — older checklists use "standard" instead of "name".
	Standard string `yaml:"standard"`
}

// DisplayName returns the framework name, falling back to Standard.
func (f *Framework) DisplayName() string {
	if f.Name != "" {
		return f.Name
	}
	return f.Standard
}

// Check is one requirement from a compliance framework.
type Check struct {
	ID          string `yaml:"id"`
	Service     string `yaml:"service"`
	Property    string `yaml:"property"`
	Description string `yaml:"description"`
	Reference   string `yaml:"reference"`
	Scope       string `yaml:"scope"`
}

// NormalizedService returns the service name lowercased with
// hyphens removed, matching Stave's scope tag convention.
func (c Check) NormalizedService() string {
	return strings.ReplaceAll(strings.ToLower(c.Service), "-", "")
}

// IsInScope reports whether the check is configuration-verifiable.
func (c Check) IsInScope() bool {
	switch c.Scope {
	case "runtime", "process", "ai-model", "physical":
		return false
	default:
		return true
	}
}

// ParseFramework reads a YAML checklist file.
func ParseFramework(path string) (*Framework, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-controlled path
	if err != nil {
		return nil, fmt.Errorf("read framework: %w", err)
	}
	var fw Framework
	if err := yaml.Unmarshal(data, &fw); err != nil {
		return nil, fmt.Errorf("parse framework: %w", err)
	}
	if fw.DisplayName() == "" {
		return nil, errors.New("framework has no name or standard field")
	}
	if len(fw.Checks) == 0 {
		return nil, errors.New("framework has no checks")
	}
	return &fw, nil
}
