// Package teams provides owner-aware finding routing and team scoping.
package teams

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"gopkg.in/yaml.v3"
)

// Manifest is the on-disk format for stave-teams.yaml.
type Manifest struct {
	SchemaVersion  string           `yaml:"schema_version"`
	OwnerTagKey    string           `yaml:"owner_tag_key"`
	FallbackTagKey string           `yaml:"fallback_tag_key"`
	Teams          []Team           `yaml:"teams"`
	Hierarchy      []HierarchyGroup `yaml:"hierarchy,omitempty"`
}

// HierarchyGroup defines a named group of teams for rollup reporting.
type HierarchyGroup struct {
	Name  string   `yaml:"name"  json:"name"`
	ID    string   `yaml:"id"    json:"id"`
	Teams []string `yaml:"teams" json:"teams"`
}

// HierarchyByID returns the hierarchy group with the given ID, or nil.
func (m *Manifest) HierarchyByID(id string) *HierarchyGroup {
	for i := range m.Hierarchy {
		if m.Hierarchy[i].ID == id {
			return &m.Hierarchy[i]
		}
	}
	return nil
}

// Team defines a team identity and its resource ownership.
type Team struct {
	ID               string             `yaml:"id"              json:"id"`
	DisplayName      string             `yaml:"display_name"    json:"display_name"`
	Contact          string             `yaml:"contact"         json:"contact,omitempty"`
	ResourcePatterns []string           `yaml:"resource_patterns" json:"resource_patterns,omitempty"`
	ControlOwnership []kernel.ControlID `yaml:"control_ownership" json:"control_ownership,omitempty"`
	IsDefault        bool               `yaml:"is_default"      json:"is_default,omitempty"`
	Routing          Routing            `yaml:"routing"         json:"routing"`
}

// Routing holds alert destination configuration.
type Routing struct {
	SlackChannel string `yaml:"slack_channel" json:"slack_channel,omitempty"`
	JiraProject  string `yaml:"jira_project"  json:"jira_project,omitempty"`
	PagerdutyKey string `yaml:"pagerduty_key" json:"pagerduty_key,omitempty"`
}

// OwnerResult records the resolved owner and how it was determined.
type OwnerResult struct {
	TeamID         string `json:"team_id"`
	TeamName       string `json:"team_name"`
	Contact        string `json:"contact,omitempty"`
	ResolutionPath string `json:"resolution_path"`
}

// LoadManifest reads a team manifest from disk.
func LoadManifest(path string) (*Manifest, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read team manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse team manifest: %w", err)
	}
	if m.OwnerTagKey == "" {
		m.OwnerTagKey = "team"
	}
	if m.FallbackTagKey == "" {
		m.FallbackTagKey = "owner"
	}
	return &m, nil
}

// ResolveOwner determines which team owns a finding based on the
// resolution hierarchy: tag → fallback tag → ARN pattern →
// control ownership → default → unassigned.
func (m *Manifest) ResolveOwner(tags map[string]string, resourceARN, controlID string) OwnerResult {
	// 1. Primary tag match.
	if tagVal, ok := tags[m.OwnerTagKey]; ok {
		for i := range m.Teams {
			if m.Teams[i].ID == tagVal {
				return OwnerResult{
					TeamID: m.Teams[i].ID, TeamName: m.Teams[i].DisplayName,
					Contact: m.Teams[i].Contact, ResolutionPath: "tag",
				}
			}
		}
	}

	// 2. Fallback tag match.
	if tagVal, ok := tags[m.FallbackTagKey]; ok {
		for i := range m.Teams {
			if m.Teams[i].ID == tagVal {
				return OwnerResult{
					TeamID: m.Teams[i].ID, TeamName: m.Teams[i].DisplayName,
					Contact: m.Teams[i].Contact, ResolutionPath: "fallback_tag",
				}
			}
		}
	}

	// 3. ARN pattern match.
	for i := range m.Teams {
		for _, pattern := range m.Teams[i].ResourcePatterns {
			if globMatch(pattern, resourceARN) {
				return OwnerResult{
					TeamID: m.Teams[i].ID, TeamName: m.Teams[i].DisplayName,
					Contact: m.Teams[i].Contact, ResolutionPath: "arn_pattern",
				}
			}
		}
	}

	// 4. Control ID ownership match.
	for i := range m.Teams {
		for _, pattern := range m.Teams[i].ControlOwnership {
			if globMatch(string(pattern), controlID) {
				return OwnerResult{
					TeamID: m.Teams[i].ID, TeamName: m.Teams[i].DisplayName,
					Contact: m.Teams[i].Contact, ResolutionPath: "control_ownership",
				}
			}
		}
	}

	// 5. Default team.
	for i := range m.Teams {
		if m.Teams[i].IsDefault {
			return OwnerResult{
				TeamID: m.Teams[i].ID, TeamName: m.Teams[i].DisplayName,
				Contact: m.Teams[i].Contact, ResolutionPath: "default",
			}
		}
	}

	// 6. Unassigned.
	return OwnerResult{
		TeamID: "unassigned", TeamName: "Unassigned",
		ResolutionPath: "unassigned",
	}
}

// TeamByID returns the team definition for an ID, or nil.
func (m *Manifest) TeamByID(id string) *Team {
	for i := range m.Teams {
		if m.Teams[i].ID == id {
			return &m.Teams[i]
		}
	}
	return nil
}

// AnnotateFindings resolves owner for each finding and sets the owner fields.
// tags is a function that returns resource tags for a given asset ID.
// If tags is nil, tag-based resolution is skipped (ARN/control patterns still work).
func (m *Manifest) AnnotateFindings(findings []FindingRef, tags func(assetID string) map[string]string) {
	for i := range findings {
		f := &findings[i]
		var t map[string]string
		if tags != nil {
			t = tags(f.AssetID)
		}
		result := m.ResolveOwner(t, f.AssetID, f.ControlID)
		f.OwnerTeamID = result.TeamID
		f.OwnerTeamName = result.TeamName
		f.OwnerContact = result.Contact
		f.OwnerResolution = result.ResolutionPath
	}
}

// FindingRef is the minimal interface for owner annotation.
// Callers build a slice of these referencing their actual finding structs.
type FindingRef struct {
	AssetID         string
	ControlID       string
	OwnerTeamID     string
	OwnerTeamName   string
	OwnerContact    string
	OwnerResolution string
}

// globMatch checks if a value matches a simple glob pattern (supports * suffix).
func globMatch(pattern, value string) bool {
	if pattern == value {
		return true
	}
	if before, ok := strings.CutSuffix(pattern, "*"); ok {
		if !strings.ContainsAny(before, "*?[") {
			return strings.HasPrefix(value, before)
		}
	}
	// filepath.Match for more complex patterns. A bad pattern
	// (filepath.ErrBadPattern) returns false here so the resolver
	// falls through to the next rule rather than crashing the
	// owner-resolution path; the gap is logged so a malformed
	// glob in a team manifest surfaces during triage rather than
	// silently producing "no owner" verdicts. Manifest authoring
	// is the right place to validate patterns up-front; this is
	// the runtime safety net.
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		slog.Warn("teams: bad glob pattern in rule, treating as no-match",
			"pattern", pattern, "value", value, "error", err)
		return false
	}
	return matched
}
