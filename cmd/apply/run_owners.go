package apply

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// annotateOwners resolves team ownership for each finding when a team
// manifest is configured. When --owner-filter is also set, findings
// not owned by an allowed team are removed from the report.
//
// A failed manifest load with no --owner-filter logs a warning and
// returns nil — the manifest is optional decoration in that mode.
// A failed load with --owner-filter set returns an error: silently
// ignoring the filter would emit a report that contradicts the
// caller's explicit filter request.
func annotateOwners(result *evaluation.ComplianceReport, opts *Options) error {
	manifestPath := resolveTeamManifest(opts.TeamManifest)
	if manifestPath == "" {
		if len(opts.OwnerFilter) > 0 {
			return errors.New("--owner-filter requires a team manifest (set --team-manifest or place stave-teams.yaml in cwd)")
		}
		return nil
	}

	manifest, err := teams.LoadManifest(manifestPath)
	if err != nil {
		if len(opts.OwnerFilter) > 0 {
			return fmt.Errorf("load team manifest %q: %w", manifestPath, err)
		}
		slog.Warn("skipping owner annotation", "manifest", manifestPath, "error", err)
		return nil
	}

	// Annotate each finding with resolved owner.
	for i := range result.Findings {
		f := &result.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		f.OwnerTeamID = kernel.TeamID(owner.TeamID)
		f.OwnerTeamName = owner.TeamName
		f.OwnerContact = owner.Contact
		f.OwnerResolution = owner.ResolutionPath
	}

	// Filter by --owner-filter if set.
	if len(opts.OwnerFilter) == 0 {
		return nil
	}

	allowed := make(map[string]bool, len(opts.OwnerFilter))
	for _, id := range opts.OwnerFilter {
		allowed[strings.TrimSpace(id)] = true
	}

	// Non-aliased filter: a fresh backing array (with a capacity
	// hint to avoid reallocation) so the filter doesn't share
	// storage with the input. The previous `[:0]` shape worked
	// when no other reference to result.Findings outlived the
	// filter, but a future caller that captured the slice header
	// before owner filtering would see partially-overwritten
	// elements past the filtered length.
	filtered := make([]evaluation.Finding, 0, len(result.Findings))
	for i := range result.Findings {
		if result.Findings[i].MatchesOwner(allowed) {
			filtered = append(filtered, result.Findings[i])
		}
	}
	result.Findings = filtered
	return nil
}

// resolveTeamManifest returns the team manifest path from the flag,
// or looks for stave-teams.yaml in cwd. Returns "" if no manifest found.
func resolveTeamManifest(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	defaultPath := "stave-teams.yaml"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}
