package apply

import (
	"log/slog"
	"os"
	"strings"

	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation"
)

// annotateOwners resolves team ownership for each finding when a team
// manifest is configured. When --owner-filter is also set, findings
// not owned by an allowed team are removed from the report.
func annotateOwners(result *evaluation.ComplianceReport, opts *Options) {
	manifestPath := resolveTeamManifest(opts.TeamManifest)
	if manifestPath == "" {
		return
	}

	manifest, err := teams.LoadManifest(manifestPath)
	if err != nil {
		slog.Debug("skipping owner annotation", "error", err)
		return
	}

	// Annotate each finding with resolved owner.
	for i := range result.Findings {
		f := &result.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		f.OwnerTeamID = owner.TeamID
		f.OwnerTeamName = owner.TeamName
		f.OwnerContact = owner.Contact
		f.OwnerResolution = owner.ResolutionPath
	}

	// Filter by --owner-filter if set.
	if opts.OwnerFilter == "" {
		return
	}

	allowed := make(map[string]bool)
	for id := range strings.SplitSeq(opts.OwnerFilter, ",") {
		allowed[strings.TrimSpace(id)] = true
	}

	filtered := result.Findings[:0]
	for i := range result.Findings {
		if allowed[result.Findings[i].OwnerTeamID] {
			filtered = append(filtered, result.Findings[i])
		}
	}
	result.Findings = filtered
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
