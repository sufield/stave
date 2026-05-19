package rank

import (
	"fmt"

	"github.com/sufield/stave/internal/app/rank/formatter"
)

// `stave rank` has four output surfaces: the default roadmap, the
// per-team breakdown (--group-by owner), the sprint plan (--sprint),
// and the identity-centric blast-radius ranking (--identity). Each
// renders a different payload and each had its own dispatch switch
// in cmd.go. The concrete renderers live in
// internal/app/rank/formatter/ (the package predates the Renderer
// migration); this file adds the format-string → concrete factories
// that the rest of the codebase now standardises on.

// NewRoadmapRenderer maps a format string to a RoadmapFormatter.
// `opts` is needed for the text renderer's ShowReach flag (derived
// from --sort blast-radius).
func NewRoadmapRenderer(format string, opts *options) (formatter.RoadmapFormatter, error) {
	switch format {
	case "json":
		return formatter.JSON{}, nil
	case "csv":
		return formatter.CSV{}, nil
	case "table", "":
		return &formatter.TextRoadmap{ShowReach: opts.SortsByBlastRadius()}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | csv)", format)
}

// NewTeamRoadmapsRenderer maps a format string to the grouped-by-
// owner renderer used when --group-by owner is set.
func NewTeamRoadmapsRenderer(format string) (formatter.TeamRoadmapsFormatter, error) {
	switch format {
	case "json":
		return formatter.JSONTeamRoadmaps{}, nil
	case "table", "":
		return formatter.TextTeamRoadmaps{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// NewSprintRenderer maps a format string to a SprintFormatter used
// when --sprint is set.
func NewSprintRenderer(format string) (formatter.SprintFormatter, error) {
	switch format {
	case "json":
		return formatter.JSONSprint{}, nil
	case "table", "":
		return formatter.TextSprint{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}

// NewIdentityRankingRenderer maps a format string to an
// IdentityRankingFormatter used when --identity is set.
func NewIdentityRankingRenderer(format string) (formatter.IdentityRankingFormatter, error) {
	switch format {
	case "json":
		return formatter.JSONIdentityRanking{}, nil
	case "table", "":
		return formatter.TextIdentityRanking{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json)", format)
}
