// Package formatter renders rank command results to text, JSON, and CSV.
//
// The package exists so cmd/rank stays thin (flag parse → format dispatch)
// while the rendering logic — which has nothing to do with the CLI shell —
// lives in the app layer where it can be unit-tested with bytes.Buffer
// instead of through a full Cobra invocation.
//
// All formatters take an io.Writer so the caller controls the
// destination: terminal, file, network buffer, test scratch buffer.
// The package never writes to a hard-coded stdout sink.
package formatter

import (
	"io"

	apprank "github.com/sufield/stave/internal/app/rank"
	"github.com/sufield/stave/internal/app/sprintplanner"
	"github.com/sufield/stave/internal/core/report"
)

// RoadmapFormatter renders a [Roadmap] alongside the assessment that
// produced it. The assessment provides per-finding context (severity,
// chain membership, SLA fields) the Roadmap entries don't carry.
type RoadmapFormatter interface {
	Render(w io.Writer, rm apprank.Roadmap, assessment *report.Assessment) error
}

// SprintFormatter renders a sprint plan derived from the rank command's
// --capacity / --effort-model inputs.
type SprintFormatter interface {
	Render(w io.Writer, r sprintplanner.SprintResult) error
}

// IdentityRankingFormatter renders an identity-centric blast radius ranking.
type IdentityRankingFormatter interface {
	Render(w io.Writer, ranking apprank.IdentityRanking) error
}
