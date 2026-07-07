package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/adapters/sla"
	er "github.com/sufield/stave/internal/app/execreport"
)

// ReportInput carries the inputs for [BuildReport]. ControlsDir/ChainsDir
// default to "controls"/"chains" at the CLI; SLAFile and TeamManifest are
// optional. Format is "json" (default) or "markdown".
type ReportInput struct {
	HistoryDir   string
	SnapshotPath string
	ControlsDir  string
	ChainsDir    string
	SLAFile      string
	TeamManifest string
	Title        string
	Period       string
	Format       string
}

// BuildReport aggregates every assessment dimension — posture score,
// findings summary, SLA compliance, top findings, active chains, ATT&CK
// coverage, framework readiness, team attribution, executive summary —
// into one report document and renders it as JSON or Markdown. now stamps
// the report. A build failure wraps [ErrInvalidInput] (exit 2); an
// unsupported format stays plain (exit 4). It is the library entry point
// behind `stave report`.
func BuildReport(ctx context.Context, in ReportInput, now time.Time) ([]byte, error) {
	builder := &er.Builder{
		Deps: er.BuilderDeps{
			ArtifactLoader:       artifact.NewLoader(),
			ChainLoader:          ctlyaml.NewChainProvider(),
			SLAProvider:          sla.NewProvider(),
			SnapshotBundleLoader: observations.NewBundleLoader(),
			ControlRepo:          ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(builtinpredicate.ResolverFunc())),
		},
	}

	report, err := builder.Build(ctx, er.BuilderInput{
		HistoryDir:       in.HistoryDir,
		SnapshotPath:     in.SnapshotPath,
		ControlsDir:      in.ControlsDir,
		ChainsDir:        in.ChainsDir,
		SLAFile:          in.SLAFile,
		TeamManifestPath: in.TeamManifest,
		Title:            in.Title,
		Period:           in.Period,
		EvalTime:         now,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", err, ErrInvalidInput)
	}

	return renderReport(report, in.Format)
}

// renderReport renders an executive report as JSON or Markdown. Split out
// so the rendering can be unit-tested without running the build pipeline.
func renderReport(report *er.Report, format string) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "json", "":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return nil, fmt.Errorf("encode report: %w", err)
		}
	case "markdown":
		if err := er.WriteMarkdown(&buf, report); err != nil {
			return nil, fmt.Errorf("write markdown report: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format %q (expected: json | markdown)", format)
	}
	return buf.Bytes(), nil
}
