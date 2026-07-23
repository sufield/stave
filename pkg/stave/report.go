package stave

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"strconv"
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
// optional. Format is "json" (default), "markdown", or "html".
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
	case "html":
		var md bytes.Buffer
		if err := er.WriteMarkdown(&md, report); err != nil {
			return nil, fmt.Errorf("write markdown for html: %w", err)
		}
		writeHTMLReport(&buf, report.Title, md.Bytes())
	case "csv":
		if err := writeCSVReport(&buf, report); err != nil {
			return nil, fmt.Errorf("write csv report: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported format %q (expected: json | markdown | html)", format)
	}
	return buf.Bytes(), nil
}

func writeCSVReport(buf *bytes.Buffer, report *er.Report) error {
	w := csv.NewWriter(buf)
	defer w.Flush()
	if err := w.Write([]string{"rank", "control_id", "severity", "asset_id", "dwell_hours", "remediation"}); err != nil {
		return err
	}
	for i := range report.TopFindings {
		f := &report.TopFindings[i]
		if err := w.Write([]string{
			strconv.Itoa(f.Rank),
			f.ControlID,
			f.Severity,
			f.AssetID,
			fmt.Sprintf("%.1f", f.DwellHours),
			f.RemediationAction,
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

func writeHTMLReport(buf *bytes.Buffer, title string, markdown []byte) {
	buf.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	buf.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	buf.WriteString(`<title>`)
	buf.WriteString(html.EscapeString(title))
	buf.WriteString(`</title><style>
body{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#1a1a1a;background:#fff}
pre{background:#f5f5f5;padding:1rem;overflow-x:auto;border-radius:4px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.5rem;text-align:left}
th{background:#f0f0f0}tr:nth-child(even){background:#fafafa}
@media(prefers-color-scheme:dark){body{color:#e0e0e0;background:#1a1a1a}pre{background:#2a2a2a}th{background:#333}td{border-color:#444}tr:nth-child(even){background:#222}}
</style></head><body><pre>`)
	buf.Write([]byte(html.EscapeString(string(markdown))))
	buf.WriteString(`</pre></body></html>`)
}
