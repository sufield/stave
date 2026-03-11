package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

type reportTemplateMetadata struct {
	reportRun
	ContextName   string `json:"context_name,omitempty"`
	GitRepoRoot   string `json:"git_repo_root,omitempty"`
	GitHeadCommit string `json:"git_head_commit,omitempty"`
	GitDirty      bool   `json:"git_dirty"`
	GitPathsDirty string `json:"git_paths_dirty,omitempty"`
}

type reportSeverityGroup struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type reportTemplateData struct {
	Metadata       reportTemplateMetadata    `json:"metadata"`
	Summary        reportSummary             `json:"summary"`
	Findings       []reportFinding           `json:"findings"`
	SeverityGroups []reportSeverityGroup     `json:"severity_groups"`
	Remediations   []reportRemediation       `json:"remediations"`
	RunRaw         safetyenvelope.Evaluation `json:"run_raw"`
}

// RenderTextOptions configures text report rendering.
type RenderTextOptions struct {
	ToolVersion     string
	DefaultTemplate string
	TemplatePath    string
	Writer          io.Writer
	Quiet           bool
}

// RenderText writes report text to opts.Writer unless opts.Quiet is true.
// When TemplatePath is set, it overrides DefaultTemplate.
func RenderText(eval safetyenvelope.Evaluation, opts RenderTextOptions) error {
	tplText := opts.DefaultTemplate
	if opts.TemplatePath != "" {
		b, err := fsutil.ReadFileLimited(opts.TemplatePath)
		if err != nil {
			return fmt.Errorf("read --template-file: %w", err)
		}
		tplText = string(b)
	}

	data := buildReportTemplateData(eval, opts.ToolVersion)
	var buf strings.Builder
	if err := ui.ExecuteTemplate(&buf, tplText, data); err != nil {
		return fmt.Errorf("render report template: %w", err)
	}

	if opts.Quiet {
		return nil
	}
	if _, err := io.WriteString(opts.Writer, buf.String()); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func buildReportTemplateData(eval safetyenvelope.Evaluation, toolVersion string) reportTemplateData {
	vm := buildReportViewModel(eval, toolVersion)
	meta := extractTemplateMetadata(vm.Run, eval.Extensions)
	return reportTemplateData{
		Metadata:       meta,
		Summary:        vm.Summary,
		Findings:       vm.Findings,
		SeverityGroups: tplGroupBySeverity(vm.Findings),
		Remediations:   vm.Remediations,
		RunRaw:         eval,
	}
}

func extractTemplateMetadata(run reportRun, ext *evaluation.Extensions) reportTemplateMetadata {
	meta := reportTemplateMetadata{reportRun: run}
	if ext == nil {
		return meta
	}
	meta.ContextName = ext.ContextName
	if ext.Git != nil {
		meta.GitRepoRoot = ext.Git.RepoRoot
		meta.GitHeadCommit = ext.Git.Head
		meta.GitDirty = ext.Git.Dirty
		if len(ext.Git.Modified) > 0 {
			meta.GitPathsDirty = strings.Join(ext.Git.Modified, ", ")
		}
	}
	return meta
}

// severityLabels maps sevRank (0=critical..5=unspecified) to display strings.
var severityLabels = [6]string{"critical", "high", "medium", "low", "info", "unspecified"}

func tplGroupBySeverity(findings []reportFinding) []reportSeverityGroup {
	const n = len(severityLabels)
	var counts [n]int
	for _, f := range findings {
		r := f.sevRank
		if r < 0 || r >= n {
			r = n - 1
		}
		counts[r]++ // #nosec G602 -- r is clamped to [0, n) above
	}
	out := make([]reportSeverityGroup, 0, len(counts))
	for i, c := range counts {
		if c > 0 {
			out = append(out, reportSeverityGroup{Severity: severityLabels[i], Count: c})
		}
	}
	return out
}
