package report

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
)

type reportTemplateMetadata struct {
	EvaluationTime string `json:"evaluation_time"`
	MaxUnsafe      string `json:"max_unsafe"`
	Snapshots      int    `json:"snapshots"`
	Offline        bool   `json:"offline"`
	ContextName    string `json:"context_name,omitempty"`
	GitRepoRoot    string `json:"git_repo_root,omitempty"`
	GitHeadCommit  string `json:"git_head_commit,omitempty"`
	GitDirty       bool   `json:"git_dirty"`
	GitPathsDirty  string `json:"git_paths_dirty,omitempty"`
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

// RenderText writes report text to w unless quiet is true.
// When templatePath is set, it overrides defaultTemplate.
func RenderText(
	eval safetyenvelope.Evaluation,
	toolVersion string,
	defaultTemplate string,
	templatePath string,
	w io.Writer,
	quiet bool,
) error {
	tplText := defaultTemplate
	if templatePath != "" {
		b, err := fsutil.ReadFileLimited(templatePath)
		if err != nil {
			return fmt.Errorf("read --template-file: %w", err)
		}
		tplText = string(b)
	}

	data := buildReportTemplateData(eval, toolVersion)
	var buf strings.Builder
	if err := ui.ExecuteTemplate(&buf, tplText, data); err != nil {
		return fmt.Errorf("render report template: %w", err)
	}

	if quiet {
		return nil
	}
	if _, err := io.WriteString(w, buf.String()); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

func buildReportTemplateData(eval safetyenvelope.Evaluation, toolVersion string) reportTemplateData {
	j := buildReportViewModel(eval, toolVersion)
	ctxName := ""
	gitRepoRoot := ""
	gitHeadCommit := ""
	gitDirty := false
	gitPathsDirty := ""
	if ext := eval.Extensions; ext != nil {
		ctxName = ext.ContextName
		if ext.Git != nil {
			gitRepoRoot = ext.Git.RepoRoot
			gitHeadCommit = ext.Git.Head
			gitDirty = ext.Git.Dirty
			if len(ext.Git.Modified) > 0 {
				gitPathsDirty = strings.Join(ext.Git.Modified, ", ")
			}
		}
	}
	d := reportTemplateData{
		Metadata: reportTemplateMetadata{
			EvaluationTime: j.Run.EvaluationTime,
			MaxUnsafe:      j.Run.MaxUnsafe,
			Snapshots:      j.Run.Snapshots,
			Offline:        j.Run.Offline,
			ContextName:    ctxName,
			GitRepoRoot:    gitRepoRoot,
			GitHeadCommit:  gitHeadCommit,
			GitDirty:       gitDirty,
			GitPathsDirty:  gitPathsDirty,
		},
		Summary:      j.Summary,
		Findings:     j.Findings,
		Remediations: j.Remediations,
		RunRaw:       eval,
	}
	d.SeverityGroups = tplGroupBySeverity(j.Findings)
	return d
}

func tplGroupBySeverity(findings []reportFinding) []reportSeverityGroup {
	counts := map[string]int{}
	for _, f := range findings {
		counts[normalizedSeverity(f.Severity)]++
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int {
		ri := severityRank(a)
		rj := severityRank(b)
		if ri != rj {
			return ri - rj
		}
		return strings.Compare(a, b)
	})
	out := make([]reportSeverityGroup, 0, len(keys))
	for _, k := range keys {
		out = append(out, reportSeverityGroup{Severity: k, Count: counts[k]})
	}
	return out
}
