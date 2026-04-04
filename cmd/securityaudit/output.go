package securityaudit

import (
	"fmt"
	"io"

	securityout "github.com/sufield/stave/internal/adapters/output/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	domainsecurityaudit "github.com/sufield/stave/internal/core/securityaudit"
)

const (
	auditFormatJSON     = string(domainsecurityaudit.ReportFormatJSON)
	auditFormatMarkdown = string(domainsecurityaudit.ReportFormatMarkdown)
	auditFormatSARIF    = string(domainsecurityaudit.ReportFormatSARIF)
)

func renderReport(format string, report domainsecurityaudit.Report) ([]byte, string, error) {
	switch format {
	case auditFormatJSON:
		data, err := securityout.MarshalJSONReport(report)
		return data, "security-report.json", err
	case auditFormatMarkdown:
		data, err := securityout.MarshalMarkdownReport(report)
		return data, "security-report.md", err
	case auditFormatSARIF:
		data, err := securityout.MarshalSARIFReport(report)
		return data, "security-report.sarif", err
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}

func printSummary(w io.Writer, mainOutPath, bundleDir string, counts domainsecurityaudit.ResultCounts, gating domainsecurityaudit.GatingInfo) error {
	if _, err := fmt.Fprintf(w, "security-audit report: %s\n", mainOutPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "security-audit bundle: %s\n", bundleDir); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "summary: total=%d pass=%d warn=%d fail=%d gated=%t threshold=%s\n",
		counts.Total, counts.Pass, counts.Warn, counts.Fail, gating.Gated, gating.DisplayFailOn())
	return err
}

func parseFormat(raw string) (string, error) {
	normalized := ui.NormalizeToken(raw)
	switch normalized {
	case auditFormatJSON, auditFormatMarkdown, auditFormatSARIF:
		return normalized, nil
	default:
		return "", &ui.UserError{Err: ui.EnumError("--format", raw, domainsecurityaudit.AllReportFormats())}
	}
}
