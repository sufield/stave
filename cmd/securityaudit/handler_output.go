package securityaudit

import (
	"fmt"
	"io"

	securityout "github.com/sufield/stave/internal/adapters/output/securityaudit"
	"github.com/sufield/stave/internal/cli/ui"
	domainsecurityaudit "github.com/sufield/stave/pkg/alpha/domain/securityaudit"
)

func renderReport(format string, report domainsecurityaudit.Report) ([]byte, string, error) {
	switch format {
	case "json":
		data, err := securityout.MarshalJSONReport(report)
		return data, "security-report.json", err
	case "markdown":
		data, err := securityout.MarshalMarkdownReport(report)
		return data, "security-report.md", err
	case "sarif":
		data, err := securityout.MarshalSARIFReport(report)
		return data, "security-report.sarif", err
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}

func printSummary(w io.Writer, mainOutPath, bundleDir string, summary domainsecurityaudit.Summary) error {
	if _, err := fmt.Fprintf(w, "security-audit report: %s\n", mainOutPath); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "security-audit bundle: %s\n", bundleDir); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "summary: total=%d pass=%d warn=%d fail=%d gated=%t threshold=%s\n",
		summary.Total, summary.Pass, summary.Warn, summary.Fail, summary.Gated, summary.FailOn)
	return err
}

func parseFormat(raw string) (string, error) {
	normalized := ui.NormalizeToken(raw)
	switch normalized {
	case "json", "markdown", "sarif":
		return normalized, nil
	default:
		return "", &ui.UserError{Err: ui.EnumError("--format", raw, []string{"json", "markdown", "sarif"})}
	}
}
