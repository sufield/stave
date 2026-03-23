package securityaudit

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options holds the raw CLI flag values for the security-audit command.
type options struct {
	FormatRaw   string
	OutPath     string
	OutDir      string
	SeverityRaw string
	SBOMFormat  string
	Frameworks  []string
	VulnSource  string
	LiveVuln    bool
	ReleaseDir  string
	Privacy     bool
	FailOn      string
	NowRaw      string
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.FormatRaw, "format", o.FormatRaw, "Report format: json, markdown, or sarif")
	f.StringVar(&o.OutPath, "out", "", "Main report output file path (default: <out-dir>/security-report.<ext>)")
	f.StringVar(&o.OutDir, "out-dir", "", "Artifact bundle output directory (default: ./security-audit-<timestamp>)")
	f.StringVar(&o.SeverityRaw, "severity", o.SeverityRaw, "Comma-separated severities to include: CRITICAL,HIGH,MEDIUM,LOW")
	f.StringVar(&o.SBOMFormat, "sbom", o.SBOMFormat, "SBOM format: spdx or cyclonedx")
	f.StringSliceVar(&o.Frameworks, "compliance-framework", nil,
		"Compliance frameworks (repeatable): "+strings.Join(
			compliance.FrameworkStrings(compliance.SupportedFrameworks()), ", ",
		),
	)
	f.StringVar(&o.VulnSource, "vuln-source", o.VulnSource, "Vulnerability evidence source: hybrid, local, or ci")
	f.BoolVar(&o.LiveVuln, "live-vuln-check", false, "Run local govulncheck live check (opt-in)")
	f.StringVar(&o.ReleaseDir, "release-bundle-dir", "", "Directory with release verification artifacts (SHA256SUMS and signatures)")
	f.BoolVar(&o.Privacy, "privacy-mode", false, "Enable strict privacy assertions")
	f.StringVar(&o.FailOn, "fail-on", o.FailOn, "Gate threshold: CRITICAL, HIGH, MEDIUM, LOW, or NONE")
	f.StringVar(&o.NowRaw, "now", "", "Override current time (RFC3339). Required for deterministic output")
}

// Prepare normalizes paths. Called from PreRunE.
func (o *options) Prepare(_ *cobra.Command) error {
	o.ReleaseDir = fsutil.CleanUserPath(o.ReleaseDir)
	o.OutPath = fsutil.CleanUserPath(o.OutPath)
	o.OutDir = fsutil.CleanUserPath(o.OutDir)
	return nil
}
