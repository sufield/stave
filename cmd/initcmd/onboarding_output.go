package initcmd

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/kernel"
)

const demoFixHint = "enable account/bucket Block Public Access + deny public principals"

const demoFixExample = `
Example (Terraform):

  resource "aws_s3_bucket_public_access_block" "example" {
    bucket                  = aws_s3_bucket.example.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
`

// SummaryRequest holds the data needed to render a finding summary.
type SummaryRequest struct {
	SourceLabel string
	ReportPath  string
	Findings    []remediation.Finding
	Snapshot    asset.Snapshot
}

// Presenter handles the formatting of demo and quickstart results.
type Presenter struct {
	Out       io.Writer
	Sanitizer kernel.Sanitizer
}

// WriteQuickstart renders the summary for the quickstart workflow.
func (p *Presenter) WriteQuickstart(req SummaryRequest) error {
	if len(req.Findings) == 0 {
		return p.render(
			req.SourceLabel, "none (0 violations)", "-",
			"no action required", false, req.ReportPath,
			"Next: add a known-unsafe snapshot to validate detection behavior.",
		)
	}

	top := req.Findings[0]
	evidence := extractEvidence(req.Snapshot, string(top.AssetID))

	return p.render(
		req.SourceLabel,
		string(top.ControlID),
		p.Sanitizer.ID(string(top.AssetID)),
		fmt.Sprintf("%s (%s)", demoFixHint, evidence),
		true,
		req.ReportPath,
		"Next: run `stave demo --fixture known-good` to compare safe output.",
	)
}

// WriteDemo renders the summary for the demo workflow.
func (p *Presenter) WriteDemo(req SummaryRequest) error {
	if len(req.Findings) == 0 {
		var err error
		writef := newWritef(p.Out, &err)
		writef("Found 0 violations.\n")
		writef("Report: %s\n", req.ReportPath)
		return err
	}

	top := req.Findings[0]
	evidence := extractEvidence(req.Snapshot, string(top.AssetID))

	var err error
	writef := newWritef(p.Out, &err)
	writef("Found 1 violation: %s\n", top.ControlID)
	writef("Asset: %s\n", p.Sanitizer.ID(string(top.AssetID)))
	writef("Evidence: %s\n", evidence)
	writef("Fix: %s\n", demoFixHint)
	writef("%s", demoFixExample)
	writef("Report: %s\n", req.ReportPath)
	return err
}

// render is the unified output engine for quickstart summaries.
func (p *Presenter) render(source, finding, assetLabel, fix string, showFixExample bool, reportPath, next string) error {
	var err error
	writef := newWritef(p.Out, &err)

	if source != "" {
		writef("Source: %s\n", source)
	}
	writef("Top finding: %s\n", finding)
	if assetLabel != "" {
		writef("Asset: %s\n", assetLabel)
	}
	if fix != "" {
		writef("Fix: %s\n", fix)
	}
	if showFixExample {
		writef("%s", demoFixExample)
	}
	writef("Report: %s\n", reportPath)
	if next != "" {
		writef("%s\n", next)
	}
	return err
}

// newWritef returns a closure that writes formatted output, short-circuiting on first error.
func newWritef(w io.Writer, err *error) func(string, ...any) {
	return func(format string, args ...any) {
		if *err != nil {
			return
		}
		_, *err = fmt.Fprintf(w, format, args...)
	}
}

// extractEvidence pulls S3 security markers from asset properties.
func extractEvidence(snapshot asset.Snapshot, assetID string) string {
	for _, r := range snapshot.Assets {
		if r.ID.String() != assetID {
			continue
		}
		block := readBool(r.Properties, "storage", "controls", "public_access_fully_blocked")
		acl := "private"
		if readBool(r.Properties, "storage", "access", "public_read_via_acl") || readBool(r.Properties, "storage", "access", "public_read") {
			acl = "public-read"
		}
		return fmt.Sprintf("BlockPublicAccess=%t, ACL=%s", block, acl)
	}
	return "BlockPublicAccess=unknown, ACL=unknown"
}
