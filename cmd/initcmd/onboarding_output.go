package initcmd

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
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

func writeQuickstartSummary(
	out io.Writer,
	sourceLabel string,
	findings []remediation.Finding,
	latest asset.Snapshot,
	reportPath string,
) error {
	if len(findings) == 0 {
		return writeQuickstartNoFindingSummary(out, sourceLabel, reportPath)
	}
	top := findings[0]
	evidence := demoEvidenceLine(latest, string(top.AssetID))
	return writeQuickstartTopFindingSummary(out, sourceLabel, reportPath, top, evidence)
}

func writeQuickstartNoFindingSummary(out io.Writer, sourceLabel, reportPath string) error {
	if _, err := fmt.Fprintf(out, "Source: %s\n", sourceLabel); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Top finding: none (0 violations)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Asset: -"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(out, "Fix: no action required"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Report: %s\n", reportPath); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "Next: add a known-unsafe snapshot to validate detection behavior.")
	return err
}

func writeQuickstartTopFindingSummary(
	out io.Writer,
	sourceLabel string,
	reportPath string,
	top remediation.Finding,
	evidence string,
) error {
	if _, err := fmt.Fprintf(out, "Source: %s\n", sourceLabel); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Top finding: %s\n", top.ControlID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Asset: %s\n", top.AssetID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Fix: %s (%s)\n", "enable account/bucket Block Public Access + deny public principals", evidence); err != nil {
		return err
	}
	if _, err := fmt.Fprint(out, demoFixExample); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Report: %s\n", reportPath); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "Next: run `stave demo --fixture known-good` to compare safe output.")
	return err
}

func printDemoSummary(out io.Writer, snapshot asset.Snapshot, findings []remediation.Finding, reportPath string) error {
	if len(findings) == 0 {
		if _, err := fmt.Fprintln(out, "Found 0 violations."); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(out, "Report: %s\n", reportPath); err != nil {
			return err
		}
		return nil
	}

	top := findings[0]
	evidence := demoEvidenceLine(snapshot, string(top.AssetID))
	if _, err := fmt.Fprintf(out, "Found 1 violation: %s\n", top.ControlID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Asset: %s\n", top.AssetID); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Evidence: %s\n", evidence); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Fix: %s\n", demoFixHint); err != nil {
		return err
	}
	if _, err := fmt.Fprint(out, demoFixExample); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "Report: %s\n", reportPath); err != nil {
		return err
	}
	return nil
}

func demoEvidenceLine(snapshot asset.Snapshot, assetID string) string {
	for _, r := range snapshot.Assets {
		if r.ID.String() != assetID {
			continue
		}
		block := readBool(r.Properties, "storage", "controls", "public_access_fully_blocked")
		acl := "private"
		if readBool(r.Properties, "storage", "visibility", "public_read_via_acl") || readBool(r.Properties, "storage", "visibility", "public_read") {
			acl = "public-read"
		}
		return fmt.Sprintf("BlockPublicAccess=%t, ACL=%s", block, acl)
	}
	return "BlockPublicAccess=unknown, ACL=unknown"
}
