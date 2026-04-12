// Package drift implements the 'stave drift' command for detecting
// configuration changes between two observation snapshots. Drift
// detection is a core capability of Stave's structural integrity
// model — it answers "what changed between two points in time?"
package drift

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
)

type options struct {
	BaselinePath string
	CurrentPath  string
	Format       string
}

// NewCmd constructs the top-level drift command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Detect configuration drift between two observation snapshots",
		Long: `Drift compares a baseline observation snapshot against a current snapshot
and reports all asset-level configuration changes. Resources that were
added, removed, or reconfigured are listed with property-level diffs.

This is the structural integrity check: "We were safe on Monday. What
specifically changed that made us unsafe on Tuesday?"

Inputs:
  --baseline, -b    Path to the baseline observation snapshot (JSON)
  --current, -c     Path to the current observation snapshot (JSON)
  --format, -f      Output format: text or json (default: text)

Outputs:
  stdout            Drift report in the requested format
  stderr            Diagnostic messages

Exit Codes:
  0   No drift detected — baseline and current are identical
  2   Input or configuration error
  3   Drift detected — one or more resources changed`,
		Example: `  stave drift --baseline monday.json --current tuesday.json
  stave drift -b baseline.json -c current.json --format json
  stave drift -b before-deploy.json -c after-deploy.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), cmd.ErrOrStderr(), opts)
		},
	}

	cmd.Flags().StringVarP(&opts.BaselinePath, "baseline", "b", "", "Path to baseline observation snapshot (required)")
	cmd.Flags().StringVarP(&opts.CurrentPath, "current", "c", "", "Path to current observation snapshot (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")

	_ = cmd.MarkFlagRequired("baseline")
	_ = cmd.MarkFlagRequired("current")

	return cmd
}

func run(stdout, stderr io.Writer, opts *options) error {
	baseline, err := loadSnapshot(opts.BaselinePath)
	if err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}

	current, err := loadSnapshot(opts.CurrentPath)
	if err != nil {
		return fmt.Errorf("load current: %w", err)
	}

	if baseline.SchemaVersion != current.SchemaVersion {
		return fmt.Errorf("schema version mismatch: baseline=%s current=%s",
			baseline.SchemaVersion, current.SchemaVersion)
	}

	result := asset.ComputeDrift(baseline, current)

	if result.Summary.Total() == 0 {
		fmt.Fprintln(stderr, "No drift detected.")
		return nil
	}

	switch opts.Format {
	case "json":
		if err := writeJSON(stdout, result); err != nil {
			return err
		}
	default:
		writeText(stdout, result)
	}

	fmt.Fprintf(stderr, "%d resource(s) changed\n", result.Summary.Total())
	return ui.ErrViolationsFound
}

func writeJSON(w io.Writer, result asset.InfrastructureDrift) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeText(w io.Writer, result asset.InfrastructureDrift) {
	fmt.Fprintf(w, "Drift Report\n")
	fmt.Fprintf(w, "------------\n")
	fmt.Fprintf(w, "Period: %s → %s\n\n",
		result.StartTime.Format("2006-01-02T15:04:05Z"),
		result.EndTime.Format("2006-01-02T15:04:05Z"))

	s := result.Summary
	fmt.Fprintf(w, "Summary: %d changed (%d new, %d removed, %d reconfigured)\n\n",
		s.Total(), s.Provisioned(), s.Decommissioned(), s.Reconfigured())

	if len(result.Changes) == 0 {
		return
	}

	fmt.Fprintf(w, "Changes:\n")
	for i := range result.Changes {
		c := &result.Changes[i]
		fmt.Fprintf(w, "  [%s] %s\n", c.Action, c.AssetID)
		for j := range c.Drifts {
			d := &c.Drifts[j]
			old := formatValue(d.OldValue, d.Attribute)
			nw := formatValue(d.NewValue, d.Attribute)
			if isSecurityAttribute(d.Attribute) {
				fmt.Fprintf(w, "    [!] %s: %s → %s\n", d.Attribute, old, nw)
			} else {
				fmt.Fprintf(w, "    %s: %s → %s\n", d.Attribute, old, nw)
			}
		}
	}
}

// isSecurityAttribute returns true for security-relevant attributes
// that deserve [!] highlighting in text output.
func isSecurityAttribute(attr string) bool {
	lower := strings.ToLower(attr)
	for _, m := range []string{
		"public", "encrypt", "logging", "audit", "mfa",
		"access_key", "password", "policy", "acl", "iam",
		"auth", "tls", "ssl", "versioning", "backup",
	} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func formatValue(v any, attr string) string {
	if v == nil {
		return "<absent>"
	}
	if isRedactable(attr) {
		return "[REDACTED]"
	}
	return fmt.Sprintf("%v", v)
}

// isRedactable returns true for attributes whose values should be masked.
func isRedactable(attr string) bool {
	lower := strings.ToLower(attr)
	for _, m := range []string{"secret", "token", "credential"} {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

func loadSnapshot(path string) (asset.Snapshot, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from CLI flag
	if err != nil {
		return asset.Snapshot{}, fmt.Errorf("read %s: %w", path, err)
	}
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return asset.Snapshot{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return snap, nil
}
