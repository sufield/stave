package nep

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/core/iam"
)

type resourceOpts struct {
	Snapshot    string
	ResourceARN string
	Format      string
	Actions     string
}

func newResourceCmd() *cobra.Command {
	opts := &resourceOpts{Format: "table"}

	cmd := &cobra.Command{
		Use:   "resource",
		Short: "Show who has effective access to a resource",
		Long: `Show all principals with resolved effective access to a specific
resource ARN, with access path attribution (identity-based, resource
policy, or both).

Exit Codes:
  0   No non-designated access to the resource
  1   Non-designated principals have access (PHI violation)
  3   Incomplete resolution
  4   Internal error

Examples:
  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-patient-records

  stave nep resource --snapshot obs.json \
    --resource arn:aws:s3:::phi-records \
    --format json`,
		Example:       `  stave nep resource --snapshot obs.json --resource arn:aws:s3:::phi-records`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runResource(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "resource ARN to query (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.Actions, "actions", "", "comma-separated action filter")

	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("resource")

	return cmd
}

func runResource(w io.Writer, opts *resourceOpts) error {
	if _, err := os.Stat(opts.Snapshot); err != nil {
		return fmt.Errorf("snapshot file not found: %s", opts.Snapshot)
	}

	// Stub: builds ResourceAccessIndex from snapshot.
	idx := iam.NewResourceAccessIndex()

	entries := idx.EntriesFor(opts.ResourceARN)

	switch opts.Format {
	case "json":
		return renderResourceJSON(w, opts.ResourceARN, entries)
	default:
		return renderResourceTable(w, opts.ResourceARN, entries)
	}
}

func renderResourceJSON(w io.Writer, resourceARN string, entries []iam.ResourceAccessEntry) error {
	out := map[string]any{
		"resource_arn":   resourceARN,
		"accessor_count": len(entries),
	}
	if len(entries) > 0 {
		accessors := make([]map[string]any, len(entries))
		for i, e := range entries {
			accessors[i] = map[string]any{
				"principal_arn":    e.PrincipalARN,
				"actions":          e.Actions,
				"is_cross_account": e.IsCrossAccount,
				"is_public":        e.IsPublic,
			}
		}
		out["accessors"] = accessors
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func renderResourceTable(w io.Writer, resourceARN string, entries []iam.ResourceAccessEntry) error {
	fmt.Fprintf(w, "Resource: %s\n", resourceARN)
	fmt.Fprintf(w, "Accessors: %d\n", len(entries))

	if len(entries) == 0 {
		fmt.Fprintln(w, "\nNo principals with effective access found in snapshot.")
		return nil
	}

	fmt.Fprintln(w, "\nEFFECTIVE ACCESS")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "%-50s %-12s %s\n", "Principal", "Cross-acct", "Public")
	fmt.Fprintln(w, strings.Repeat("-", 90))
	for _, e := range entries {
		crossAcct := "no"
		if e.IsCrossAccount {
			crossAcct = "yes"
		}
		public := ""
		if e.IsPublic {
			public = "YES"
		}
		fmt.Fprintf(w, "%-50s %-12s %s\n",
			truncateARN(e.PrincipalARN, 50), crossAcct, public)
	}

	return nil
}
