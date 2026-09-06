// Package exempt implements the 'stave exempt' command group for managing
// risk acceptances (acknowledgments, exceptions, exemptions).
package exempt

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/pkg/stave"
)

const defaultFile = "./stave-acknowledgments.yaml"

// NewCmd constructs the exempt command group.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exempt",
		Short: "Manage risk acceptances (acknowledgments, exceptions, exemptions)",
		Long: `CRUD interface for managing formal risk acceptance records.

Subcommands:
  acknowledge   Add a formal risk acceptance
  except        Add an operational suppression
  exempt        Add a scope exclusion
  list          List all active entries
  remove        Mark an acknowledgment as revoked
  upcoming      Show entries approaching expiry
  lint          Lint the acceptance file
  suggest       Suggest exemptions for chronic/oscillating findings`,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newAcknowledgeCmd())
	cmd.AddCommand(newExceptCmd())
	cmd.AddCommand(newExemptSubCmd())
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newRemoveCmd())
	cmd.AddCommand(newUpcomingCmd())
	cmd.AddCommand(newValidateCmd())
	cmd.AddCommand(newHistoryCmd())
	cmd.AddCommand(newExportCmd())
	cmd.AddCommand(newSuggestCmd())

	return cmd
}

// --- acknowledge ---

type acknowledgeOptions struct {
	ControlID     string
	AssetID       string
	Reason        string
	Approver      string
	Expires       string
	Compensating  string
	ReviewCadence string
	File          string
}

func newAcknowledgeCmd() *cobra.Command {
	opts := acknowledgeOptions{File: defaultFile}

	cmd := &cobra.Command{
		Use:   "acknowledge",
		Short: "Add a formal risk acceptance",
		Long: `Add a formal risk acceptance (acknowledgment) for a specific finding.
Requires approver identity, rationale, and expiry date.
The entry is written to the acceptance YAML file with a full audit trail.

Exit Codes:
  0   Acknowledgment added
  2   Invalid input
  4   Internal error`,
		Example: `  stave exempt acknowledge \
    --control-id CTL.S3.PUBLIC.001 \
    --asset-id arn:aws:s3:::legacy-bucket \
    --reason "Temporary public access during migration" \
    --approver "jane.doe@example.com (CISO)" \
    --expires 2026-09-01`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := stave.AddAcknowledgment(opts.File, stave.AcknowledgmentInput{
				ControlID:     stave.ControlID(opts.ControlID),
				AssetID:       opts.AssetID,
				Reason:        opts.Reason,
				Approver:      opts.Approver,
				Expires:       opts.Expires,
				Compensating:  opts.Compensating,
				ReviewCadence: opts.ReviewCadence,
			}); err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Acknowledged: %s@%s (expires %s)\n", opts.ControlID, opts.AssetID, opts.Expires); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "control ID (required)")
	cmd.Flags().StringVar(&opts.AssetID, "asset-id", "", "asset ARN or ID (required)")
	cmd.Flags().StringVar(&opts.Reason, "reason", "", "rationale for accepting this risk (required)")
	cmd.Flags().StringVar(&opts.Approver, "approver", "", "identity of approving authority (required)")
	cmd.Flags().StringVar(&opts.Expires, "expires", "", "expiry date YYYY-MM-DD (required)")
	cmd.Flags().StringVar(&opts.Compensating, "compensating", "", "comma-separated compensating control IDs")
	cmd.Flags().StringVar(&opts.ReviewCadence, "review-cadence", "", "review cadence (annual, quarterly, monthly, or duration like 90d)")
	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")

	cliflags.MustMarkRequired(cmd, "control-id")
	cliflags.MustMarkRequired(cmd, "asset-id")
	cliflags.MustMarkRequired(cmd, "reason")
	cliflags.MustMarkRequired(cmd, "approver")
	cliflags.MustMarkRequired(cmd, "expires")

	return cmd
}

// --- except ---

type exceptOptions struct {
	ControlID string
	AssetID   string
	Expires   string
	Reason    string
	File      string
}

func newExceptCmd() *cobra.Command {
	opts := exceptOptions{File: defaultFile}

	cmd := &cobra.Command{
		Use:   "except",
		Short: "Add an operational suppression",
		Long: `Add an operational suppression (exception) for a specific control and asset pair.

Exit Codes:
  0   Exception added
  2   Invalid input
  4   Internal error`,
		Example:       `  stave exempt except --control-id CTL.IAM.MFA.001 --asset-id arn:aws:iam::123:user/svc`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return stave.AddException(opts.File, stave.ExceptionInput{ //nolint:wrapcheck // facade already wrapped; preserve exit 4.
				ControlID: stave.ControlID(opts.ControlID),
				AssetID:   opts.AssetID,
				Expires:   opts.Expires,
				Reason:    opts.Reason,
			})
		},
	}

	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "control ID (required)")
	cmd.Flags().StringVar(&opts.AssetID, "asset-id", "", "asset ARN or ID (required)")
	cmd.Flags().StringVar(&opts.Expires, "expires", "", "expiry date YYYY-MM-DD")
	cmd.Flags().StringVar(&opts.Reason, "reason", "", "reason for exception")
	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")

	cliflags.MustMarkRequired(cmd, "control-id")
	cliflags.MustMarkRequired(cmd, "asset-id")

	return cmd
}

// --- asset (exemption) ---

type assetOptions struct {
	Pattern string
	Reason  string
	File    string
}

func newExemptSubCmd() *cobra.Command {
	opts := assetOptions{File: defaultFile}

	cmd := &cobra.Command{
		Use:   "asset",
		Short: "Add a scope exclusion (exemption)",
		Long: `Add a scope exclusion (exemption) for an asset or asset pattern.
Exempted assets are excluded from all control evaluation.

Exit Codes:
  0   Exemption added
  2   Invalid input
  4   Internal error`,
		Example:       `  stave exempt asset --pattern "arn:aws:s3:::sandbox-*" --reason "sandbox"`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return stave.AddAssetExemption(opts.File, opts.Pattern, opts.Reason) //nolint:wrapcheck // facade already wrapped; preserve exit 4.
		},
	}

	cmd.Flags().StringVar(&opts.Pattern, "pattern", "", "asset ID or glob pattern (required)")
	cmd.Flags().StringVar(&opts.Reason, "reason", "", "reason for exemption")
	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")

	cliflags.MustMarkRequired(cmd, "pattern")

	return cmd
}

// --- list ---

type listOptions struct {
	File        string
	Format      string
	ListType    string
	ShowExpired bool
}

func newListCmd() *cobra.Command {
	opts := listOptions{File: defaultFile, Format: "table", ListType: "all"}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all active risk acceptances",
		Long: `List all active risk acceptances including acknowledgments, exceptions, and exemptions.

Exit Codes:
  0   List produced
  2   Invalid input
  4   Internal error`,
		Example:       "  stave exempt list\n  stave exempt list --format json --expired",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.ListAcceptances(opts.File, opts.Format, opts.ListType, opts.ShowExpired)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			_, werr := cmd.OutOrStdout().Write(out)
			return werr
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: table | json")
	cmd.Flags().StringVar(&opts.ListType, "type", opts.ListType, "filter by type: acknowledgment | exception | exemption | all")
	cmd.Flags().BoolVar(&opts.ShowExpired, "expired", false, "include expired/revoked entries")

	return cmd
}

// --- remove ---

type removeOptions struct {
	ID   string
	File string
}

func newRemoveCmd() *cobra.Command {
	opts := removeOptions{File: defaultFile}

	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Mark an acknowledgment as revoked",
		Long: `Mark an acknowledgment as revoked. The entry is preserved with audit trail — not deleted.

Exit Codes:
  0   Entry revoked
  2   Invalid input
  4   Internal error`,
		Example:       `  stave exempt remove --id "CTL.S3.PUBLIC.001@arn:aws:s3:::bucket"`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := stave.RemoveAcceptance(opts.File, opts.ID); err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Revoked: %s\n", opts.ID); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.ID, "id", "", "acknowledgment ID (control_id@asset_id)")
	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")

	cliflags.MustMarkRequired(cmd, "id")

	return cmd
}

// --- upcoming ---

type upcomingOptions struct {
	File string
	Days int
}

func newUpcomingCmd() *cobra.Command {
	opts := upcomingOptions{File: defaultFile, Days: 30}

	cmd := &cobra.Command{
		Use:   "upcoming",
		Short: "Show acceptances approaching expiry",
		Long: `Show acknowledgments with expiry dates within the specified look-ahead window.

Exit Codes:
  0   Report produced
  2   Invalid input
  4   Internal error`,
		Example:       "  stave exempt upcoming --days 30",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.UpcomingAcceptances(opts.File, opts.Days, time.Now().UTC())
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			_, werr := cmd.OutOrStdout().Write(out)
			return werr
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")
	cmd.Flags().IntVar(&opts.Days, "days", opts.Days, "look-ahead window in days")

	return cmd
}

// --- history ---

type historyOptions struct {
	File   string
	Format string
}

func newHistoryCmd() *cobra.Command {
	opts := historyOptions{File: defaultFile, Format: "table"}

	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show full audit trail including expired entries",
		Long: `Show the complete audit trail for all acknowledgments, including
expired and revoked entries. Each entry shows its full lifecycle.

Exit Codes:
  0   History produced
  2   Invalid input
  4   Internal error`,
		Example:       "  stave exempt history\n  stave exempt history --format json",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.AcceptanceHistory(opts.File, opts.Format)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			_, werr := cmd.OutOrStdout().Write(out)
			return werr
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: table | json")

	return cmd
}

// --- validate ---

type validateOptions struct {
	File   string
	Strict bool
}

func newValidateCmd() *cobra.Command {
	opts := validateOptions{File: defaultFile}

	cmd := &cobra.Command{
		Use:   "lint",
		Short: "Lint the acceptance file",
		Long: `Lint the acceptance file for required fields, date formats, and structural correctness.

Overdue exemption reviews are surfaced as warnings by default.
With --strict, overdue reviews are treated as errors.

Exit Codes:
  0   Lint passed
  2   Invalid input
  4   Internal error`,
		Example:       "  stave exempt lint --file ./stave-acknowledgments.yaml",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := stave.ValidateAcceptances(opts.File)
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			w := cmd.OutOrStdout()
			hasErrors := len(result.Errors) > 0
			hasWarnings := len(result.Warnings) > 0
			if !hasErrors && !hasWarnings {
				if _, werr := fmt.Fprintln(w, "Acceptance file is valid."); werr != nil {
					return fmt.Errorf("write output: %w", werr)
				}
				return nil
			}
			for _, e := range result.Errors {
				if _, werr := fmt.Fprintf(w, "  ERROR: %s\n", e); werr != nil {
					return werr
				}
			}
			for _, warn := range result.Warnings {
				if _, werr := fmt.Fprintf(w, "  WARNING: %s\n", warn); werr != nil {
					return werr
				}
			}
			if hasErrors || (opts.Strict && hasWarnings) {
				return errors.New("validation failed")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")
	cmd.Flags().BoolVar(&opts.Strict, "strict", false, "treat overdue reviews as errors")

	return cmd
}
