// Package exempt implements the 'stave exempt' command group for managing
// risk acceptances (acknowledgments, exceptions, exemptions).
package exempt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	appexempt "github.com/sufield/stave/internal/app/exempt"
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
  validate      Validate the acceptance file`,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newAcknowledgeCmd())
	cmd.AddCommand(newExceptCmd())
	cmd.AddCommand(newExemptSubCmd())
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newRemoveCmd())
	cmd.AddCommand(newUpcomingCmd())
	cmd.AddCommand(newValidateCmd())

	return cmd
}

func newAcknowledgeCmd() *cobra.Command {
	var controlID, assetID, reason, approver, expires, compensating, file string

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
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			var comps []string
			if compensating != "" {
				comps = strings.Split(compensating, ",")
			}
			if addErr := f.AddAcknowledgment(appexempt.AcknowledgmentEntry{
				ControlID:            controlID,
				AssetID:              assetID,
				Reason:               reason,
				Approver:             approver,
				ExpiryDate:           expires,
				CompensatingControls: comps,
			}, time.Now().UTC().Format(time.RFC3339)); addErr != nil {
				return addErr
			}
			if saveErr := appexempt.Save(file, f, "stave exempt acknowledge", time.Now().UTC().Format(time.RFC3339)); saveErr != nil {
				return saveErr
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Acknowledged: %s@%s (expires %s)\n", controlID, assetID, expires)
			return nil
		},
	}

	cmd.Flags().StringVar(&controlID, "control-id", "", "control ID (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "asset ARN or ID (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "rationale for accepting this risk (required)")
	cmd.Flags().StringVar(&approver, "approver", "", "identity of approving authority (required)")
	cmd.Flags().StringVar(&expires, "expires", "", "expiry date YYYY-MM-DD (required)")
	cmd.Flags().StringVar(&compensating, "compensating", "", "comma-separated compensating control IDs")
	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")

	_ = cmd.MarkFlagRequired("control-id")
	_ = cmd.MarkFlagRequired("asset-id")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("approver")
	_ = cmd.MarkFlagRequired("expires")

	return cmd
}

func newExceptCmd() *cobra.Command {
	var controlID, assetID, expires, reason, file string

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			if addErr := f.AddException(appexempt.ExceptionEntry{
				ControlID:  controlID,
				AssetID:    assetID,
				ExpiryDate: expires,
				Reason:     reason,
			}); addErr != nil {
				return addErr
			}
			return appexempt.Save(file, f, "stave exempt except", time.Now().UTC().Format(time.RFC3339))
		},
	}

	cmd.Flags().StringVar(&controlID, "control-id", "", "control ID (required)")
	cmd.Flags().StringVar(&assetID, "asset-id", "", "asset ARN or ID (required)")
	cmd.Flags().StringVar(&expires, "expires", "", "expiry date YYYY-MM-DD")
	cmd.Flags().StringVar(&reason, "reason", "", "reason for exception")
	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")

	_ = cmd.MarkFlagRequired("control-id")
	_ = cmd.MarkFlagRequired("asset-id")

	return cmd
}

func newExemptSubCmd() *cobra.Command {
	var pattern, reason, file string

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
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			if addErr := f.AddExemption(appexempt.ExemptionEntry{
				AssetPattern: pattern,
				Reason:       reason,
			}); addErr != nil {
				return addErr
			}
			return appexempt.Save(file, f, "stave exempt asset", time.Now().UTC().Format(time.RFC3339))
		},
	}

	cmd.Flags().StringVar(&pattern, "pattern", "", "asset ID or glob pattern (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "reason for exemption")
	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")

	_ = cmd.MarkFlagRequired("pattern")

	return cmd
}

func newListCmd() *cobra.Command {
	var file, format, listType string
	var showExpired bool

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
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			return writeList(cmd.OutOrStdout(), f, format, listType, showExpired)
		},
	}

	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&listType, "type", "all", "filter by type: acknowledgment | exception | exemption | all")
	cmd.Flags().BoolVar(&showExpired, "expired", false, "include expired/revoked entries")

	return cmd
}

func newRemoveCmd() *cobra.Command {
	var id, file string

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
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			if rmErr := f.Remove(id, time.Now().UTC().Format(time.RFC3339)); rmErr != nil {
				return rmErr
			}
			if saveErr := appexempt.Save(file, f, "stave exempt remove", time.Now().UTC().Format(time.RFC3339)); saveErr != nil {
				return saveErr
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Revoked: %s\n", id)
			return nil
		},
	}

	cmd.Flags().StringVar(&id, "id", "", "acknowledgment ID (control_id@asset_id)")
	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")

	_ = cmd.MarkFlagRequired("id")

	return cmd
}

func newUpcomingCmd() *cobra.Command {
	var file string
	var days int

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
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			upcoming := f.Upcoming(days, time.Now().UTC())
			if len(upcoming) == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "No acceptances expiring within %d days.\n", days)
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ACCEPTANCES EXPIRING WITHIN %d DAYS\n", days)
			fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("-", 70))
			for i := range upcoming {
				a := &upcoming[i]
				expiry, _ := time.Parse("2006-01-02", a.ExpiryDate)
				daysLeft := int(time.Until(expiry).Hours() / 24)
				fmt.Fprintf(cmd.OutOrStdout(), "  %-40s  %s  %d days  %s\n",
					a.ID, a.ExpiryDate, daysLeft, a.Approver)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")
	cmd.Flags().IntVar(&days, "days", 30, "look-ahead window in days")

	return cmd
}

func newValidateCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate the acceptance file",
		Long: `Validate the acceptance file for required fields, date formats, and structural correctness.

Exit Codes:
  0   Validation passed
  2   Invalid input
  4   Internal error`,
		Example:       "  stave exempt validate --file ./stave-acknowledgments.yaml",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := appexempt.Load(file)
			if err != nil {
				return err
			}
			errs := f.Validate()
			if len(errs) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "Acceptance file is valid.")
				return nil
			}
			for _, e := range errs {
				fmt.Fprintf(cmd.OutOrStdout(), "  ERROR: %s\n", e)
			}
			return errors.New("validation failed")
		},
	}

	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acceptance file")

	return cmd
}

func writeList(w io.Writer, f *appexempt.AcceptanceFile, format, listType string, showExpired bool) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(f)
	}

	acks, exceptions, exemptions := f.ActiveCount()
	fmt.Fprintf(w, "Risk Acceptances: %d acknowledgments, %d exceptions, %d exemptions\n\n",
		acks, exceptions, exemptions)

	if listType == "all" || listType == "acknowledgment" {
		for i := range f.Acknowledgments {
			a := &f.Acknowledgments[i]
			if !showExpired && (a.Status == "revoked" || a.Status == "expired") {
				continue
			}
			fmt.Fprintf(w, "  [ACK]  %-40s  expires %s  %s  %s\n",
				a.ID, a.ExpiryDate, a.Approver, strings.ToUpper(a.Status))
		}
	}
	if listType == "all" || listType == "exception" {
		for _, e := range f.Exceptions {
			exp := "never"
			if e.ExpiryDate != "" {
				exp = e.ExpiryDate
			}
			fmt.Fprintf(w, "  [EXC]  %s@%s  expires %s\n", e.ControlID, e.AssetID, exp)
		}
	}
	if listType == "all" || listType == "exemption" {
		for _, e := range f.Exemptions {
			fmt.Fprintf(w, "  [EXM]  %s  %s\n", e.AssetPattern, e.Reason)
		}
	}
	return nil
}
