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

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/core/ports"
)

// Deps holds the adapter factories the exempt command group needs.
// Currently only the validate subcommand depends on a factory; the
// others read or write the acceptance file via the appexempt
// app-layer service. Empty Deps is valid — NewCmd uses
// compose.DefaultFactories().
type Deps struct {
	NewBuiltinControlStore compose.BuiltinControlStoreFactory
}

const defaultFile = "./stave-acknowledgments.yaml"

// NewCmd constructs the exempt command group with default factories.
func NewCmd() *cobra.Command {
	f := compose.DefaultFactories()
	return NewCmdWithDeps(Deps{NewBuiltinControlStore: f.NewBuiltinControlStore})
}

// NewCmdWithDeps constructs the exempt command group with explicit
// dependencies. Used by cmd/commands.go to share the compose factory
// instance across all the wired subcommands.
func NewCmdWithDeps(deps Deps) *cobra.Command {
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
  validate      Validate the acceptance file
  suggest       Suggest exemptions for chronic/oscillating findings`,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(newAcknowledgeCmd())
	cmd.AddCommand(newExceptCmd())
	cmd.AddCommand(newExemptSubCmd())
	cmd.AddCommand(newListCmd())
	cmd.AddCommand(newRemoveCmd())
	cmd.AddCommand(newUpcomingCmd())
	cmd.AddCommand(newValidateCmd(deps))
	cmd.AddCommand(newHistoryCmd())
	cmd.AddCommand(newExportCmd())
	cmd.AddCommand(newSuggestCmd())

	return cmd
}

// --- acknowledge ---

type acknowledgeOptions struct {
	ControlID    string
	AssetID      string
	Reason       string
	Approver     string
	Expires      string
	Compensating string
	File         string
}

// Normalize is a no-op for acknowledge — all user-facing fields are
// cobra-required and File has a flag-default. The method exists so
// PreRunE has a stable hook if future validation lands here.
func (o *acknowledgeOptions) Normalize() error { return nil }

type acknowledgeResult struct {
	ControlID string
	AssetID   string
	Expires   string
}

func runAcknowledge(opts acknowledgeOptions) (acknowledgeResult, error) {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return acknowledgeResult{}, err
	}
	var comps []string
	if opts.Compensating != "" {
		comps = strings.Split(opts.Compensating, ",")
	}
	if addErr := f.AddAcknowledgment(appexempt.AcknowledgmentEntry{
		ControlID:            opts.ControlID,
		AssetID:              opts.AssetID,
		Reason:               opts.Reason,
		Approver:             opts.Approver,
		ExpiryDate:           opts.Expires,
		CompensatingControls: comps,
	}, appexempt.NewTimestamp(ports.RealClock{})); addErr != nil {
		return acknowledgeResult{}, addErr
	}
	if saveErr := appexempt.Save(opts.File, f, "stave exempt acknowledge", appexempt.NewTimestamp(ports.RealClock{})); saveErr != nil {
		return acknowledgeResult{}, saveErr
	}
	return acknowledgeResult{ControlID: opts.ControlID, AssetID: opts.AssetID, Expires: opts.Expires}, nil
}

func renderAcknowledge(w io.Writer, r acknowledgeResult) error {
	_, err := fmt.Fprintf(w, "Acknowledged: %s@%s (expires %s)\n", r.ControlID, r.AssetID, r.Expires)
	return err
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := runAcknowledge(opts)
			if err != nil {
				return err
			}
			return renderAcknowledge(cmd.OutOrStdout(), result)
		},
	}

	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "control ID (required)")
	cmd.Flags().StringVar(&opts.AssetID, "asset-id", "", "asset ARN or ID (required)")
	cmd.Flags().StringVar(&opts.Reason, "reason", "", "rationale for accepting this risk (required)")
	cmd.Flags().StringVar(&opts.Approver, "approver", "", "identity of approving authority (required)")
	cmd.Flags().StringVar(&opts.Expires, "expires", "", "expiry date YYYY-MM-DD (required)")
	cmd.Flags().StringVar(&opts.Compensating, "compensating", "", "comma-separated compensating control IDs")
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

func (o *exceptOptions) Normalize() error { return nil }

func runExcept(opts exceptOptions) error {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return err
	}
	if addErr := f.AddException(appexempt.ExceptionEntry{
		ControlID:  opts.ControlID,
		AssetID:    opts.AssetID,
		ExpiryDate: opts.Expires,
		Reason:     opts.Reason,
	}); addErr != nil {
		return addErr
	}
	return appexempt.Save(opts.File, f, "stave exempt except", appexempt.NewTimestamp(ports.RealClock{}))
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runExcept(opts)
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

func (o *assetOptions) Normalize() error { return nil }

func runAsset(opts assetOptions) error {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return err
	}
	if addErr := f.AddExemption(appexempt.ExemptionEntry{
		AssetPattern: opts.Pattern,
		Reason:       opts.Reason,
	}); addErr != nil {
		return addErr
	}
	return appexempt.Save(opts.File, f, "stave exempt asset", appexempt.NewTimestamp(ports.RealClock{}))
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAsset(opts)
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

func (o *listOptions) Normalize() error { return nil }

func runList(opts listOptions) (*appexempt.AcceptanceFile, error) {
	return appexempt.Load(opts.File)
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := runList(opts)
			if err != nil {
				return err
			}
			return appexempt.WriteList(cmd.OutOrStdout(), f, opts.Format, opts.ListType, opts.ShowExpired)
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

func (o *removeOptions) Normalize() error { return nil }

type removeResult struct{ ID string }

func runRemove(opts removeOptions) (removeResult, error) {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return removeResult{}, err
	}
	if rmErr := f.Remove(opts.ID, appexempt.NewTimestamp(ports.RealClock{})); rmErr != nil {
		return removeResult{}, rmErr
	}
	if saveErr := appexempt.Save(opts.File, f, "stave exempt remove", appexempt.NewTimestamp(ports.RealClock{})); saveErr != nil {
		return removeResult{}, saveErr
	}
	return removeResult{ID: opts.ID}, nil
}

func renderRemove(w io.Writer, r removeResult) error {
	_, err := fmt.Fprintf(w, "Revoked: %s\n", r.ID)
	return err
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := runRemove(opts)
			if err != nil {
				return err
			}
			return renderRemove(cmd.OutOrStdout(), result)
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
	// Resolved in Normalize.
	Now time.Time
}

// Normalize resolves the "now" reference that determines remaining
// days. Kept here (rather than in the runner) so a future --now
// override flag can slot in without reshaping the run function.
func (o *upcomingOptions) Normalize() error {
	o.Now = time.Now().UTC()
	return nil
}

type upcomingResult struct {
	Days    int
	Entries []appexempt.AcknowledgmentEntry
	Now     time.Time
}

func runUpcoming(opts upcomingOptions) (upcomingResult, error) {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return upcomingResult{}, err
	}
	return upcomingResult{
		Days:    opts.Days,
		Entries: f.Upcoming(opts.Days, opts.Now),
		Now:     opts.Now,
	}, nil
}

func renderUpcoming(w io.Writer, r upcomingResult) error {
	if len(r.Entries) == 0 {
		_, err := fmt.Fprintf(w, "No acceptances expiring within %d days.\n", r.Days)
		return err
	}
	if _, err := fmt.Fprintf(w, "ACCEPTANCES EXPIRING WITHIN %d DAYS\n", r.Days); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("-", 70)); err != nil {
		return err
	}
	for i := range r.Entries {
		a := &r.Entries[i]
		daysLeft := -1
		if expiry, parseErr := time.Parse("2006-01-02", a.ExpiryDate); parseErr == nil {
			daysLeft = int(time.Until(expiry).Hours() / 24)
		}
		if _, err := fmt.Fprintf(w, "  %-40s  %s  %d days  %s\n",
			a.ID, a.ExpiryDate, daysLeft, a.Approver); err != nil {
			return err
		}
	}
	return nil
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := runUpcoming(opts)
			if err != nil {
				return err
			}
			return renderUpcoming(cmd.OutOrStdout(), result)
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

func (o *historyOptions) Normalize() error { return nil }

func runHistory(opts historyOptions) ([]appexempt.AcknowledgmentEntry, error) {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return nil, err
	}
	return f.History(), nil
}

func renderHistory(w io.Writer, entries []appexempt.AcknowledgmentEntry, format string) error {
	if len(entries) == 0 {
		_, err := fmt.Fprintln(w, "No acknowledgment history.")
		return err
	}
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	appexempt.WriteHistory(w, entries)
	return nil
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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := runHistory(opts)
			if err != nil {
				return err
			}
			return renderHistory(cmd.OutOrStdout(), entries, opts.Format)
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: table | json")

	return cmd
}

// --- validate ---

type validateOptions struct {
	File string
}

func (o *validateOptions) Normalize() error { return nil }

type validateResult struct {
	Errors []string
}

func runValidate(opts validateOptions, newStore compose.BuiltinControlStoreFactory) (validateResult, error) {
	f, err := appexempt.Load(opts.File)
	if err != nil {
		return validateResult{}, err
	}

	// Load built-in catalog for compensating-control validation. The
	// factory is the compose-layer indirection so cmd/exempt no longer
	// imports the adapter or controldata packages directly.
	//
	// Catalog load errors are tolerated: validate's other checks
	// (required fields, expiry dates) are still useful without
	// catalog cross-reference.
	knownIDs := make(map[string]bool)
	if controls, loadErr := newStore(); loadErr == nil {
		for i := range controls {
			knownIDs[string(controls[i].ID)] = true
		}
	}

	return validateResult{Errors: f.ValidateWithCatalog(knownIDs)}, nil
}

func renderValidate(w io.Writer, r validateResult) error {
	if len(r.Errors) == 0 {
		_, err := fmt.Fprintln(w, "Acceptance file is valid.")
		return err
	}
	for _, e := range r.Errors {
		if _, err := fmt.Fprintf(w, "  ERROR: %s\n", e); err != nil {
			return err
		}
	}
	return errors.New("validation failed")
}

func newValidateCmd(deps Deps) *cobra.Command {
	opts := validateOptions{File: defaultFile}

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
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return opts.Normalize()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := runValidate(opts, deps.NewBuiltinControlStore)
			if err != nil {
				return err
			}
			return renderValidate(cmd.OutOrStdout(), result)
		},
	}

	cmd.Flags().StringVar(&opts.File, "file", opts.File, "path to acceptance file")

	return cmd
}
