package gate

import (
	"github.com/spf13/cobra"

	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/app/teamgate"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/internal/util/jsonutil"
	"github.com/sufield/stave/pkg/stave"
)

// renderGate writes the gate result in JSON (when isJSON) or text.
// Text is suppressed when quiet is set. Takes an io.Writer so the
// caller owns the cobra boundary.
//
// JSON is rendered through gateJSON so the wire format stays
// compatible with the previous usecase.GateResponse shape — operators
// running the JSON output through scripts or downstream gates rely
// on those exact field names.
func renderGate(w io.Writer, result *stave.GateResult, isJSON, quiet bool) error {
	if isJSON {
		return jsonutil.WriteIndented(w, gateJSON{
			Policy:            string(result.Policy),
			Pass:              result.Passed,
			Reason:            result.Reason,
			CheckedAt:         result.CheckedAt,
			CurrentViolations: result.CurrentViolations,
			NewViolations:     result.NewViolations,
			OverdueUpcoming:   result.OverdueCount,
		})
	}
	if quiet {
		return nil
	}
	_, err := fmt.Fprintf(w, "Gate %s (%s): %s\n", result.PassLabel(), result.Policy, result.Reason)
	return err
}

// gateJSON is the wire-format envelope for the JSON output. Field
// names and time-encoding match the prior usecase.GateResponse shape
// (time.Time's default RFC3339Nano marshaling) so existing CI scripts
// that grep `pass` or `current_violations` continue to work after
// the migration.
type gateJSON struct {
	Policy            string    `json:"policy"`
	Pass              bool      `json:"pass"`
	Reason            string    `json:"reason"`
	CheckedAt         time.Time `json:"checked_at"`
	CurrentViolations int       `json:"current_violations,omitempty"`
	NewViolations     int       `json:"new_violations,omitempty"`
	OverdueUpcoming   int       `json:"overdue_upcoming,omitempty"`
}

// Deps is retained as an empty struct for ABI compatibility with
// callers that pass it; the gate command now wires its own adapters
// through pkg/stave.Gate. Future iterations may remove the parameter.
type Deps struct{}

// NewCmd constructs the CI gate command.
func NewCmd(deps Deps) *cobra.Command {
	opts := DefaultOptions()

	cmd := &cobra.Command{
		Use:   "gate",
		Short: "Enforce CI failure policy modes from config or flags",
		Long: `Gate applies a CI failure policy and returns exit code 3 when the policy fails.

Supported policies:
  - fail_on_any_violation
  - fail_on_new_violation
  - fail_on_overdue_upcoming

Inputs:
  --policy          CI failure policy mode (default: from project config)
  --in              Path to evaluation JSON (required for fail_on_any/new)
  --baseline        Path to baseline JSON (required for fail_on_new_violation)
  --controls, -i    Path to control definitions directory (used by fail_on_overdue_upcoming)
  --observations, -o Path to observation snapshots directory (used by fail_on_overdue_upcoming)
  --max-unsafe      Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)
  --now             Reference time (RFC3339). If omitted, uses wall clock
  --format, -f      Output format: text or json (default: text)

Outputs:
  stdout            Gate result summary (text or JSON)
  stderr            Error messages (if any)

Exit Codes:
  0   - Policy passed; no violations detected
  2   - Invalid input or configuration error
  3   - Policy failed; violations detected
  130 - Interrupted (SIGINT)` + metadata.OfflineHelpSuffix,
		Example: `  # Fail on any findings in evaluation output
  stave ci gate --policy fail_on_any_violation --in output/evaluation.json

  # Fail only on newly introduced findings
  stave ci gate --policy fail_on_new_violation --in output/evaluation.json --baseline output/baseline.json

  # Fail when any upcoming action is already overdue
  stave ci gate --policy fail_on_overdue_upcoming --controls ./controls --observations ./observations`,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := toConfig(&opts, cliflags.GetGlobalFlags(cmd), cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			result, err := stave.Gate(cmd.Context(), stave.GateConfig{
				Policy:          stave.GatePolicy(cfg.Policy),
				EvaluationPath:  cfg.InPath,
				BaselinePath:    cfg.BaselinePath,
				ControlsDir:     cfg.ControlsDir,
				ObservationsDir: cfg.ObservationsDir,
				MaxUnsafe:       cfg.MaxUnsafeDuration,
			})
			if err != nil {
				return err
			}

			// Per-team gate: filter findings to one team and evaluate
			// thresholds. The team-gate path reads cfg.InPath (the
			// evaluation file). Policies like fail_on_overdue_upcoming
			// derive their verdict from controls + observations
			// directly and never produce an evaluation file — skip the
			// per-team filter for those cases instead of failing the
			// command on a missing path the operator was never asked
			// to provide.
			teamFilterRequested := opts.HasTeamFilter()
			policySupportsTeams := cfg.Policy.RequiresTeamScope()
			isIgnoredFilter := teamFilterRequested && !policySupportsTeams
			isApplyingTeamFilter := teamFilterRequested && policySupportsTeams

			if isIgnoredFilter {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: --team flag ignored because policy %q does not require team scope\n",
					cfg.Policy)
			}
			if isApplyingTeamFilter {
				if opts.TeamManifest == "" {
					return &ui.UserError{Err: errors.New("--team-manifest is required when using --team")}
				}
				manifest, manifestErr := teams.LoadManifest(opts.TeamManifest)
				if manifestErr != nil {
					return &ui.UserError{Err: fmt.Errorf("load team manifest: %w", manifestErr)}
				}
				evalData, readErr := fsutil.ReadFileLimited(cfg.InPath)
				if readErr != nil {
					return &ui.UserError{Err: fmt.Errorf("read evaluation for team gate: %w", readErr)}
				}
				var evalDoc struct {
					Findings []remediation.Finding `json:"findings"`
				}
				if unmarshalErr := json.Unmarshal(evalData, &evalDoc); unmarshalErr != nil {
					return &ui.UserError{Err: fmt.Errorf("parse evaluation for team gate: %w", unmarshalErr)}
				}
				teamResult := teamgate.Evaluate(teamgate.Input{
					Findings:   evalDoc.Findings,
					Manifest:   manifest,
					TeamID:     opts.Team,
					Thresholds: teamgate.DefaultThresholds(),
				})
				// Combine: the gate must clear BOTH the global policy
				// (already in result.Passed) and the per-team policy.
				// MergeTeamVerdict on GateResponse owns the AND-merge
				// so cmd-side code stops mutating Passed and Reason
				// inline.
				result.MergeTeamVerdict(teamResult.TeamID, teamResult.Passed, teamResult.Reason)
			}

			if renderErr := renderGate(cfg.Stdout, result, cfg.Format.IsJSON(), cfg.Quiet); renderErr != nil {
				return renderErr
			}

			return result.ExitError()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	registerCompletions(cmd)

	return cmd
}

func registerCompletions(cmd *cobra.Command) {
	_ = cmd.RegisterFlagCompletionFunc("policy", cliflags.CompleteFixed(appconfig.AllEnforcementGates()...))
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))
}
