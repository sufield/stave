package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/enforce/shared"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

const (
	gatePolicyAny     = projconfig.GatePolicyAny
	gatePolicyNew     = projconfig.GatePolicyNew
	gatePolicyOverdue = projconfig.GatePolicyOverdue
)

type options struct {
	Policy          string // raw flag value, normalized to GatePolicy by prepareRunInput
	InPath          string
	BaselinePath    string
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	Now             string
	Format          string
}

func defaultOptions() *options {
	return &options{
		Policy:          string(projconfig.ResolveCIFailurePolicyDefault()),
		InPath:          "output/evaluation.json",
		BaselinePath:    "output/baseline.json",
		ControlsDir:     "controls/s3",
		ObservationsDir: "observations",
		MaxUnsafe:       projconfig.ResolveMaxUnsafeDefault(),
		Format:          "text",
	}
}

func (o *options) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Policy, "policy", o.Policy, cmdutil.WithDynamicDefaultHelp("CI failure policy mode: fail_on_any_violation, fail_on_new_violation, fail_on_overdue_upcoming"))
	cmd.Flags().StringVar(&o.InPath, "in", o.InPath, "Path to evaluation JSON (required for fail_on_any_violation and fail_on_new_violation)")
	cmd.Flags().StringVar(&o.BaselinePath, "baseline", o.BaselinePath, "Path to baseline JSON (required for fail_on_new_violation)")
	cmd.Flags().StringVarP(&o.ControlsDir, "controls", "i", o.ControlsDir, "Path to control definitions directory (used by fail_on_overdue_upcoming)")
	cmd.Flags().StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory (used by fail_on_overdue_upcoming)")
	cmd.Flags().StringVar(&o.MaxUnsafe, "max-unsafe", o.MaxUnsafe, cmdutil.WithDynamicDefaultHelp("Maximum allowed unsafe duration (used by fail_on_overdue_upcoming)"))
	cmd.Flags().StringVar(&o.Now, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	cmd.Flags().StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
}

type gateResult struct {
	SchemaVersion kernel.Schema         `json:"schema_version"`
	Kind          kernel.OutputKind     `json:"kind"`
	CheckedAt     time.Time             `json:"checked_at"`
	Policy        projconfig.GatePolicy `json:"policy"`
	Pass          bool                  `json:"pass"`
	Reason        string                `json:"reason"`

	EvaluationPath   string `json:"evaluation_path,omitempty"`
	BaselinePath     string `json:"baseline_path,omitempty"`
	ControlsPath     string `json:"controls_path,omitempty"`
	ObservationsPath string `json:"observations_path,omitempty"`

	CurrentViolations int `json:"current_violations,omitempty"`
	NewViolations     int `json:"new_violations,omitempty"`
	OverdueUpcoming   int `json:"overdue_upcoming,omitempty"`
}

func run(cmd *cobra.Command, opts *options) error {
	runInput, err := prepareRunInput(opts)
	if err != nil {
		return err
	}
	result, err := executePolicy(cmd.Context(), runInput)
	if err != nil {
		return err
	}

	result = sanitizeGateResult(cmdutil.GetSanitizer(cmd), result)

	format, err := compose.ResolveFormatValue(cmd, opts.Format)
	if err != nil {
		return err
	}
	if err := writeOutput(cmd, format, result); err != nil {
		return err
	}
	if !result.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

type runInput struct {
	policy          projconfig.GatePolicy
	now             time.Time
	inPath          string
	baselinePath    string
	controlsDir     string
	observationsDir string
	maxUnsafe       time.Duration
}

func prepareRunInput(opts *options) (runInput, error) {
	inPath := fsutil.CleanUserPath(opts.InPath)
	baselinePath := fsutil.CleanUserPath(opts.BaselinePath)
	controlsDir := fsutil.CleanUserPath(opts.ControlsDir)
	observationsDir := fsutil.CleanUserPath(opts.ObservationsDir)

	policy, err := projconfig.ParseGatePolicy(opts.Policy)
	if err != nil {
		return runInput{}, err
	}

	now, err := compose.ResolveNow(opts.Now)
	if err != nil {
		return runInput{}, err
	}

	out := runInput{
		policy:          policy,
		now:             now,
		inPath:          inPath,
		baselinePath:    baselinePath,
		controlsDir:     controlsDir,
		observationsDir: observationsDir,
	}
	if policy != gatePolicyOverdue {
		return out, nil
	}
	maxUnsafeDur, parseErr := timeutil.ParseDurationFlag(opts.MaxUnsafe, "--max-unsafe")
	if parseErr != nil {
		return runInput{}, parseErr
	}
	out.maxUnsafe = maxUnsafeDur
	return out, nil
}

func executePolicy(ctx context.Context, input runInput) (gateResult, error) {
	switch input.policy {
	case gatePolicyAny:
		return runPolicyAny(input.now, input.inPath)
	case gatePolicyNew:
		return runPolicyNew(input.now, input.inPath, input.baselinePath)
	case gatePolicyOverdue:
		return runPolicyOverdue(ctx, input.now, input.controlsDir, input.observationsDir, input.maxUnsafe)
	default:
		return gateResult{}, fmt.Errorf("unsupported --policy %q", input.policy)
	}
}

func writeOutput(cmd *cobra.Command, format ui.OutputFormat, result gateResult) error {
	if format.IsJSON() {
		if err := jsonutil.WriteIndented(cmd.OutOrStdout(), result); err != nil {
			return fmt.Errorf("write gate output: %w", err)
		}
		return nil
	}
	if cmdutil.QuietEnabled(cmd) {
		return nil
	}
	if result.Pass {
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "Gate PASS (%s): %s\n", result.Policy, result.Reason)
		return err
	}
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "Gate FAIL (%s): %s\n", result.Policy, result.Reason)
	return err
}

func runPolicyAny(now time.Time, evaluationPath string) (gateResult, error) {
	eval, err := shared.LoadEvaluationEnvelope(evaluationPath)
	if err != nil {
		return gateResult{}, err
	}
	count := len(eval.Findings)
	pass := count == 0
	reason := fmt.Sprintf("current findings=%d", count)
	if pass {
		reason = "no current findings"
	}
	return gateResult{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         now,
		Policy:            gatePolicyAny,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    evaluationPath,
		CurrentViolations: count,
	}, nil
}

func runPolicyNew(now time.Time, evaluationPath, baselinePath string) (gateResult, error) {
	eval, err := shared.LoadEvaluationEnvelope(evaluationPath)
	if err != nil {
		return gateResult{}, err
	}
	base, err := shared.LoadBaselineFile(baselinePath, "baseline")
	if err != nil {
		return gateResult{}, err
	}
	bc := shared.CompareBaseline(base.Findings, eval.Findings)
	pass := !bc.Comparison.HasNewFindings()
	reason := fmt.Sprintf("new findings=%d", len(bc.Comparison.New))
	if pass {
		reason = "no new findings compared to baseline"
	}
	return gateResult{
		SchemaVersion:     kernel.SchemaGate,
		Kind:              kernel.KindGateCheck,
		CheckedAt:         now,
		Policy:            gatePolicyNew,
		Pass:              pass,
		Reason:            reason,
		EvaluationPath:    evaluationPath,
		BaselinePath:      baselinePath,
		CurrentViolations: len(bc.Current),
		NewViolations:     len(bc.Comparison.New),
	}, nil
}

func sanitizeGateResult(s kernel.Sanitizer, r gateResult) gateResult {
	if s == nil {
		return r
	}
	r.EvaluationPath = s.Path(r.EvaluationPath)
	r.BaselinePath = s.Path(r.BaselinePath)
	r.ControlsPath = s.Path(r.ControlsPath)
	r.ObservationsPath = s.Path(r.ObservationsPath)
	return r
}

func runPolicyOverdue(ctx context.Context, now time.Time, controlsDir, observationsDir string, maxUnsafe time.Duration) (gateResult, error) {
	loaded, err := compose.ActiveProvider().LoadAssets(ctx, observationsDir, controlsDir)
	if err != nil {
		return gateResult{}, err
	}
	items := risk.ComputeItems(risk.Request{
		Controls:        loaded.Controls,
		Snapshots:       loaded.Snapshots,
		GlobalMaxUnsafe: maxUnsafe,
		Now:             now,
		PredicateParser: ctlyaml.YAMLPredicateParser,
	})
	overdue := items.CountOverdue()
	pass := overdue == 0
	reason := fmt.Sprintf("overdue upcoming actions=%d", overdue)
	if pass {
		reason = "no overdue upcoming actions"
	}
	return gateResult{
		SchemaVersion:    kernel.SchemaGate,
		Kind:             kernel.KindGateCheck,
		CheckedAt:        now,
		Policy:           gatePolicyOverdue,
		Pass:             pass,
		Reason:           reason,
		ControlsPath:     controlsDir,
		ObservationsPath: observationsDir,
		OverdueUpcoming:  overdue,
	}, nil
}
