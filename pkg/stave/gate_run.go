package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/app/teamgate"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// GateRunConfig parameterizes [RunGate]. It mirrors the `stave ci gate`
// flags. Policy / MaxUnsafe defaults are resolved from project config by the
// caller before this is built.
type GateRunConfig struct {
	Policy          string
	InPath          string
	BaselinePath    string
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string // raw duration
	Now             string // RFC3339 (validated but not applied — see note)
	Format          string // text | json
	Quiet           bool
	Team            string
	TeamManifest    string
}

// EnforcementGatePolicies returns the supported CI failure policy names (for
// shell completion).
func EnforcementGatePolicies() []string { return appconfig.AllEnforcementGates() }

// RunGate applies a CI failure policy (optionally scoped to one team) to an
// evaluation artifact and renders the gate verdict (text | json). It returns
// the rendered bytes, any operator warnings (to be shown on stderr), and
// whether the gate passed (the caller maps a fail to exit 3). Invalid policy
// / flags / team inputs wrap [ErrInvalidInput] (exit 2); the underlying gate
// failure stays plain (exit 4). It is the library entry point behind
// `stave ci gate`.
//
// Note: --now is validated for format but not applied to the verdict, and
// --sanitize does not affect the verdict — preserving the pre-facade command
// behavior exactly (both were resolved into a config the runner never read).
func RunGate(ctx context.Context, cfg GateRunConfig) (output []byte, warnings []string, passed bool, err error) {
	policy, err := appconfig.ParseEnforcementGate(cfg.Policy)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid policy: %w: %w", err, ErrInvalidInput)
	}

	var maxUnsafe time.Duration
	if !policy.SkipsMaxUnsafe() {
		maxUnsafe, err = kernel.ParseDuration(cfg.MaxUnsafe)
		if err != nil {
			return nil, nil, false, fmt.Errorf("invalid --max-unsafe %q: %w: %w", cfg.MaxUnsafe, err, ErrInvalidInput)
		}
	}

	// --now is validated (a bad value is an input error) but intentionally
	// not applied to the gate verdict — see the function note.
	if cfg.Now != "" {
		if _, perr := time.Parse(time.RFC3339, cfg.Now); perr != nil {
			return nil, nil, false, fmt.Errorf("parse --now %q: %w: %w", cfg.Now, perr, ErrInvalidInput)
		}
	}

	format, err := parseGateFormat(cfg.Format)
	if err != nil {
		return nil, nil, false, err
	}

	inPath := fsutil.CleanUserPath(cfg.InPath)

	result, err := Gate(ctx, GateConfig{
		Policy:          GatePolicy(policy),
		EvaluationPath:  inPath,
		BaselinePath:    fsutil.CleanUserPath(cfg.BaselinePath),
		ControlsDir:     fsutil.CleanUserPath(cfg.ControlsDir),
		ObservationsDir: fsutil.CleanUserPath(cfg.ObservationsDir),
		MaxUnsafe:       maxUnsafe,
	})
	if err != nil {
		return nil, nil, false, fmt.Errorf("run gate: %w", err)
	}

	// Per-team gate: filter findings to one team and fold its verdict into
	// the global result. Policies that derive their verdict from controls +
	// observations (no evaluation file) skip the per-team filter.
	teamRequested := cfg.Team != ""
	policySupportsTeams := policy.RequiresTeamScope()
	if teamRequested && !policySupportsTeams {
		warnings = append(warnings, fmt.Sprintf(
			"warning: --team flag ignored because policy %q does not require team scope", policy))
	}
	if teamRequested && policySupportsTeams {
		if cfg.TeamManifest == "" {
			return nil, nil, false, fmt.Errorf("--team-manifest is required when using --team: %w", ErrInvalidInput)
		}
		manifest, manifestErr := teams.LoadManifest(cfg.TeamManifest)
		if manifestErr != nil {
			return nil, nil, false, fmt.Errorf("load team manifest: %w: %w", manifestErr, ErrInvalidInput)
		}
		evalData, readErr := fsutil.ReadFileLimited(inPath)
		if readErr != nil {
			return nil, nil, false, fmt.Errorf("read evaluation for team gate: %w: %w", readErr, ErrInvalidInput)
		}
		var evalDoc struct {
			Findings []remediation.Finding `json:"findings"`
		}
		if unmarshalErr := json.Unmarshal(evalData, &evalDoc); unmarshalErr != nil {
			return nil, nil, false, fmt.Errorf("parse evaluation for team gate: %w: %w", unmarshalErr, ErrInvalidInput)
		}
		teamResult := teamgate.Evaluate(teamgate.Input{
			Findings:   evalDoc.Findings,
			Manifest:   manifest,
			TeamID:     cfg.Team,
			Thresholds: teamgate.DefaultThresholds(),
		})
		result.MergeTeamVerdict(teamResult.TeamID, teamResult.Passed, teamResult.Reason)
	}

	out, err := gateRenderResult(format, cfg.Quiet, result)
	if err != nil {
		return nil, nil, false, err
	}
	return out, warnings, result.Passed, nil
}

// gateJSONDoc is the JSON wire-format envelope. Field names + time encoding
// match the prior usecase.GateResponse shape so CI scripts keep working.
type gateJSONDoc struct {
	Policy            string    `json:"policy"`
	Pass              bool      `json:"pass"`
	Reason            string    `json:"reason"`
	CheckedAt         time.Time `json:"checked_at"`
	CurrentViolations int       `json:"current_violations,omitempty"`
	NewViolations     int       `json:"new_violations,omitempty"`
	OverdueUpcoming   int       `json:"overdue_upcoming,omitempty"`
}

// gateRenderResult renders the gate verdict. Text honors quiet (exit-code
// only); JSON always emits its wire format so downstream gates can parse it.
func gateRenderResult(format string, quiet bool, result *GateResult) ([]byte, error) {
	var buf bytes.Buffer
	switch format {
	case "json":
		if err := jsonutil.WriteIndented(&buf, gateJSONDoc{
			Policy:            string(result.Policy),
			Pass:              result.Passed,
			Reason:            result.Reason,
			CheckedAt:         result.CheckedAt,
			CurrentViolations: result.CurrentViolations,
			NewViolations:     result.NewViolations,
			OverdueUpcoming:   result.OverdueCount,
		}); err != nil {
			return nil, fmt.Errorf("write output: %w", err)
		}
	case "text":
		if !quiet {
			if _, err := fmt.Fprintf(&buf, "Gate %s (%s): %s\n", result.PassLabel(), result.Policy, result.Reason); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

// parseGateFormat normalizes the --format value to "text" or "json".
func parseGateFormat(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "text", "":
		return "text", nil
	case "json":
		return "json", nil
	}
	return "", fmt.Errorf("unsupported format %q (expected: text | json): %w", raw, ErrInvalidInput)
}
