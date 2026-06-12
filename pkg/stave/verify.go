package stave

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	"github.com/sufield/stave/internal/adapters/predicate"
	appattest "github.com/sufield/stave/internal/app/attestation"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/sanitize"
)

// VerifyConfig parameterizes [VerifyRemediation]. It mirrors the
// `stave check` flags plus the global --sanitize / --path-mode settings.
type VerifyConfig struct {
	BeforeDir   string
	AfterDir    string
	ControlsDir string
	MaxUnsafe   string // raw duration, e.g. "168h", "7d", or ""
	Now         string // RFC3339 override, or "" for wall clock
	SanitizeIDs bool
	PathMode    string // "" base, "full"

	// Progress is an optional per-stage progress hook (label -> done func).
	// nil disables progress (the default for non-CLI callers).
	Progress func(label string) func()
}

// VerifyRemediation runs the same controls against the before- and after-
// remediation observation directories and renders the attestation report
// (resolved / remaining / introduced findings) as JSON, returning the
// rendered bytes and whether any remaining-or-introduced violations exist
// (the caller maps that to exit 3; the report is rendered regardless).
// Load/parse/evaluation failures stay plain (exit 4). It is the library
// entry point behind `stave check`.
func VerifyRemediation(ctx context.Context, cfg VerifyConfig) (output []byte, hasViolations bool, err error) {
	maxUnsafe, err := kernel.ParseDuration(cfg.MaxUnsafe)
	if err != nil {
		return nil, false, fmt.Errorf("parse max-unsafe duration: %w", err)
	}

	clock, err := resolveVerifyClock(cfg.Now)
	if err != nil {
		return nil, false, err
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, false, fmt.Errorf("init CEL evaluator: %w", err)
	}

	sanitizer := sanitize.Policy{SanitizeIDs: cfg.SanitizeIDs, PathMode: sanitize.PathMode(cfg.PathMode)}.NewSanitizer()

	var buf bytes.Buffer
	perr := appattest.PerformAttestation(ctx, appattest.WorkflowDeps{
		LoadPolicies: func(ctx context.Context, dir string) ([]policy.ControlDefinition, error) {
			controls, lErr := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(predicate.ResolverFunc())).LoadControls(ctx, dir)
			if lErr != nil {
				return nil, fmt.Errorf("loading controls from %s: %w", dir, lErr)
			}
			return controls, nil
		},
		NewObservationRepo: func() (appcontracts.ObservationRepository, error) {
			return observations.NewObservationLoader(), nil
		},
		PublishAttestation: func(w io.Writer, a *report.Attestation) error {
			return outjson.WriteVerification(w, a)
		},
		BeginStage: cfg.Progress,
	}, appattest.Request{
		BaselineSource: cfg.BeforeDir,
		TargetSource:   cfg.AfterDir,
		PolicySource:   cfg.ControlsDir,
		SLAThreshold:   maxUnsafe,
		Clock:          clock,
		Sanitizer:      sanitizer,
		Stdout:         &buf,
		PredicateEval:  celEval,
	})
	if perr != nil {
		if errors.Is(perr, appcontracts.ErrViolationsFound) {
			return buf.Bytes(), true, nil
		}
		return nil, false, perr //nolint:wrapcheck // app layer already wrapped; preserve exit 4.
	}
	return buf.Bytes(), false, nil
}

// resolveVerifyClock mirrors the CLI clock resolution: empty defers to the
// wall clock; otherwise an RFC3339 instant pins a fixed clock.
func resolveVerifyClock(raw string) (ports.Clock, error) {
	if raw == "" {
		return ports.RealClock{}, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("parse --now: %w", err)
	}
	return ports.FixedClock(t), nil
}
