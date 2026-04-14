package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
	"github.com/sufield/stave/internal/adapters/observations"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/version"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/platform/crypto"
)

func runCompliance(
	ctx context.Context,
	opts *options,
	w io.Writer,
	newCtlRepo compose.CtlRepoFactory,
	newCELEvaluator compose.CELEvaluatorFactory,
) error {
	// 1. Validate profile ID.
	profile, err := evidenceadapter.LoadProfile(opts.Profile)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("invalid --profile: %w", err)}
	}

	// 2. Load snapshot.
	snapshots, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load snapshot: %w", err)}
	}
	if len(snapshots) == 0 {
		return &ui.UserError{Err: errors.New("snapshot file contains no observations")}
	}

	// 3. Load controls filtered to the compliance framework.
	repo, err := newCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}
	allControls, err := repo.LoadControls(ctx, "")
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	fw := policy.ComplianceFramework(profile.FrameworkKey)
	var controls []policy.ControlDefinition
	for i := range allControls {
		if allControls[i].HasCompliance(fw) {
			controls = append(controls, allControls[i])
		}
	}

	// 4. Initialize CEL evaluator.
	celEval, err := newCELEvaluator()
	if err != nil {
		return fmt.Errorf("init CEL evaluator: %w", err)
	}

	// 5. Run assessment with evidence generation.
	result, err := appeval.Evaluate(appeval.EvaluateInput{
		Controls:         controls,
		Snapshots:        snapshots,
		Clock:            ports.RealClock{},
		Hasher:           crypto.NewHasher(),
		StaveVersion:     version.String,
		PredicateParser:  ctlyaml.ParsePredicate,
		CELEvaluator:     celEval,
		GenerateEvidence: true,
	})
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	// 6. Evaluate profile against evidence package.
	pkg := result.EvidencePackage
	if pkg == nil {
		return errors.New("assessment did not produce evidence package")
	}

	assessment := evidence.EvaluateProfile(pkg, profile)

	// 7. Build export DTO.
	snapshotTime := snapshots[len(snapshots)-1].CapturedAt
	export := buildExport(profile, assessment, pkg, version.String, snapshotTime, opts.IncludePass, opts.MinSeverity)

	// 8. Write output.
	out := w
	if opts.Out != "" {
		f, fileErr := os.Create(opts.Out)
		if fileErr != nil {
			return fmt.Errorf("create output file: %w", fileErr)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(export); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}

	// 9. Determine exit code.
	return exitError(assessment)
}

// exitError returns a sentinel error matching the assessment outcome
// for correct exit code mapping.
func exitError(assessment *evidence.ProfileAssessment) error {
	if assessment.NotMetCount > 0 {
		return ui.ErrSecurityAuditFindings
	}
	if assessment.IncompleteCount > 0 {
		return ui.ErrViolationsFound
	}
	return nil
}
