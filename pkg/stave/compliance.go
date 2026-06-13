package stave

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/adapters/cel"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	evidenceadapter "github.com/sufield/stave/internal/adapters/evidence"
	appeval "github.com/sufield/stave/internal/app/eval"
	policy "github.com/sufield/stave/internal/core/controldef"
	coreevidence "github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// ComplianceReport is a framework-scoped compliance posture: the
// requirement-level met / not-met / not-evaluated breakdown plus the
// overall coverage percentage.
type ComplianceReport = coreevidence.ProfileAssessment

// Compliance evaluates the snapshots in snapshotsDir against the
// requested compliance framework profile (e.g. "hipaa",
// "cis_aws_v3.0", "pci_dss_v4.0") and returns the requirement-level
// posture.
//
// It loads the embedded profile, evaluates only the builtin controls
// mapped to that framework (with evidence generation), and projects
// the per-requirement assessment. Deterministic and offline. An
// unknown framework returns an error listing the available profiles.
func Compliance(ctx context.Context, snapshotsDir, framework string) (*ComplianceReport, error) {
	if snapshotsDir == "" {
		return nil, errors.New("stave.Compliance: snapshotsDir is required")
	}
	if framework == "" {
		return nil, errors.New("stave.Compliance: framework is required")
	}
	profile, err := loadProfile(framework)
	if err != nil {
		return nil, err
	}
	pkg, err := evidencePackageForProfiles(ctx, snapshotsDir, []*coreevidence.FrameworkProfile{profile})
	if err != nil {
		return nil, err
	}
	return coreevidence.EvaluateProfile(pkg, profile), nil
}

// ComplianceMulti evaluates the snapshots in snapshotsDir ONCE and
// projects the requirement-level posture for each requested framework
// from the same evidence package. It is the single-pass equivalent of
// calling [Compliance] per framework — one evaluation over the union
// of mapped controls instead of N full evaluations — which matters
// when building a multi-framework scorecard.
//
// An empty frameworks slice defaults to every available framework
// (see [AvailableFrameworks]). Reports are returned in the same order
// as the resolved framework list. An unknown framework returns an
// error listing the available profiles. Deterministic and offline.
func ComplianceMulti(ctx context.Context, snapshotsDir string, frameworks []string) ([]*ComplianceReport, error) {
	if snapshotsDir == "" {
		return nil, errors.New("stave.ComplianceMulti: snapshotsDir is required")
	}
	if len(frameworks) == 0 {
		frameworks = availableProfileIDs()
	}

	profiles := make([]*coreevidence.FrameworkProfile, 0, len(frameworks))
	for _, fw := range frameworks {
		profile, err := loadProfile(fw)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}

	pkg, err := evidencePackageForProfiles(ctx, snapshotsDir, profiles)
	if err != nil {
		return nil, err
	}

	reports := make([]*ComplianceReport, 0, len(profiles))
	for _, profile := range profiles {
		reports = append(reports, coreevidence.EvaluateProfile(pkg, profile))
	}
	return reports, nil
}

// loadProfile loads one embedded framework profile by ID, wrapping a
// miss in an error that lists the available profiles.
func loadProfile(framework string) (*coreevidence.FrameworkProfile, error) {
	profile, err := evidenceadapter.LoadProfile(framework)
	if err != nil {
		return nil, fmt.Errorf("framework %q not found; available: %s",
			framework, strings.Join(availableProfileIDs(), ", "))
	}
	return profile, nil
}

// evidencePackageForProfiles evaluates the snapshots once against the
// union of builtin controls mapped to any of the given profiles'
// frameworks, with evidence generation, and returns the evidence
// package. Shared by [Compliance] and [ComplianceMulti] so a
// multi-framework scorecard pays for a single evaluation. For a single
// profile the union is exactly that framework's controls, so
// [Compliance]'s result is unchanged by the refactor.
func evidencePackageForProfiles(ctx context.Context, snapshotsDir string, profiles []*coreevidence.FrameworkProfile) (*coreevidence.EvidencePackage, error) {
	allControls, err := builtinControls()
	if err != nil {
		return nil, err
	}
	wanted := make(map[policy.ComplianceFramework]bool, len(profiles))
	for _, p := range profiles {
		wanted[policy.ComplianceFramework(p.FrameworkKey)] = true
	}
	var controls []policy.ControlDefinition
	for i := range allControls {
		for fw := range wanted {
			if allControls[i].HasCompliance(fw) {
				controls = append(controls, allControls[i])
				break
			}
		}
	}

	snaps, err := loadSnapshots(ctx, snapshotsDir)
	if err != nil {
		return nil, err
	}

	celEval, err := cel.NewPredicateEval()
	if err != nil {
		return nil, fmt.Errorf("init CEL evaluator: %w", err)
	}

	report, err := appeval.Evaluate(ctx, appeval.EvaluateInput{
		Controls:         controls,
		Snapshots:        snaps,
		Clock:            ports.RealClock{},
		Hasher:           crypto.NewHasher(),
		StaveVersion:     version.String,
		PredicateParser:  ctlyaml.ParsePredicate,
		CELEvaluator:     celEval,
		GenerateEvidence: true,
	})
	if err != nil {
		return nil, fmt.Errorf("evaluate: %w", err)
	}
	if report.EvidencePackage == nil {
		return nil, errors.New("assessment did not produce evidence package")
	}
	return report.EvidencePackage, nil
}

// AvailableFrameworks returns the sorted IDs of the embedded
// compliance framework profiles (e.g. "hipaa", "pci_dss_v4.0",
// "cis_aws_v3.0"). Use it to enumerate every framework [Compliance]
// can evaluate — for example to build a multi-framework scorecard.
func AvailableFrameworks() []string {
	return availableProfileIDs()
}

// availableProfileIDs returns the sorted IDs of the embedded
// framework profiles, for the unknown-framework error message.
func availableProfileIDs() []string {
	profiles, err := evidenceadapter.LoadEmbeddedProfiles()
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(profiles))
	for _, p := range profiles {
		ids = append(ids, p.ID)
	}
	slices.Sort(ids)
	return ids
}
