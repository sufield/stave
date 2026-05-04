package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// Profile represents a validated evaluation profile.
type Profile string

const (
	// ProfileAWSS3 selects the AWS S3 evaluation profile.
	ProfileAWSS3 Profile = "aws-s3"
	// ProfileAWSIAM selects the AWS IAM identity security profile.
	ProfileAWSIAM Profile = "aws-iam"
	// ProfileGCPGCS selects the GCP Cloud Storage evaluation profile.
	ProfileGCPGCS Profile = "gcp-gcs"
	// ProfileHIPAA selects the HIPAA Security Rule evaluation profile.
	ProfileHIPAA Profile = "hipaa"
	// ProfileCISv3 selects the CIS AWS Foundations Benchmark v3.0 profile.
	ProfileCISv3 Profile = "cis-aws-v3.0"
	// ProfileSOC2 selects the SOC 2 Trust Service Criteria profile.
	ProfileSOC2 Profile = "soc2"
	// ProfilePCIDSSv4 selects the PCI-DSS v4.0 profile.
	ProfilePCIDSSv4 Profile = "pci-dss-v4.0"
	// ProfileNIST selects the NIST SP 800-53 Rev 5 profile.
	ProfileNIST Profile = "nist-800-53"
	// ProfileFedRAMP selects the FedRAMP Moderate baseline profile.
	ProfileFedRAMP Profile = "fedramp"
	// ProfileGDPR selects the GDPR compliance profile.
	ProfileGDPR Profile = "gdpr"
	// ProfileFFIEC selects the FFIEC compliance profile.
	ProfileFFIEC Profile = "ffiec"
	// ProfileISO27001 selects the ISO 27001:2022 profile.
	ProfileISO27001 Profile = "iso-27001"
	// ProfileNISTCSF selects the NIST CSF 2.0 profile.
	ProfileNISTCSF Profile = "nist-csf-2.0"
	// ProfileAWSEFS selects the AWS Elastic File System profile.
	ProfileAWSEFS Profile = "aws-efs"
)

// UsesPHIScope reports whether this profile keeps the default PHI
// audit scope. Only the AWS-S3 default profile does — every other
// profile (IAM/EFS/GCS/HIPAA/SOC2/CIS/PCI/NIST/FedRAMP/GDPR/FFIEC/
// ISO/NISTCSF) wants the global scope so PHIBoundary doesn't
// silently filter out IAM, VPC, KMS, and compute assets the
// profile must evaluate. Replaces the open-coded
// `cfg.Profile != ProfileAWSS3` probe in resolveScopeFilter.
func (p Profile) UsesPHIScope() bool {
	return p == ProfileAWSS3
}

// AssetTypeLabel returns the human-readable asset-type plural the
// "no assets matching scope" error message references. Centralised
// so the error string in filterSnapshots adapts to the profile —
// the previous hardcoded "S3 buckets" misled IAM / EFS / GCS / KMS
// operators when an empty filter result was about identities or
// EFS volumes, not buckets.
func (p Profile) AssetTypeLabel() string {
	switch p {
	case ProfileAWSS3:
		return "S3 buckets"
	case ProfileAWSIAM:
		return "IAM identities"
	case ProfileAWSEFS:
		return "EFS file systems"
	case ProfileGCPGCS:
		return "GCS buckets"
	}
	// Compliance profiles span multiple asset types; the message
	// generalises rather than enumerating.
	return "assets"
}

// ParseProfile validates and returns a Profile value.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileAWSS3, ProfileAWSIAM, ProfileAWSEFS, ProfileGCPGCS, ProfileHIPAA, ProfileCISv3, ProfileSOC2, ProfilePCIDSSv4, ProfileNIST, ProfileFedRAMP, ProfileGDPR, ProfileFFIEC, ProfileISO27001, ProfileNISTCSF:
		return Profile(s), nil
	default:
		return "", fmt.Errorf("unsupported --profile %q (supported: aws-s3, aws-iam, aws-efs, gcp-gcs, hipaa, cis-aws-v3.0, soc2, pci-dss-v4.0, nist-800-53, fedramp, gdpr, ffiec, iso-27001, nist-csf-2.0)", s)
	}
}

// ParseProfiles parses a comma-separated profile string into a slice.
// Supports multi-profile evaluation (e.g., "hipaa,soc2,pci-dss-v4.0").
func ParseProfiles(s string) ([]Profile, error) {
	parts := strings.Split(s, ",")
	profiles := make([]Profile, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		prof, err := ParseProfile(trimmed)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, prof)
	}
	if len(profiles) == 0 {
		return nil, errors.New("no valid profiles specified")
	}
	return profiles, nil
}

// Config holds the parameters for a profile-based apply operation.
type Config struct {
	InputFile string
	// Profile is the primary profile (kept for output labeling and
	// the AWS-S3 default-scope check). Profiles is the full list
	// when --profile is comma-separated; loadControlsMulti uses it
	// so all profiles' controls are evaluated, not just the first.
	Profile           Profile
	Profiles          []Profile
	BucketAllowlist   []string
	IncludeAll        bool
	MaxUnsafeDuration time.Duration
	OutputFormat      appcontracts.OutputFormat
	Quiet             bool
	Stdout            io.Writer
	Stderr            io.Writer
	Sanitizer         kernel.Sanitizer
}

// Runner handles the execution of the profile apply logic.
type Runner struct {
	Clock            ports.Clock
	Hasher           ports.Digester
	UI               *ui.Runtime
	NewCELEvaluator  compose.CELEvaluatorFactory
	LoadControls     compose.ControlLoaderFunc
	newFindingWriter compose.FindingWriterFactory
}

// RunnerOption configures optional Runner dependencies.
type RunnerOption func(*Runner)

// WithClock overrides the default wall clock.
func WithClock(c ports.Clock) RunnerOption {
	return func(r *Runner) { r.Clock = c }
}

// WithUI sets the UI runtime for progress and hints.
func WithUI(rt *ui.Runtime) RunnerOption {
	return func(r *Runner) { r.UI = rt }
}

// NewRunner initializes a runner with required factories and optional overrides.
func NewRunner(newCELEvaluator compose.CELEvaluatorFactory, loadControls compose.ControlLoaderFunc, newFindingWriter compose.FindingWriterFactory, opts ...RunnerOption) *Runner {
	r := &Runner{
		Hasher:           crypto.NewHasher(),
		NewCELEvaluator:  newCELEvaluator,
		LoadControls:     loadControls,
		newFindingWriter: newFindingWriter,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Run executes the profile evaluation workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	if err := validateInput(cfg.InputFile); err != nil {
		return err
	}

	snapshots, err := observations.LoadBundle(cfg.InputFile)
	if err != nil {
		return fmt.Errorf("load observation bundle: %w", err)
	}

	filtered := filterSnapshots(cfg.Stderr, cfg.Quiet, cfg, snapshots)
	if len(filtered) == 0 {
		return nil
	}

	// Use Profiles when populated (multi-profile path); fall back
	// to single-profile loadControls only if Profiles is empty
	// (callers that constructed Config by hand without going
	// through resolveProfileMode).
	profiles := cfg.Profiles
	if len(profiles) == 0 {
		profiles = []Profile{cfg.Profile}
	}
	ctlDir, controls, err := r.loadControlsMulti(ctx, profiles)
	if err != nil {
		return fmt.Errorf("load controls: %w", err)
	}

	celEval, err := r.NewCELEvaluator()
	if err != nil {
		return fmt.Errorf("init CEL evaluator: %w", err)
	}

	// Load chain definitions for risk reasoning.
	chainsDir := filepath.Join(getControlsBaseDir(), "..", "chains")
	chains, chainsErr := ctlyaml.LoadChains(chainsDir, capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}

	done := r.UI.BeginProgress("apply profile observations")
	defer done()

	result, err := appeval.EvaluateLoaded(ctx, appeval.EvaluationRequest{
		Controls:          controls,
		Snapshots:         filtered,
		MaxUnsafeDuration: cfg.MaxUnsafeDuration,
		Clock:             r.Clock,
		Hasher:            r.Hasher,
		StaveVersion:      version.String,
		PredicateParser:   ctlyaml.ParsePredicate,
		CELEvaluator:      celEval,
	})
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	// Enrich with risk reasoning (chains, attack stages, exposure ranking).
	appeval.EnrichReport(&result, controls, chains)

	if err := r.writeResults(ctx, cfg, &result, controls); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}

	return finalizeProfileEvaluation(cfg.Stderr, cfg.Quiet, &result, filtered, ctlDir, cfg.InputFile)
}

func validateInput(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ui.UserError{Err: fmt.Errorf("--input not found: %q", path)}
		}
		if os.IsPermission(err) {
			return &ui.UserError{Err: fmt.Errorf("--input not readable: %q (check file permissions)", path)}
		}
		return &ui.UserError{Err: fmt.Errorf("cannot access --input %q: %w", path, err)}
	}
	if fi.IsDir() {
		return &ui.UserError{Err: fmt.Errorf("--input must be a file, got directory: %q", path)}
	}
	return nil
}

func (r *Runner) loadControlsMulti(ctx context.Context, profiles []Profile) (string, []policy.ControlDefinition, error) {
	// Walk every profile's control domain so a multi-profile run
	// (e.g. --profile=hipaa,soc2,pci-dss-v4.0) sees the union of
	// available controls. The previous "use the first profile only"
	// shape silently dropped controls authored in any other domain
	// and the profile-side compliance filter would then have nothing
	// to match — multi-profile runs collapsed to their first
	// profile's domain content.
	base := getControlsBaseDir()
	seenDir := make(map[string]struct{})
	seenCtl := make(map[kernel.ControlID]struct{})
	var primaryDir string
	var controls []policy.ControlDefinition
	for _, prof := range profiles {
		domain := profileControlDomain(prof)
		dir := filepath.Join(base, domain)
		if primaryDir == "" {
			primaryDir = dir
		}
		if _, dup := seenDir[dir]; dup {
			continue
		}
		seenDir[dir] = struct{}{}
		loaded, err := r.LoadControls(ctx, dir)
		if err != nil {
			return "", nil, err
		}
		// Dedup by ControlID — the same control can live under
		// multiple framework directories during the migration to
		// per-profile catalogues, and a duplicate would inflate
		// finding counts in the assessment summary.
		for i := range loaded {
			id := loaded[i].ID
			if _, dup := seenCtl[id]; dup {
				continue
			}
			seenCtl[id] = struct{}{}
			controls = append(controls, loaded[i])
		}
	}
	ctlDir := primaryDir

	// Collect compliance frameworks from all profiles.
	var frameworks []policy.ComplianceFramework
	for _, prof := range profiles {
		if fw := profileComplianceFramework(prof); fw != "" {
			frameworks = append(frameworks, fw)
		}
	}

	// Filter: union across all requested frameworks.
	if len(frameworks) == 1 {
		controls = filterByCompliance(controls, frameworks[0])
	} else if len(frameworks) > 1 {
		controls = filterByComplianceUnion(controls, frameworks)
	}

	if len(controls) == 0 {
		label := profileControlDomain(profiles[0])
		if label == "" {
			var names []string
			for _, p := range profiles {
				names = append(names, string(p))
			}
			label = strings.Join(names, ",")
		}
		return "", nil, fmt.Errorf("%w: no %s controls found in %s", appeval.ErrNoControls, label, ctlDir)
	}

	return ctlDir, controls, nil
}

// profileControlDomain maps a profile to its control subdirectory.
// Returns empty string for cross-domain profiles (e.g. HIPAA).
func profileControlDomain(prof Profile) string {
	switch prof {
	case ProfileAWSIAM:
		return "iam"
	case ProfileAWSEFS:
		return "efs"
	case ProfileGCPGCS:
		return "gcs"
	case ProfileHIPAA, ProfileCISv3, ProfileSOC2, ProfilePCIDSSv4, ProfileNIST, ProfileFedRAMP, ProfileGDPR, ProfileFFIEC, ProfileISO27001, ProfileNISTCSF:
		return "" // Cross-domain: loads all, filtered by compliance ref.
	default:
		return "s3"
	}
}

// profileComplianceFramework returns the compliance framework key used to
// filter controls for compliance-based profiles. Returns empty for
// domain-scoped profiles that load all controls from their directory.
func profileComplianceFramework(prof Profile) policy.ComplianceFramework {
	switch prof {
	case ProfileHIPAA:
		return "hipaa"
	case ProfileCISv3:
		return "cis_aws_v3.0"
	case ProfileSOC2:
		return "soc2"
	case ProfilePCIDSSv4:
		return "pci_dss_v4.0"
	case ProfileNIST:
		return "nist_800_53_r5"
	case ProfileFedRAMP:
		return "fedramp_moderate"
	case ProfileGDPR:
		return "gdpr"
	case ProfileFFIEC:
		return "ffiec"
	case ProfileISO27001:
		return "iso_27001_2022"
	case ProfileNISTCSF:
		return "nist_csf_2.0"
	default:
		return ""
	}
}

func filterByCompliance(controls []policy.ControlDefinition, fw policy.ComplianceFramework) []policy.ControlDefinition {
	filtered := make([]policy.ControlDefinition, 0, len(controls))
	for i := range controls {
		if controls[i].HasCompliance(fw) {
			filtered = append(filtered, controls[i])
		}
	}
	return filtered
}

// filterByComplianceUnion returns controls that match ANY of the given frameworks.
// Controls are deduplicated by ID — a control appearing in multiple frameworks
// is included once with all its compliance citations intact.
func filterByComplianceUnion(controls []policy.ControlDefinition, frameworks []policy.ComplianceFramework) []policy.ControlDefinition {
	fwSet := make(map[policy.ComplianceFramework]bool, len(frameworks))
	for _, fw := range frameworks {
		fwSet[fw] = true
	}

	filtered := make([]policy.ControlDefinition, 0, len(controls))
	seen := make(map[kernel.ControlID]bool)
	for i := range controls {
		ctl := &controls[i]
		if seen[ctl.ID] {
			continue
		}
		for fw := range ctl.Compliance {
			if fwSet[fw] {
				filtered = append(filtered, *ctl)
				seen[ctl.ID] = true
				break
			}
		}
	}
	return filtered
}

func getControlsBaseDir() string {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exe), "controls")
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			return dir
		}
	}
	return "controls"
}
