package applycmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	covadapter "github.com/sufield/stave/internal/adapters/coverage"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	corecov "github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/kernel"
)

// Profile is a validated evaluation-profile name.
type Profile string

const (
	ProfileAWSS3    Profile = "aws-s3"
	ProfileAWSIAM   Profile = "aws-iam"
	ProfileGCPGCS   Profile = "gcp-gcs"
	ProfileHIPAA    Profile = "hipaa"
	ProfileCISv3    Profile = "cis-aws-v3.0"
	ProfileSOC2     Profile = "soc2"
	ProfilePCIDSSv4 Profile = "pci-dss-v4.0"
	ProfileNIST     Profile = "nist-800-53"
	ProfileFedRAMP  Profile = "fedramp"
	ProfileGDPR     Profile = "gdpr"
	ProfileFFIEC    Profile = "ffiec"
	ProfileISO27001 Profile = "iso-27001"
	ProfileNISTCSF  Profile = "nist-csf-2.0"
	ProfileAWSEFS   Profile = "aws-efs"
)

// UsesPHIScope reports whether this profile keeps the PHI audit scope. Only
// AWS-S3 does; every other profile uses the global scope so PHIBoundary
// doesn't filter out IAM/VPC/KMS/compute assets the profile must evaluate.
func (p Profile) UsesPHIScope() bool { return p == ProfileAWSS3 }

// AssetTypeLabel returns the asset-type plural the "no assets matching scope"
// message references, so the message adapts per profile.
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
	return "assets"
}

// parseProfileNames maps validated profile-name strings to Profile values.
// The command validates the names (ParseProfiles) before constructing the
// request, so this trusts them.
func parseProfileNames(names []string) []Profile {
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		out = append(out, Profile(n))
	}
	return out
}

func primaryProfile(profiles []Profile) Profile {
	if len(profiles) == 0 {
		return ProfileAWSS3
	}
	return profiles[0]
}

func resolveScopeFilter(primary Profile, includeAll bool, allowlist []string) *asset.AuditScope {
	if includeAll {
		return asset.GetGlobalScope()
	}
	if len(allowlist) > 0 {
		return asset.NewAuditScopeFromAllowlist(allowlist)
	}
	if !primary.UsesPHIScope() {
		return asset.GetGlobalScope()
	}
	return asset.PHIBoundary()
}

// filterSnapshots applies the scope filter and returns the kept snapshots
// plus any operator warnings (the command writes them to stderr, quiet-gated).
func filterSnapshots(primary Profile, req ProfileRequest, snapshots []asset.Snapshot) ([]asset.Snapshot, []string) {
	if len(snapshots) == 0 {
		return nil, []string{"No snapshots in observations file"}
	}
	scopeFilter := resolveScopeFilter(primary, req.IncludeAll, req.BucketAllowlist)
	filtered := asset.ApplyScopeToSnapshots(scopeFilter, snapshots)
	if len(filtered) == 0 {
		return nil, []string{fmt.Sprintf("No %s matching configured scope found in observations", primary.AssetTypeLabel())}
	}
	return filtered, nil
}

func loadControlsMulti(ctx context.Context, profiles []Profile) (string, []policy.ControlDefinition, error) {
	base := getControlsBaseDir()
	_, statErr := os.Stat(base)
	useEmbedded := statErr != nil

	seenDir := make(map[string]struct{})
	seenCtl := make(map[kernel.ControlID]struct{})
	var primaryDir string
	var controls []policy.ControlDefinition
	for _, prof := range profiles {
		domain := profileControlDomain(prof)
		var dir string
		if useEmbedded {
			dir = "embedded"
			if domain != "" {
				dir = filepath.Join("embedded", domain)
			}
		} else {
			dir = filepath.Join(base, domain)
		}
		if primaryDir == "" {
			primaryDir = dir
		}
		if _, dup := seenDir[dir]; dup {
			continue
		}
		seenDir[dir] = struct{}{}
		var loaded []policy.ControlDefinition
		var err error
		if useEmbedded {
			store := ctlbuiltin.NewControlStore(
				ctlbuiltin.EmbeddedFS(), dir,
				ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc()),
			)
			loaded, err = store.All()
		} else {
			loader := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(builtinpredicate.ResolverFunc()))
			loaded, err = loader.LoadControls(ctx, dir)
		}
		if err != nil {
			return "", nil, fmt.Errorf("load controls from %s: %w", dir, err)
		}
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

	var frameworks []policy.ComplianceFramework
	for _, prof := range profiles {
		if fw := profileComplianceFramework(prof); fw != "" {
			frameworks = append(frameworks, fw)
		}
	}
	if len(frameworks) == 1 {
		controls = filterByCompliance(controls, frameworks[0])
	} else if len(frameworks) > 1 {
		controls = filterByComplianceUnion(controls, frameworks)
	}

	if len(controls) == 0 {
		label := profileControlDomain(profiles[0])
		if label == "" {
			names := make([]string, 0, len(profiles))
			for _, p := range profiles {
				names = append(names, string(p))
			}
			label = strings.Join(names, ",")
		}
		return "", nil, fmt.Errorf("%w: no %s controls found in %s", appeval.ErrNoControls, label, ctlDir)
	}
	return ctlDir, controls, nil
}

func profileControlDomain(prof Profile) string {
	switch prof {
	case ProfileAWSIAM:
		return "iam"
	case ProfileAWSEFS:
		return "efs"
	case ProfileGCPGCS:
		return "gcs"
	case ProfileHIPAA, ProfileCISv3, ProfileSOC2, ProfilePCIDSSv4, ProfileNIST, ProfileFedRAMP, ProfileGDPR, ProfileFFIEC, ProfileISO27001, ProfileNISTCSF:
		return ""
	default:
		return "s3"
	}
}

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

func filterByComplianceUnion(controls []policy.ControlDefinition, frameworks []policy.ComplianceFramework) []policy.ControlDefinition {
	fwSet := make(map[policy.ComplianceFramework]struct{}, len(frameworks))
	for _, fw := range frameworks {
		fwSet[fw] = struct{}{}
	}
	filtered := make([]policy.ControlDefinition, 0, len(controls))
	seen := make(map[kernel.ControlID]struct{})
	for i := range controls {
		ctl := &controls[i]
		if _, ok := seen[ctl.ID]; ok {
			continue
		}
		for fw := range ctl.Compliance {
			if _, ok := fwSet[fw]; ok {
				filtered = append(filtered, *ctl)
				seen[ctl.ID] = struct{}{}
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

func getChainsDir() string {
	for _, candidate := range []string{"chains", "internal/chains"} {
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
	}
	return "chains"
}

// latestSnapshotSource returns the origin context of the most recent
// snapshot, defaulting to "deployed".
func latestSnapshotSource(snapshots []asset.Snapshot) asset.SnapshotSource {
	source := asset.SourceDeployed
	var latest time.Time
	for i := range snapshots {
		if s := snapshots[i].Source; s != "" && !snapshots[i].CapturedAt.Before(latest) {
			source = s
			latest = snapshots[i].CapturedAt
		}
	}
	return source
}

// buildCoveragePosture loads the embedded alternative-tool inventories and
// aggregates them with the active controls into a CoverageIndex.
func buildCoveragePosture(controls []policy.ControlDefinition, logger *slog.Logger) *corecov.CoverageIndex {
	if len(controls) == 0 {
		return nil
	}
	inventories, err := covadapter.LoadEmbedded()
	if err != nil {
		if logger != nil {
			logger.Warn("coverage posture disabled: inventory load failed", "error", err)
		}
		return nil
	}
	idx := corecov.BuildCoverageIndex(controls, inventories)
	if len(idx.ByTool) == 0 {
		return nil
	}
	return &idx
}
