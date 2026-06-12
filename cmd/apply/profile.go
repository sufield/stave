package apply

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// Profile represents a validated evaluation profile. The type + name parsing
// stay command-side for flag validation; the evaluation pipeline lives in the
// pkg/stave facade (stave.EvaluateProfile).
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

// Config holds the resolved parameters for a profile-based apply operation.
// Flag string parsing happens in resolveProfileMode; the evaluation itself
// runs in the pkg/stave facade.
type Config struct {
	InputFile         string
	Profile           Profile // primary profile, for output labeling
	Profiles          []Profile
	BucketAllowlist   []string
	IncludeAll        bool
	MaxUnsafeDuration time.Duration
	OutputFormat      appcontracts.OutputFormat
	Quiet             bool
	Stdout            io.Writer
	Stderr            io.Writer
	NowTime           string // RFC3339 or "" — the facade builds the clock
}

// runProfile drives profile-based evaluation through the pkg/stave facade.
// It owns the progress runtime, the stdout/stderr writes, and exit-code
// routing; the load -> evaluate -> render pipeline is in stave.EvaluateProfile.
func runProfile(ctx context.Context, cs cobraState, cfg RunConfig) error {
	p := cfg.Profile

	names := make([]string, len(p.Profiles))
	for i, pr := range p.Profiles {
		names[i] = string(pr)
	}

	rt := ui.NewRuntime(cs.Stdout, cs.Stderr)
	rt.Quiet = p.Quiet
	done := rt.BeginProgress("apply profile observations")
	res, err := stave.EvaluateProfile(ctx, stave.ProfileRequest{
		InputFile:       p.InputFile,
		Profiles:        names,
		BucketAllowlist: p.BucketAllowlist,
		IncludeAll:      p.IncludeAll,
		MaxUnsafe:       p.MaxUnsafeDuration,
		Format:          string(p.OutputFormat),
		Now:             p.NowTime,
		SanitizeIDs:     cs.GlobalFlags.Sanitize,
		PathMode:        string(cs.GlobalFlags.PathMode),
	})
	done()

	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
	}

	if _, werr := p.Stdout.Write(res.Output); werr != nil {
		return fmt.Errorf("write profile output: %w", werr)
	}

	if !p.Quiet {
		for _, w := range res.Warnings {
			fmt.Fprintln(p.Stderr, w)
		}
		if res.DiagnoseHint != "" {
			ui.WriteHint(p.Stderr, res.DiagnoseHint)
		}
	}

	if res.HasViolations {
		return ui.ErrViolationsFound
	}
	return nil
}
