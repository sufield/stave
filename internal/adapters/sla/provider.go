package sla

import (
	"context"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

// Provider implements appcontracts.SLAProvider over the embedded and
// file-system SLA policy loaders. File path takes precedence over profile
// name when both are set; both empty falls back to the embedded "default"
// profile so adopters get severity-keyed SLA evaluation out of the box
// without having to discover the --sla-profile flag.
type Provider struct{}

// NewProvider returns the standard SLA provider.
func NewProvider() *Provider { return &Provider{} }

var _ appcontracts.SLAProvider = (*Provider)(nil)

// DefaultProfileID is the embedded SLA profile used when neither
// --sla-profile nor --sla-profile-file is set. Keeps the previously-
// optional severity-keyed SLA evaluation on by default; the deadlines
// live in internal/adapters/sla/embedded/default.yaml.
const DefaultProfileID = "default"

// LoadSLAConfig resolves an SLA policy from a file path or an embedded
// profile and converts it into the engine-facing evaluation.SLAConfig.
//
// The file-precedence rule is centralized here so cmd/apply, cmd/report,
// and any future caller share a single resolution path — see Tier 1
// remediation in coderabbit/7.md. When both inputs are empty, the
// DefaultProfileID is loaded so the caller still gets a fully-populated
// SLAConfig with industry-norm deadlines.
func (p *Provider) LoadSLAConfig(_ context.Context, profileID, filePath string) (*evaluation.SLAConfig, error) {
	var pol *Policy
	switch {
	case filePath != "":
		loaded, err := LoadFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("load sla profile file: %w", err)
		}
		pol = loaded
	case profileID != "":
		loaded, err := LoadEmbedded(profileID)
		if err != nil {
			return nil, fmt.Errorf("load sla profile: %w", err)
		}
		pol = loaded
	default:
		// Neither flag supplied — fall back to the embedded "default"
		// profile (Temporal Iteration 1, Gap E). Loading must always
		// succeed because the file ships with the binary; an error here
		// is a build-time embed-directive failure, surface it as such.
		loaded, err := LoadEmbedded(DefaultProfileID)
		if err != nil {
			return nil, fmt.Errorf("load embedded default sla profile: %w", err)
		}
		pol = loaded
	}

	return &evaluation.SLAConfig{
		ProfileID: pol.ID,
		DeadlineBySeverity: map[string]float64{
			"critical": pol.DeadlineHoursFor("critical"),
			"high":     pol.DeadlineHoursFor("high"),
			"medium":   pol.DeadlineHoursFor("medium"),
			"low":      pol.DeadlineHoursFor("low"),
		},
		EscalationFactor: pol.EscalationFactor,
	}, nil
}
