package sla

import (
	"context"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

// Provider implements appcontracts.SLAProvider over the embedded and
// file-system SLA policy loaders. File path takes precedence over profile
// name when both are set; both empty returns (nil, nil) — the caller
// treats absent SLA config as "no SLA configured".
type Provider struct{}

// NewProvider returns the standard SLA provider.
func NewProvider() *Provider { return &Provider{} }

var _ appcontracts.SLAProvider = (*Provider)(nil)

// LoadSLAConfig resolves an SLA policy from a file path or an embedded
// profile and converts it into the engine-facing evaluation.SLAConfig.
//
// The file-precedence rule is centralized here so cmd/apply, cmd/report,
// and any future caller share a single resolution path — see Tier 1
// remediation in coderabbit/7.md.
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
		return nil, nil
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
