// Package exportchanges extracts remediation property changes from
// assessment findings into a structured format for external tooling.
// Stave provides the data. External tools generate vendor-specific scripts.
package exportchanges

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Change represents a single property change needed for remediation.
type Change struct {
	ControlID      kernel.ControlID `json:"control_id"`
	AssetID        asset.ID         `json:"asset_id"`
	AssetType      kernel.AssetType `json:"asset_type"`
	Severity       policy.Severity  `json:"severity"`
	Confidence     float64          `json:"confidence"`
	PropertyPath   string           `json:"property_path"`
	CurrentValue   any              `json:"current_value"`
	RequiredValue  any              `json:"required_value"`
	HasSafeDefault bool             `json:"has_safe_default"`
	Vendor         string           `json:"vendor"`
	Service        string           `json:"service"`
	ResourceID     string           `json:"resource_id"`
}

// Report holds the exported changes.
type Report struct {
	GeneratedAt string   `json:"generated_at"`
	Changes     []Change `json:"changes"`
}

// Input configures the export.
type Input struct {
	Findings      []remediation.Finding
	MinConfidence float64
	GeneratedAt   string
}

// Export extracts remediation changes from findings.
func Export(in Input) *Report {
	report := &Report{GeneratedAt: in.GeneratedAt}

	for i := range in.Findings {
		f := &in.Findings[i]
		for _, pc := range f.RemediationSpec.Changes {
			confidence := f.RemediationSpec.Confidence
			if confidence < in.MinConfidence {
				continue
			}

			vendor, service, resourceID := parseAssetID(string(f.AssetID))

			report.Changes = append(report.Changes, Change{
				ControlID:      f.ControlID,
				AssetID:        f.AssetID,
				AssetType:      f.AssetType,
				Severity:       f.ControlSeverity,
				Confidence:     confidence,
				PropertyPath:   pc.PropertyPath,
				CurrentValue:   pc.CurrentValue,
				RequiredValue:  pc.RequiredValue,
				HasSafeDefault: pc.HasSafeDefault,
				Vendor:         vendor,
				Service:        service,
				ResourceID:     resourceID,
			})
		}
	}

	return report
}

func parseAssetID(assetID string) (vendor, service, resourceID string) {
	// Parse ARN: arn:aws:s3:::bucket-name
	if !strings.HasPrefix(assetID, "arn:") {
		return "", "", assetID
	}
	remaining := assetID[4:] // skip "arn:"
	var found bool

	// segment 1: partition (vendor)
	vendor, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return vendor, "", ""
	}

	// segment 2: service
	service, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return vendor, service, ""
	}

	// segment 3: region
	_, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return vendor, service, ""
	}

	// segment 4: account-id
	_, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return vendor, service, ""
	}

	// segment 5: resource-type or resource-id
	var part5 string
	part5, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return vendor, service, part5
	}

	// segment 6: resource-id (if there is a 6th colon)
	return vendor, service, part5 + ":" + remaining
}
