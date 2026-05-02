// Package exportchanges extracts remediation property changes from
// assessment findings into a structured format for external tooling.
// Stave provides the data. External tools generate vendor-specific scripts.
package exportchanges

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// Change represents a single property change needed for remediation.
type Change struct {
	ControlID      string  `json:"control_id"`
	AssetID        string  `json:"asset_id"`
	AssetType      string  `json:"asset_type"`
	Severity       string  `json:"severity"`
	Confidence     float64 `json:"confidence"`
	PropertyPath   string  `json:"property_path"`
	CurrentValue   any     `json:"current_value"`
	RequiredValue  any     `json:"required_value"`
	HasSafeDefault bool    `json:"has_safe_default"`
	Vendor         string  `json:"vendor"`
	Service        string  `json:"service"`
	ResourceID     string  `json:"resource_id"`
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
				ControlID:      string(f.ControlID),
				AssetID:        string(f.AssetID),
				AssetType:      string(f.AssetType),
				Severity:       f.ControlSeverity.String(),
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
	parts := strings.SplitN(assetID, ":", 7)
	if len(parts) >= 3 && parts[0] == "arn" {
		vendor = parts[1]
		service = parts[2]
		if len(parts) >= 7 {
			resourceID = parts[6]
		} else if len(parts) >= 6 {
			resourceID = parts[5]
		}
		return vendor, service, resourceID
	}
	return "", "", assetID
}
