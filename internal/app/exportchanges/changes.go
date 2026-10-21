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

// ConfidenceScore represents remediation confidence score in [0.0, 1.0].
type ConfidenceScore float64

// Float64 returns the raw float64 value.
func (c ConfidenceScore) Float64() float64 {
	return float64(c)
}

// IsHigh reports whether the confidence score meets or exceeds 0.8.
func (c ConfidenceScore) IsHigh() bool {
	return c >= 0.8
}

// IsSufficient reports whether the confidence score meets or exceeds the required threshold.
func (c ConfidenceScore) IsSufficient(threshold ConfidenceScore) bool {
	return c >= threshold
}

// IsZero reports whether confidence score is zero.
func (c ConfidenceScore) IsZero() bool {
	return c == 0
}

// Change represents a single property change needed for remediation.
type Change struct {
	ControlID      kernel.ControlID `json:"control_id"`
	AssetID        asset.ID         `json:"asset_id"`
	AssetType      kernel.AssetType `json:"asset_type"`
	Severity       policy.Severity  `json:"severity"`
	Confidence     ConfidenceScore  `json:"confidence"`
	PropertyPath   string           `json:"property_path"`
	CurrentValue   any              `json:"current_value"`
	RequiredValue  any              `json:"required_value"`
	HasSafeDefault bool             `json:"has_safe_default"`
	Vendor         kernel.Vendor    `json:"vendor"`
	Service        string           `json:"service"`
	ResourceID     string           `json:"resource_id"`
}

// Changes is a domain collection of Change items with query and filter methods.
type Changes []Change

// Len returns the number of changes in the collection.
func (cs Changes) Len() int {
	return len(cs)
}

// Report holds the exported changes.
type Report struct {
	GeneratedAt string  `json:"generated_at"`
	Changes     Changes `json:"changes"`
}

// FindingList is a domain collection of remediation.Finding items with query methods.
type FindingList []remediation.Finding

// Len returns the count of findings in the collection.
func (fl FindingList) Len() int {
	return len(fl)
}

// Input configures the export.
type Input struct {
	Findings      FindingList
	MinConfidence ConfidenceScore
	GeneratedAt   string
}

// Export extracts remediation changes from findings.
func Export(in Input) *Report {
	report := &Report{GeneratedAt: in.GeneratedAt}

	for i := range in.Findings {
		f := &in.Findings[i]
		for _, pc := range f.RemediationSpec.Changes {
			confidence := ConfidenceScore(f.RemediationSpec.Confidence)
			if !confidence.IsSufficient(in.MinConfidence) {
				continue
			}

			vendor, service, resourceID := parseAssetID(f.AssetID)

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

func parseAssetID(assetID asset.ID) (vendor kernel.Vendor, service, resourceID string) {
	rawID := assetID.String()
	// Parse ARN: arn:aws:s3:::bucket-name
	if !strings.HasPrefix(rawID, "arn:") {
		return "", "", rawID
	}
	remaining := rawID[4:] // skip "arn:"
	var found bool
	var vendorStr string

	// segment 1: partition (vendor)
	vendorStr, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return kernel.Vendor(vendorStr), "", ""
	}

	// segment 2: service
	service, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return kernel.Vendor(vendorStr), service, ""
	}

	// segment 3: region
	_, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return kernel.Vendor(vendorStr), service, ""
	}

	// segment 4: account-id
	_, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return kernel.Vendor(vendorStr), service, ""
	}

	// segment 5: resource-type or resource-id
	var part5 string
	part5, remaining, found = strings.Cut(remaining, ":")
	if !found {
		return kernel.Vendor(vendorStr), service, part5
	}

	// segment 6: resource-id (if there is a 6th colon)
	return kernel.Vendor(vendorStr), service, part5 + ":" + remaining
}
