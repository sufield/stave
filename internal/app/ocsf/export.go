// Package ocsf produces OCSF 1.1 Compliance Finding events from
// Stave assessment findings.
package ocsf

import (
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/util/strutil"
)

// ComplianceFinding is an OCSF 1.1 Compliance Finding (class_uid: 2003).
type ComplianceFinding struct {
	ClassUID   int            `json:"class_uid"`
	ClassName  string         `json:"class_name"`
	ActivityID int            `json:"activity_id"`
	SeverityID int            `json:"severity_id"`
	Severity   string         `json:"severity"`
	StatusID   int            `json:"status_id"`
	Status     string         `json:"status"`
	Finding    OCSFFinding    `json:"finding"`
	Compliance OCSFCompliance `json:"compliance"`
	Resources  []OCSFResource `json:"resources,omitempty"`
}

// OCSFFinding holds the finding details.
type OCSFFinding struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
	Desc  string `json:"desc,omitempty"`
}

// OCSFCompliance holds compliance context.
type OCSFCompliance struct {
	Requirements []string `json:"requirements,omitempty"`
	Control      string   `json:"control"`
	Status       string   `json:"status"`
}

// OCSFResource describes the affected resource.
type OCSFResource struct {
	UID  string `json:"uid"`
	Type string `json:"type"`
}

// Export converts Stave findings to OCSF Compliance Finding events.
func Export(findings []remediation.Finding) []ComplianceFinding {
	events := make([]ComplianceFinding, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		uid := string(f.ControlID) + ":" + string(f.AssetID)
		if f.AssetType != "" {
			uid = string(f.ControlID) + ":" + string(f.AssetType) + ":" + string(f.AssetID)
		}
		events = append(events, ComplianceFinding{
			ClassUID:   2003,
			ClassName:  "Compliance Finding",
			ActivityID: 1,
			SeverityID: sevID(f.SeverityLabel()),
			Severity:   strutil.TitleCase(f.SeverityLabel()),
			StatusID:   2,
			Status:     "New",
			Finding: OCSFFinding{
				UID:   uid,
				Title: f.ControlName,
			},
			Compliance: OCSFCompliance{
				Requirements: ccmRequirements(f.ControlCCMV4),
				Control:      string(f.ControlID),
				Status:       "FAILED",
			},
			Resources: []OCSFResource{
				{UID: string(f.AssetID), Type: string(f.AssetType)},
			},
		})
	}
	return events
}

// ccmRequirements renders CCM v4 control IDs as OCSF compliance
// requirement strings in the form "CCM:IAM-05" so consumers can filter
// by the framework prefix. Returns nil when there are no mappings so
// the field omits from JSON output.
func ccmRequirements(ccms []string) []string {
	if len(ccms) == 0 {
		return nil
	}
	out := make([]string, len(ccms))
	for i, id := range ccms {
		out[i] = "CCM:" + id
	}
	return out
}

func sevID(sev string) int {
	if strings.EqualFold(sev, "critical") {
		return 5
	}
	if strings.EqualFold(sev, "high") {
		return 4
	}
	if strings.EqualFold(sev, "medium") {
		return 3
	}
	if strings.EqualFold(sev, "low") {
		return 2
	}
	return 1
}
