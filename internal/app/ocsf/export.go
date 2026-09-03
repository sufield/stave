// Package ocsf produces OCSF 1.1 Compliance Finding events from
// Stave assessment findings.
package ocsf

import (
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/strutil"
)

// ClassUID classifies the OCSF event class (2003 = Compliance Finding).
type ClassUID int

const ClassComplianceFinding ClassUID = 2003

// ActivityID classifies the OCSF activity (1 = Create).
type ActivityID int

const ActivityCreate ActivityID = 1

// SeverityID maps Stave severities to OCSF 1.1 severity numbers (1-5).
type SeverityID int

const (
	SeverityIDUnknown  SeverityID = 1
	SeverityIDLow      SeverityID = 2
	SeverityIDMedium   SeverityID = 3
	SeverityIDHigh     SeverityID = 4
	SeverityIDCritical SeverityID = 5
)

// StatusID classifies OCSF finding status (1 = New).
type StatusID int

const StatusIDNew StatusID = 1

// ComplianceFinding is an OCSF 1.1 Compliance Finding (class_uid: 2003).
type ComplianceFinding struct {
	ClassUID   ClassUID       `json:"class_uid"`
	ClassName  string         `json:"class_name"`
	ActivityID ActivityID     `json:"activity_id"`
	SeverityID SeverityID     `json:"severity_id"`
	Severity   string         `json:"severity"`
	StatusID   StatusID       `json:"status_id"`
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
	Requirements []string         `json:"requirements,omitempty"`
	Control      kernel.ControlID `json:"control"`
	Status       string           `json:"status"`
}

// OCSFResource describes the affected resource.
type OCSFResource struct {
	UID  asset.ID         `json:"uid"`
	Type kernel.AssetType `json:"type"`
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
			ClassUID:   ClassComplianceFinding,
			ClassName:  "Compliance Finding",
			ActivityID: ActivityCreate,
			SeverityID: sevID(f.SeverityLabel()),
			Severity:   strutil.TitleCase(f.SeverityLabel()),
			StatusID:   StatusIDNew,
			Status:     "New",
			Finding: OCSFFinding{
				UID:   uid,
				Title: f.ControlName,
			},
			Compliance: OCSFCompliance{
				Requirements: ccmRequirements(f.ControlCCMV4),
				Control:      f.ControlID,
				Status:       "FAILED",
			},
			Resources: []OCSFResource{
				{UID: f.AssetID, Type: f.AssetType},
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

func sevID(sev string) SeverityID {
	if strings.EqualFold(sev, "critical") {
		return SeverityIDCritical
	}
	if strings.EqualFold(sev, "high") {
		return SeverityIDHigh
	}
	if strings.EqualFold(sev, "medium") {
		return SeverityIDMedium
	}
	if strings.EqualFold(sev, "low") {
		return SeverityIDLow
	}
	return SeverityIDUnknown
}
