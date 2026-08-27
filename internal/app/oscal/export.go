// Package oscal produces OSCAL 1.1.2 Assessment Results JSON from
// Stave assessment findings.
package oscal

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// AssessmentResults is the top-level OSCAL document.
type AssessmentResults struct {
	AR ARContent `json:"assessment-results"`
}

// ARContent is the assessment-results content.
type ARContent struct {
	UUID     string     `json:"uuid"`
	Metadata ARMetadata `json:"metadata"`
	ImportAP ImportAP   `json:"import-ap"`
	Results  []ARResult `json:"results"`
}

// ARMetadata holds OSCAL metadata.
type ARMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

// ImportAP references the assessment plan.
type ImportAP struct {
	Href string `json:"href"`
}

// ARResult is one assessment result.
type ARResult struct {
	UUID         string          `json:"uuid"`
	Title        string          `json:"title"`
	Start        string          `json:"start"`
	End          string          `json:"end"`
	Findings     []ARFinding     `json:"findings"`
	Observations []ARObservation `json:"observations"`
}

// ARFinding is a single OSCAL finding.
type ARFinding struct {
	UUID        string   `json:"uuid"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Target      ARTarget `json:"target"`
	RelatedObs  []RelObs `json:"related-observations,omitempty"`
}

// ARTarget describes what was evaluated.
type ARTarget struct {
	Type     string           `json:"type"`
	TargetID kernel.ControlID `json:"target-id"`
	Status   ARStatus         `json:"status"`
}

// ARStatus holds the finding status.
type ARStatus struct {
	State string `json:"state"`
}

// RelObs references a related observation.
type RelObs struct {
	ObservationUUID string `json:"observation-uuid"`
}

// ARObservation describes an observed asset.
type ARObservation struct {
	UUID        string      `json:"uuid"`
	Description string      `json:"description"`
	Methods     []string    `json:"methods"`
	Subjects    []ARSubject `json:"subjects,omitempty"`
}

// ARSubject identifies the observed component.
type ARSubject struct {
	Type        kernel.AssetType `json:"type"`
	SubjectUUID asset.ID         `json:"subject-uuid"`
	Title       string           `json:"title"`
}

// Export converts Stave findings to OSCAL Assessment Results.
func Export(findings []remediation.Finding, generatedAt time.Time) *AssessmentResults {
	now := generatedAt.Format(time.RFC3339)
	resultUUID := uuidV5("stave-result", now)

	var oscalFindings []ARFinding
	var observations []ARObservation

	for i := range findings {
		f := &findings[i]
		findingID := string(f.ControlID) + ":" + string(f.AssetID)
		if f.AssetType != "" {
			findingID = string(f.ControlID) + ":" + string(f.AssetType) + ":" + string(f.AssetID)
		}
		findingUUID := uuidV5("finding", findingID)
		obsUUID := uuidV5("observation", findingID)

		state := "not-satisfied"

		oscalFindings = append(oscalFindings, ARFinding{
			UUID:        findingUUID,
			Title:       string(f.ControlID),
			Description: f.ControlName,
			Target: ARTarget{
				Type:     "objective-id",
				TargetID: f.ControlID,
				Status:   ARStatus{State: state},
			},
			RelatedObs: []RelObs{{ObservationUUID: obsUUID}},
		})

		observations = append(observations, ARObservation{
			UUID:        obsUUID,
			Description: "Asset: " + string(f.AssetID),
			Methods:     []string{"EXAMINE"},
			Subjects: []ARSubject{{
				Type:        kernel.AssetType("component"),
				SubjectUUID: asset.ID(uuidV5("component", string(f.AssetID))),
				Title:       string(f.AssetID),
			}},
		})
	}

	return &AssessmentResults{
		AR: ARContent{
			UUID: uuidV5("assessment", now),
			Metadata: ARMetadata{
				Title:        "Stave Assessment Results",
				LastModified: now,
				Version:      "1.0",
				OSCALVersion: "1.1.2",
			},
			ImportAP: ImportAP{Href: "#"},
			Results: []ARResult{{
				UUID:         resultUUID,
				Title:        "Assessment",
				Start:        now,
				End:          now,
				Findings:     oscalFindings,
				Observations: observations,
			}},
		},
	}
}

// uuidV5 generates a deterministic UUID from a namespace and name
// using SHA-256 truncated to UUID format.
func uuidV5(namespace, name string) string {
	h := sha256.Sum256([]byte(namespace + ":" + name))
	h[6] = (h[6] & 0x0f) | 0x50 // version 5
	h[8] = (h[8] & 0x3f) | 0x80 // variant rfc4122
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
