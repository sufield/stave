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

// UUID uniquely identifies an OSCAL entity.
type UUID string

func (u UUID) String() string { return string(u) }

// AssessmentResults is the top-level OSCAL document.
type AssessmentResults struct {
	AR ARContent `json:"assessment-results"`
}

// ARContent is the assessment-results content.
type ARContent struct {
	UUID     UUID       `json:"uuid"`
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

// ARFindings is a domain collection of ARFinding items with query methods.
type ARFindings []ARFinding

// Len returns the number of findings in the collection.
func (af ARFindings) Len() int {
	return len(af)
}

// ByControl returns a new ARFindings collection filtered by target control ID.
func (af ARFindings) ByControl(id kernel.ControlID) ARFindings {
	if len(af) == 0 {
		return nil
	}
	var filtered ARFindings
	for i := range af {
		if af[i].Target.TargetID == id {
			filtered = append(filtered, af[i])
		}
	}
	return filtered
}

// ARObservations is a domain collection of ARObservation items with query methods.
type ARObservations []ARObservation

// Len returns the number of observations in the collection.
func (ao ARObservations) Len() int {
	return len(ao)
}

// ARResult is one assessment result.
type ARResult struct {
	UUID         UUID           `json:"uuid"`
	Title        string         `json:"title"`
	Start        string         `json:"start"`
	End          string         `json:"end"`
	Findings     ARFindings     `json:"findings"`
	Observations ARObservations `json:"observations"`
}

// RelatedObservations represents a domain collection of RelObs items with query methods.
type RelatedObservations []RelObs

// Len returns the number of related observations in the collection.
func (ro RelatedObservations) Len() int {
	return len(ro)
}

// ContainsUUID reports whether an observation with the given UUID is present in the collection.
func (ro RelatedObservations) ContainsUUID(u UUID) bool {
	for i := range ro {
		if ro[i].ObservationUUID == u {
			return true
		}
	}
	return false
}

// ARFinding is a single OSCAL finding.
type ARFinding struct {
	UUID        UUID                `json:"uuid"`
	Title       string              `json:"title"`
	Description string              `json:"description,omitempty"`
	Target      ARTarget            `json:"target"`
	RelatedObs  RelatedObservations `json:"related-observations,omitempty"`
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
	ObservationUUID UUID `json:"observation-uuid"`
}

// Methods represents a domain collection of OSCAL examination method strings.
type Methods []string

// Len returns the number of methods.
func (m Methods) Len() int {
	return len(m)
}

// Contains reports whether the target method string is present in the collection.
func (m Methods) Contains(target string) bool {
	for _, item := range m {
		if item == target {
			return true
		}
	}
	return false
}

// ARSubjects is a domain collection of ARSubject items with query methods.
type ARSubjects []ARSubject

// Len returns the number of subjects in the collection.
func (as ARSubjects) Len() int {
	return len(as)
}

// ByAssetType returns a new ARSubjects collection filtered by target asset type.
func (as ARSubjects) ByAssetType(at kernel.AssetType) ARSubjects {
	if len(as) == 0 {
		return nil
	}
	var filtered ARSubjects
	for i := range as {
		if as[i].Type == at {
			filtered = append(filtered, as[i])
		}
	}
	return filtered
}

// ARObservation describes an observed asset.
type ARObservation struct {
	UUID        UUID       `json:"uuid"`
	Description string     `json:"description"`
	Methods     Methods    `json:"methods"`
	Subjects    ARSubjects `json:"subjects,omitempty"`
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
				SubjectUUID: asset.ID(string(uuidV5("component", string(f.AssetID)))),
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
func uuidV5(namespace, name string) UUID {
	h := sha256.Sum256([]byte(namespace + ":" + name))
	h[6] = (h[6] & 0x0f) | 0x50 // version 5
	h[8] = (h[8] & 0x3f) | 0x80 // variant rfc4122
	return UUID(fmt.Sprintf("%x-%x-%x-%x-%x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16]))
}
