package compliance

import (
	"crypto/sha1" //nolint:gosec // UUID v5 requires SHA-1 per RFC 4122
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/version"
)

// OSCAL Assessment Results types per NIST OSCAL 1.1.2 schema.

type oscalDocument struct {
	AssessmentResults oscalAssessmentResults `json:"assessment-results"`
}

type oscalAssessmentResults struct {
	UUID             string          `json:"uuid"`
	Metadata         oscalMetadata   `json:"metadata"`
	ImportAP         oscalImportAP   `json:"import-ap"`
	LocalDefinitions *oscalLocalDefs `json:"local-definitions,omitempty"`
	Results          []oscalResult   `json:"results"`
}

type oscalMetadata struct {
	Title        string       `json:"title"`
	LastModified string       `json:"last-modified"`
	Version      string       `json:"version"`
	OsCalVersion string       `json:"oscal-version"`
	Parties      []oscalParty `json:"parties"`
}

type oscalParty struct {
	UUID string `json:"uuid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type oscalImportAP struct {
	Href string `json:"href"`
}

type oscalLocalDefs struct {
	Activities []oscalActivity `json:"activities,omitempty"`
}

type oscalActivity struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

type oscalResult struct {
	UUID             string                `json:"uuid"`
	Title            string                `json:"title"`
	Description      string                `json:"description"`
	Start            string                `json:"start"`
	End              string                `json:"end"`
	ReviewedControls oscalReviewedControls `json:"reviewed-controls"`
	Findings         []oscalFinding        `json:"findings"`
	Observations     []oscalObservation    `json:"observations"`
}

type oscalReviewedControls struct {
	ControlSelections []oscalControlSelection `json:"control-selections"`
}

type oscalControlSelection struct {
	Description     string               `json:"description"`
	IncludeControls []oscalControlSelect `json:"include-controls"`
}

type oscalControlSelect struct {
	ControlID string `json:"control-id"`
}

type oscalFinding struct {
	UUID                string        `json:"uuid"`
	Title               string        `json:"title"`
	Description         string        `json:"description"`
	Target              oscalTarget   `json:"target"`
	RelatedObservations []oscalObsRef `json:"related-observations,omitempty"`
}

type oscalTarget struct {
	Type     string      `json:"type"`
	TargetID string      `json:"target-id"`
	Status   oscalStatus `json:"status"`
}

type oscalStatus struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type oscalObsRef struct {
	ObservationUUID string `json:"observation-uuid"`
}

type oscalObservation struct {
	UUID             string          `json:"uuid"`
	Title            string          `json:"title"`
	Description      string          `json:"description"`
	Methods          []string        `json:"methods"`
	Types            []string        `json:"types"`
	Collected        string          `json:"collected"`
	RelevantEvidence []oscalEvidence `json:"relevant-evidence,omitempty"`
}

type oscalEvidence struct {
	Description string      `json:"description"`
	Props       []oscalProp `json:"props,omitempty"`
}

type oscalProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// renderOSCAL produces an OSCAL 1.1.2 Assessment Results JSON document.
func renderOSCAL(
	w io.Writer,
	opts *options,
	profiles []*evidence.FrameworkProfile,
	assessments []*evidence.ProfileAssessment,
	pkg *evidence.EvidencePackage,
	snapshotTime time.Time,
) error {
	now := time.Now().UTC()

	assessmentUUID := opts.AssessmentUUID
	if assessmentUUID == "" {
		assessmentUUID = uuidV5("assessment", pkg.SnapshotID, now.Format(time.RFC3339))
	}

	systemUUID := opts.SystemUUID
	if systemUUID == "" {
		systemUUID = uuidV5("system", pkg.SnapshotID)
	}

	partyUUID := uuidV5("party", opts.Assessor)

	doc := oscalDocument{
		AssessmentResults: oscalAssessmentResults{
			UUID: assessmentUUID,
			Metadata: oscalMetadata{
				Title:        "Stave Automated Assessment Results",
				LastModified: now.Format(time.RFC3339),
				Version:      version.String,
				OsCalVersion: "1.1.2",
				Parties: []oscalParty{
					{UUID: partyUUID, Type: "organization", Name: opts.Assessor},
				},
			},
			ImportAP: oscalImportAP{Href: "#" + systemUUID},
			LocalDefinitions: &oscalLocalDefs{
				Activities: []oscalActivity{
					{
						UUID:        uuidV5("activity", "invariant-evaluation"),
						Title:       "Stave Invariant Evaluation",
						Description: "Deterministic evaluation of infrastructure configuration against invariant controls using local snapshots",
					},
				},
			},
		},
	}

	// Build one result per framework.
	for i, profile := range profiles {
		assessment := assessments[i]
		resultUUID := uuidV5("result", profile.ID, pkg.SnapshotID)

		// Reviewed controls.
		var controlSelects []oscalControlSelect
		controlSeen := make(map[string]bool)
		for ri := range assessment.Requirements {
			req := &assessment.Requirements[ri]
			oscalID := toOSCALControlID(profile.FrameworkKey, req.RequirementID)
			if !controlSeen[oscalID] {
				controlSeen[oscalID] = true
				controlSelects = append(controlSelects, oscalControlSelect{ControlID: oscalID})
			}
		}

		// Findings and observations.
		var findings []oscalFinding
		var observations []oscalObservation

		for ri := range assessment.Requirements {
			req := &assessment.Requirements[ri]
			oscalCtlID := toOSCALControlID(profile.FrameworkKey, req.RequirementID)

			state := "satisfied"
			reason := ""
			switch req.Status {
			case evidence.RequirementNotMet:
				state = "not-satisfied"
				reason = "fail"
			case evidence.RequirementIncomplete:
				state = "not-satisfied"
				reason = "incomplete"
			case evidence.RequirementNotEvaluated:
				state = "not-satisfied"
				reason = "not-evaluated"
			}

			findingUUID := uuidV5("finding", profile.ID, req.RequirementID, pkg.SnapshotID)

			// Build observations from evidence records.
			var obsRefs []oscalObsRef
			for _, rec := range req.Evidence {
				obsUUID := uuidV5("observation", rec.ControlID, rec.ResourceARN, pkg.SnapshotID)

				obs := oscalObservation{
					UUID:        obsUUID,
					Title:       rec.ControlID + " on " + rec.ResourceARN,
					Description: rec.ReasoningTrace.FindingMessage,
					Methods:     []string{"EXAMINE", "TEST"},
					Types:       []string{"finding"},
					Collected:   rec.EvaluatedAt.Format(time.RFC3339),
					RelevantEvidence: []oscalEvidence{
						{
							Description: "Stave invariant evaluation",
							Props: []oscalProp{
								{Name: "control-id", Value: rec.ControlID},
								{Name: "verdict", Value: rec.Verdict.String()},
								{Name: "severity", Value: rec.Severity},
							},
						},
					},
				}
				observations = append(observations, obs)
				obsRefs = append(obsRefs, oscalObsRef{ObservationUUID: obsUUID})
			}

			finding := oscalFinding{
				UUID:        findingUUID,
				Title:       req.RequirementID + ": " + req.Description,
				Description: fmt.Sprintf("%s requirement %s", profile.ID, req.RequirementID),
				Target: oscalTarget{
					Type:     "statement-id",
					TargetID: oscalCtlID,
					Status:   oscalStatus{State: state, Reason: reason},
				},
				RelatedObservations: obsRefs,
			}
			findings = append(findings, finding)
		}

		result := oscalResult{
			UUID:        resultUUID,
			Title:       "Assessment Result — " + profile.Name,
			Description: "Automated assessment from snapshot " + pkg.SnapshotID,
			Start:       snapshotTime.Format(time.RFC3339),
			End:         now.Format(time.RFC3339),
			ReviewedControls: oscalReviewedControls{
				ControlSelections: []oscalControlSelection{
					{
						Description:     profile.Name + " controls evaluated",
						IncludeControls: controlSelects,
					},
				},
			},
			Findings:     findings,
			Observations: deduplicateObservations(observations),
		}

		doc.AssessmentResults.Results = append(doc.AssessmentResults.Results, result)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode OSCAL: %w", err)
	}

	return exitErrorComposite(assessments)
}

// toOSCALControlID converts a Stave requirement ID to OSCAL format.
// FedRAMP uses NIST 800-53 notation (lowercase: ac-2, sc-28).
// Other frameworks use custom URIs.
func toOSCALControlID(frameworkKey, reqID string) string {
	switch frameworkKey {
	case "fedramp_moderate", "nist_800_53_r5":
		return strings.ToLower(reqID)
	default:
		return frameworkKey + ":" + reqID
	}
}

// uuidV5 generates a deterministic UUID v5 from components.
func uuidV5(parts ...string) string {
	// RFC 4122 UUID v5: SHA-1 hash in the "stave" namespace.
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	content := strings.Join(parts, ":")
	h := sha1.New() //nolint:gosec // UUID v5 requires SHA-1
	h.Write(ns)
	h.Write([]byte(content))
	sum := h.Sum(nil)

	// Set version 5 and variant bits.
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func deduplicateObservations(obs []oscalObservation) []oscalObservation {
	seen := make(map[string]bool)
	var out []oscalObservation
	for i := range obs {
		if seen[obs[i].UUID] {
			continue
		}
		seen[obs[i].UUID] = true
		out = append(out, obs[i])
	}
	return out
}
