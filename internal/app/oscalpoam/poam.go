// Package oscalpoam produces OSCAL 1.1.2 Plan of Action and Milestones
// (POA&M) JSON from assessment findings. Each open finding maps to one
// poam-item with SLA deadline as scheduled-completion-date.
package oscalpoam

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// UUID uniquely identifies a POA&M document or item.
type UUID string

func (u UUID) String() string { return string(u) }

// POAM is the top-level OSCAL POA&M document.
type POAM struct {
	UUID     UUID         `json:"uuid"`
	Metadata POAMMetadata `json:"metadata"`
	Items    []POAMItem   `json:"poam-items"`
}

// POAMMetadata holds document metadata.
type POAMMetadata struct {
	Title        string `json:"title"`
	LastModified string `json:"last-modified"`
	Version      string `json:"version"`
	OSCALVersion string `json:"oscal-version"`
}

// POAMItem is a single action item in the POA&M.
type POAMItem struct {
	UUID                    UUID         `json:"uuid"`
	Title                   string       `json:"title"`
	Description             string       `json:"description"`
	RelatedControls         []RelatedCtl `json:"related-controls,omitempty"`
	Subjects                []Subject    `json:"subjects,omitempty"`
	Risk                    *POAMRisk    `json:"risk,omitempty"`
	ScheduledCompletionDate string       `json:"scheduled-completion-date,omitempty"`
}

// RelatedCtl maps a finding to its control.
type RelatedCtl struct {
	ControlID kernel.ControlID `json:"control-id"`
}

// Subject maps a finding to its asset.
type Subject struct {
	SubjectUUID asset.ID         `json:"subject-uuid"`
	Type        kernel.AssetType `json:"type"`
	Title       string           `json:"title"`
}

// POAMRisk captures the risk status.
type POAMRisk struct {
	Status       string `json:"status"`
	IdentifiedAt string `json:"identified-at,omitempty"`
}

// Input configures the POA&M generation.
type Input struct {
	Findings   []remediation.Finding
	SystemUUID string
	EvalTime   time.Time
}

// Generate produces an OSCAL POA&M from assessment findings.
func Generate(in Input) *POAM {
	poam := &POAM{
		UUID: deterministicUUID("poam", in.SystemUUID),
		Metadata: POAMMetadata{
			Title:        "Stave POA&M — Plan of Action and Milestones",
			LastModified: in.EvalTime.UTC().Format(time.RFC3339),
			Version:      "1.0",
			OSCALVersion: "1.1.2",
		},
	}

	for i := range in.Findings {
		f := &in.Findings[i]
		itemKey := string(f.ControlID) + ":" + string(f.AssetID)
		if f.AssetType != "" {
			itemKey = string(f.ControlID) + ":" + string(f.AssetType) + ":" + string(f.AssetID)
		}
		item := POAMItem{
			UUID:        deterministicUUID("poam-item", itemKey),
			Title:       string(f.ControlID) + " on " + string(f.AssetID),
			Description: f.ControlName,
			RelatedControls: []RelatedCtl{
				{ControlID: f.ControlID},
			},
			Subjects: []Subject{
				{
					SubjectUUID: asset.ID(deterministicUUID("subject", string(f.AssetID))),
					Type:        kernel.AssetType("inventory-item"),
					Title:       string(f.AssetID),
				},
			},
			Risk: &POAMRisk{
				Status: f.SeverityLabel(),
			},
		}

		if dl, ok := f.SLADeadlineValue(); ok {
			deadline := in.EvalTime.Add(time.Duration(dl) * time.Hour)
			item.ScheduledCompletionDate = deadline.Format("2006-01-02")
		}

		if !f.Evidence.FirstUnsafeAt.IsZero() {
			item.Risk.IdentifiedAt = f.Evidence.FirstUnsafeAt.Format(time.RFC3339)
		}

		poam.Items = append(poam.Items, item)
	}

	return poam
}

func deterministicUUID(namespace, value string) UUID {
	h := sha256.Sum256([]byte(namespace + ":" + value))
	h[6] = (h[6] & 0x0f) | 0x50 // version 5
	h[8] = (h[8] & 0x3f) | 0x80 // variant rfc4122
	hexVal := hex.EncodeToString(h[:16])
	return UUID(hexVal[:8] + "-" + hexVal[8:12] + "-" + hexVal[12:16] + "-" + hexVal[16:20] + "-" + hexVal[20:32])
}
