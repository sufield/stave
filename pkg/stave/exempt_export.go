package stave

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // UUID v5 requires SHA-1 per RFC 4122
	"encoding/json"
	"fmt"
	"strings"
	"time"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/version"
)

// ExportRiskRegister builds an OSCAL Plan of Action and Milestones (POA&M)
// document from the acceptance file's acknowledgments plus (when
// assessmentPath is non-empty) the open findings of an out.v0.1 assessment,
// returning the rendered JSON. It is the library entry point behind
// `stave exempt export` (the command owns the --out file write).
func ExportRiskRegister(file, assessmentPath, systemUUID, assessor string, now time.Time) ([]byte, error) {
	af, err := appexempt.Load(file)
	if err != nil {
		return nil, fmt.Errorf("load acceptance file: %w", err)
	}

	var assessment *report.Assessment
	if assessmentPath != "" {
		data, readErr := fsutil.ReadFileLimited(assessmentPath)
		if readErr != nil {
			return nil, fmt.Errorf("read assessment: %w", readErr)
		}
		var a report.Assessment
		if jsonErr := json.Unmarshal(data, &a); jsonErr != nil {
			return nil, fmt.Errorf("parse assessment: %w", jsonErr)
		}
		assessment = &a
	}

	poam := exemptBuildPOAM(af, assessment, systemUUID, assessor, now)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(poam); encErr != nil {
		return nil, fmt.Errorf("encode POAM document: %w", encErr)
	}
	return buf.Bytes(), nil
}

func exemptBuildPOAM(af *appexempt.AcceptanceFile, assessment *report.Assessment, systemUUID, assessor string, now time.Time) map[string]any {
	if systemUUID == "" {
		systemUUID = exemptPOAMUUID("system", "stave-default")
	}

	staveID := exemptPOAMUUID("party", "stave-assessment")
	var poamItems []map[string]any
	var risks []map[string]any

	// Type 1: Accepted risk items from acknowledgments.
	ackIDs := make(map[string]struct{})
	for i := range af.Acknowledgments {
		a := &af.Acknowledgments[i]
		if !a.IsExportable() {
			continue
		}

		cid := string(a.ControlID)
		assetID := string(a.AssetID)
		ackIDs[cid+"@"+assetID] = struct{}{}
		itemUUID := exemptPOAMUUID("poam-item", cid, assetID)
		riskUUID := exemptPOAMUUID("risk", cid, assetID)

		status := a.ExportStatus()

		risk := map[string]any{
			"uuid":   riskUUID,
			"title":  "Risk: " + cid + " on " + assetID,
			"status": status,
			"responses": []map[string]any{
				{
					"uuid":        exemptPOAMUUID("response", cid, assetID),
					"lifecycle":   "accept",
					"title":       "Risk Accepted",
					"description": a.Reason,
					"props": []map[string]string{
						{"name": "approved-by", "value": a.Approver},
						{"name": "approved-date", "value": a.AcknowledgedDate},
					},
				},
			},
		}
		risks = append(risks, risk)

		props := []map[string]string{
			{"name": "stave-control-id", "value": cid},
			{"name": "stave-asset-id", "value": assetID},
			{"name": "stave-approver", "value": a.Approver},
			{"name": "stave-acknowledged-date", "value": a.AcknowledgedDate},
			{"name": "stave-status", "value": string(a.Status)},
		}
		if len(a.CompensatingControls) > 0 {
			props = append(props, map[string]string{
				"name": "stave-compensating-controls", "value": strings.Join(a.CompensatingControls, ","),
			})
		}

		item := map[string]any{
			"uuid":        itemUUID,
			"title":       "Accepted Risk: " + cid + " on " + assetID,
			"description": a.Reason,
			"related-risks": []map[string]string{
				{"risk-uuid": riskUUID},
			},
			"props": props,
		}

		if a.ExpiryDate != "" {
			item["remediations"] = []map[string]any{
				{
					"uuid":      exemptPOAMUUID("remediation", cid, assetID),
					"lifecycle": "recommendation",
					"title":     "Review before expiry",
					"milestones": []map[string]any{
						{
							"uuid":     exemptPOAMUUID("milestone", cid, assetID),
							"title":    "Expiry review",
							"due-date": a.ExpiryDate + "T00:00:00Z",
						},
					},
				},
			}
		}

		poamItems = append(poamItems, item)
	}

	// Type 2: Open findings from assessment.
	if assessment != nil {
		for i := range assessment.Findings {
			f := &assessment.Findings[i]
			key := string(f.ControlID) + "@" + string(f.AssetID)
			if _, ok := ackIDs[key]; ok {
				continue // acknowledged — already in Type 1
			}

			findingUUID := exemptPOAMUUID("poam-item", string(f.FindingID))
			riskUUID := exemptPOAMUUID("risk", string(f.FindingID))

			risks = append(risks, map[string]any{
				"uuid":   riskUUID,
				"title":  "Open Risk: " + string(f.ControlID) + " on " + string(f.AssetID),
				"status": "open",
			})

			props := []map[string]string{
				{"name": "stave-finding-id", "value": string(f.FindingID)},
				{"name": "stave-severity", "value": f.SeverityLabel()},
			}

			poamItems = append(poamItems, map[string]any{
				"uuid":        findingUUID,
				"title":       "Open Finding: " + string(f.ControlID) + " on " + string(f.AssetID),
				"description": f.Evidence.TemporalRisk,
				"related-risks": []map[string]string{
					{"risk-uuid": riskUUID},
				},
				"props": props,
			})
		}
	}

	return map[string]any{
		"plan-of-action-and-milestones": map[string]any{
			"uuid": exemptPOAMUUID("poam", systemUUID, now.Format(time.RFC3339)),
			"metadata": map[string]any{
				"title":         "Stave Risk Register — Plan of Action and Milestones",
				"last-modified": now.Format(time.RFC3339),
				"version":       version.String,
				"oscal-version": "1.1.2",
				"parties": []map[string]any{
					{"uuid": staveID, "type": "organization", "name": assessor},
				},
			},
			"import-ssp": map[string]string{"href": "#" + systemUUID},
			"risks":      risks,
			"poam-items": poamItems,
		},
	}
}

func exemptPOAMUUID(parts ...string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New() //nolint:gosec // UUID v5 requires SHA-1
	h.Write(ns)
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{':'})
	}
	sum := h.Sum(nil)
	sum[6] = (sum[6] & 0x0f) | 0x50
	sum[8] = (sum[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
