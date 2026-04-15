package exempt

import (
	"crypto/sha1" //nolint:gosec // UUID v5
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/version"
)

func newExportCmd() *cobra.Command {
	var file, format, outputFile, systemUUID, assessor, outPath string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export risk register as OSCAL POA&M",
		Long: `Export acknowledgments and open findings as an OSCAL Plan of Action
and Milestones (POA&M) document for FedRAMP, HIPAA, and SOC2 submissions.

Exit Codes:
  0   Export complete
  2   Invalid input
  4   Internal error`,
		Example: `  stave exempt export --format oscal-poam --system-uuid <uuid> --out poam.json
  stave exempt export --format oscal-poam --output assessment.json --out poam.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExemptExport(cmd.OutOrStdout(), file, format, outputFile, systemUUID, assessor, outPath)
		},
	}

	cmd.Flags().StringVar(&file, "file", defaultFile, "path to acknowledgment YAML file")
	cmd.Flags().StringVarP(&format, "format", "f", "oscal-poam", "output format: oscal-poam")
	cmd.Flags().StringVar(&outputFile, "output", "", "path to out.v0.1.json for open findings")
	cmd.Flags().StringVar(&systemUUID, "system-uuid", "", "UUID of the System Security Plan")
	cmd.Flags().StringVar(&assessor, "assessor", "Stave automated assessment", "assessor name")
	cmd.Flags().StringVar(&outPath, "out", "", "write to file instead of stdout")

	return cmd
}

func runExemptExport(stdout io.Writer, file, format, outputFile, systemUUID, assessor, outPath string) error {
	if format != "oscal-poam" {
		return fmt.Errorf("unsupported format %q (use oscal-poam)", format)
	}

	// Load acknowledgments.
	af, err := appexempt.Load(file)
	if err != nil {
		return fmt.Errorf("load acceptance file: %w", err)
	}

	// Optionally load assessment for open findings.
	var assessment *report.Assessment
	if outputFile != "" {
		data, readErr := fsutil.ReadFileLimited(outputFile)
		if readErr != nil {
			return fmt.Errorf("read assessment: %w", readErr)
		}
		var a report.Assessment
		if jsonErr := json.Unmarshal(data, &a); jsonErr != nil {
			return fmt.Errorf("parse assessment: %w", jsonErr)
		}
		assessment = &a
	}

	now := time.Now().UTC()
	poam := buildPOAM(af, assessment, systemUUID, assessor, now)

	out := stdout
	if outPath != "" {
		f, createErr := os.Create(outPath) //nolint:gosec // user-specified output path
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer f.Close()
		out = f
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(poam)
}

func buildPOAM(af *appexempt.AcceptanceFile, assessment *report.Assessment, systemUUID, assessor string, now time.Time) map[string]any {
	if systemUUID == "" {
		systemUUID = poamUUID("system", "stave-default")
	}

	staveID := poamUUID("party", "stave-assessment")
	var poamItems []map[string]any
	var risks []map[string]any

	// Type 1: Accepted risk items from acknowledgments.
	ackIDs := make(map[string]bool)
	for i := range af.Acknowledgments {
		a := &af.Acknowledgments[i]
		if a.Status != "active" && a.Status != "expired" {
			continue
		}

		ackIDs[a.ControlID+"@"+a.AssetID] = true
		itemUUID := poamUUID("poam-item", a.ControlID, a.AssetID)
		riskUUID := poamUUID("risk", a.ControlID, a.AssetID)

		status := "accepted"
		if a.Status == "expired" {
			status = "open" // expired = no longer accepted
		}

		risk := map[string]any{
			"uuid":   riskUUID,
			"title":  "Risk: " + a.ControlID + " on " + a.AssetID,
			"status": status,
			"responses": []map[string]any{
				{
					"uuid":        poamUUID("response", a.ControlID, a.AssetID),
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
			{"name": "stave-control-id", "value": a.ControlID},
			{"name": "stave-asset-id", "value": a.AssetID},
			{"name": "stave-approver", "value": a.Approver},
			{"name": "stave-acknowledged-date", "value": a.AcknowledgedDate},
			{"name": "stave-status", "value": a.Status},
		}
		if len(a.CompensatingControls) > 0 {
			props = append(props, map[string]string{
				"name": "stave-compensating-controls", "value": strings.Join(a.CompensatingControls, ","),
			})
		}

		item := map[string]any{
			"uuid":        itemUUID,
			"title":       "Accepted Risk: " + a.ControlID + " on " + a.AssetID,
			"description": a.Reason,
			"related-risks": []map[string]string{
				{"risk-uuid": riskUUID},
			},
			"props": props,
		}

		if a.ExpiryDate != "" {
			item["remediations"] = []map[string]any{
				{
					"uuid":      poamUUID("remediation", a.ControlID, a.AssetID),
					"lifecycle": "recommendation",
					"title":     "Review before expiry",
					"milestones": []map[string]any{
						{
							"uuid":     poamUUID("milestone", a.ControlID, a.AssetID),
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
			if ackIDs[key] {
				continue // acknowledged — already in Type 1
			}

			findingUUID := poamUUID("poam-item", f.FindingID)
			riskUUID := poamUUID("risk", f.FindingID)

			risks = append(risks, map[string]any{
				"uuid":   riskUUID,
				"title":  "Open Risk: " + string(f.ControlID) + " on " + string(f.AssetID),
				"status": "open",
			})

			props := []map[string]string{
				{"name": "stave-finding-id", "value": f.FindingID},
				{"name": "stave-severity", "value": f.ControlSeverity.String()},
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
			"uuid": poamUUID("poam", systemUUID, now.Format(time.RFC3339)),
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

func poamUUID(parts ...string) string {
	ns := []byte{0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}
	h := sha1.New() //nolint:gosec // UUID v5
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
