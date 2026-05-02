package engine

import (
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

// buildEvidencePackage converts assessment findings and checks into a
// structured compliance evidence package. It produces one EvidenceRecord
// per (verdict × compliance citation).
func buildEvidencePackage(
	findings []evaluation.Finding,
	checks []evaluation.ResourceCheck,
	controls []policy.ControlDefinition,
	latestSnapshot *asset.Snapshot,
	auditTime time.Time,
) *evidence.EvidencePackage {
	ctlIndex := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		ctlIndex[controls[i].ID] = &controls[i]
	}

	snapshotID := ""
	if latestSnapshot != nil {
		snapshotID = latestSnapshot.CapturedAt.Format(time.RFC3339)
	}

	cfg := evidence.BuilderConfig{
		SnapshotID:  snapshotID,
		EvaluatedAt: auditTime,
		IsSensitive: isSensitiveField,
	}

	var inputs []evidence.FindingInput

	// Violation findings.
	for i := range findings {
		f := &findings[i]
		ctl := ctlIndex[f.ControlID]
		if ctl == nil || len(ctl.Compliance) == 0 {
			continue
		}
		inputs = append(inputs, findingToInput(f, ctl, latestSnapshot))
	}

	// Pass checks.
	for i := range checks {
		c := &checks[i]
		if c.Verdict != evaluation.VerdictPass {
			continue
		}
		ctl := ctlIndex[c.ControlID]
		if ctl == nil || len(ctl.Compliance) == 0 {
			continue
		}
		inputs = append(inputs, checkToInput(c, ctl, latestSnapshot))
	}

	return evidence.Build(cfg, inputs)
}

func findingToInput(
	f *evaluation.Finding,
	ctl *policy.ControlDefinition,
	snap *asset.Snapshot,
) evidence.FindingInput {
	return evidence.FindingInput{
		ControlID:         string(f.ControlID),
		ControlName:       f.ControlName,
		ResourceARN:       string(f.AssetID),
		Verdict:           "VIOLATION",
		Severity:          ctl.Severity.String(),
		Compliance:        complianceToMap(ctl.Compliance),
		ObservationFields: ctl.ObservationFields,
		AssetProperties:   lookupProperties(snap, f.AssetID),
		FindingMessage:    f.Evidence.TemporalRisk,
		InvariantText:     ctl.Description,
	}
}

func checkToInput(
	c *evaluation.ResourceCheck,
	ctl *policy.ControlDefinition,
	snap *asset.Snapshot,
) evidence.FindingInput {
	return evidence.FindingInput{
		ControlID:         string(c.ControlID),
		ControlName:       ctl.Name,
		ResourceARN:       string(c.AssetID),
		Verdict:           string(c.Verdict),
		Severity:          ctl.Severity.String(),
		Compliance:        complianceToMap(ctl.Compliance),
		ObservationFields: ctl.ObservationFields,
		AssetProperties:   lookupProperties(snap, c.AssetID),
		InvariantText:     ctl.Description,
	}
}

func complianceToMap(cm policy.ComplianceMapping) map[string]string {
	if len(cm) == 0 {
		return nil
	}
	out := make(map[string]string, len(cm))
	for k, v := range cm {
		out[string(k)] = string(v)
	}
	return out
}

func lookupProperties(snap *asset.Snapshot, id asset.ID) map[string]any {
	if snap == nil {
		return nil
	}
	a, ok := snap.FindAsset(string(id))
	if !ok {
		return nil
	}
	return a.Properties
}

// isSensitiveField checks whether a field name leaf indicates a sensitive
// value, using the same token vocabulary as the sanitize package.
func isSensitiveField(key string) bool {
	tokens := strings.FieldsFunc(strings.ToLower(key), func(r rune) bool {
		return r == '_' || r == '-' || r == '.' || r == ':'
	})
	for _, t := range tokens {
		if _, ok := sanitize.SensitiveTokens[t]; ok {
			return true
		}
	}
	return false
}
