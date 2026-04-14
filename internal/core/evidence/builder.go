package evidence

import (
	"cmp"
	"slices"
	"time"
)

// FindingInput is the builder's view of a single assessment verdict.
// It is decoupled from the evaluation package to keep the evidence
// package dependency-free within core.
type FindingInput struct {
	ControlID         string
	ControlName       string
	ResourceARN       string
	Verdict           string // "VIOLATION", "PASS", "INCONCLUSIVE", etc.
	Severity          string
	Compliance        map[string]string // framework → requirement
	ObservationFields []string
	AssetProperties   map[string]any
	FindingMessage    string
	InvariantText     string // control description
}

// BuilderConfig holds run-level parameters for evidence generation.
type BuilderConfig struct {
	SnapshotID  string
	EvaluatedAt time.Time
	IsSensitive func(string) bool
}

// Build produces an EvidencePackage from assessment verdicts. Each
// FindingInput with N compliance entries produces N EvidenceRecords
// (one per citation). Records are sorted deterministically.
func Build(cfg BuilderConfig, inputs []FindingInput) *EvidencePackage {
	pkg := NewEvidencePackage(cfg.SnapshotID, cfg.EvaluatedAt)

	for i := range inputs {
		in := &inputs[i]
		if len(in.Compliance) == 0 {
			continue
		}

		verdict := MapVerdict(in.Verdict)
		obs := ExtractObservationProperties(in.AssetProperties, in.ObservationFields, cfg.IsSensitive)

		trace := ReasoningTrace{
			InvariantEvaluated:    in.InvariantText,
			FindingMessage:        in.FindingMessage,
			ObservationProperties: obs,
		}

		// Collect framework keys and sort for deterministic output.
		frameworks := make([]string, 0, len(in.Compliance))
		for fw := range in.Compliance {
			frameworks = append(frameworks, fw)
		}
		slices.Sort(frameworks)

		for _, fw := range frameworks {
			req := in.Compliance[fw]
			r := &EvidenceRecord{
				ControlID:   in.ControlID,
				ControlName: in.ControlName,
				ResourceARN: in.ResourceARN,
				SnapshotID:  cfg.SnapshotID,
				Verdict:     verdict,
				Severity:    in.Severity,
				Citations: []Citation{{
					Framework:   fw,
					Requirement: req,
				}},
				ReasoningTrace: trace,
				EvaluatedAt:    cfg.EvaluatedAt,
			}
			pkg.Add(r)
		}
	}

	// Sort records for deterministic output.
	slices.SortFunc(pkg.Records, func(a, b *EvidenceRecord) int {
		if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ResourceARN, b.ResourceARN); c != 0 {
			return c
		}
		if len(a.Citations) > 0 && len(b.Citations) > 0 {
			return cmp.Compare(a.Citations[0].Framework, b.Citations[0].Framework)
		}
		return 0
	})

	return pkg
}
