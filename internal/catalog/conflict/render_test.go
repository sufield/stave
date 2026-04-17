package conflict

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/sufield/stave/internal/core/kernel"
)

// fixedTime returns a stable timestamp for tests so generated_at does
// not bleed wall-clock time into golden comparisons.
func fixedTime() time.Time {
	return time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
}

// loadSchema compiles the conflict-report schema for round-trip
// validation in renderer tests. Mirrors the helper in
// internal/ontology/schema_test.go but lives in this package so renderer
// tests can validate without test-package ceremony.
func loadSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	schemaPath := filepath.Join(filepath.Dir(thisFile),
		"..", "..", "..", "docs", "ontology", "v0.1", "conflict-report.schema.json")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc any
	if uerr := json.Unmarshal(raw, &doc); uerr != nil {
		t.Fatalf("parse schema: %v", uerr)
	}
	c := jsonschema.NewCompiler()
	const id = "https://stave.dev/ontology/v0.1/conflict-report"
	if aerr := c.AddResource(id, doc); aerr != nil {
		t.Fatalf("add resource: %v", aerr)
	}
	s, err := c.Compile(id)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return s
}

// roundtripValidate marshals the report, parses the JSON back to a
// generic document, and validates it against the schema.
func roundtripValidate(t *testing.T, r Report) {
	t.Helper()
	raw, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if err := loadSchema(t).Validate(doc); err != nil {
		t.Fatalf("rendered report failed schema validation:\n%v\n\nreport:\n%s", err, raw)
	}
}

// pcMeta returns a metadata map matching the canonical strings the
// renderer hashes for REDUNDANCY shared_compliance_hash /
// shared_remediation_hash.
func pcMeta(idA, idB string) (ControlMetadata, ControlMetadata) {
	m := ControlMetadata{
		AttackStage:          "exfiltration",
		ComplianceCanonical:  "PCI-DSS:1.2|SOC2:CC6.1",
		RemediationCanonical: "block public access|aws s3api put-public-access-block",
	}
	a, b := m, m
	a.ControlID = idA
	b.ControlID = idB
	return a, b
}

// TestBuildReport_DerivesReportIDFromCatalogAndCorpus pins the report_id
// derivation: same catalog + same corpus → same id; different inputs →
// different ids; generated_at and stave_version do NOT contribute.
func TestBuildReport_DerivesReportIDFromCatalogAndCorpus(t *testing.T) {
	in := ReportInputs{
		CatalogVersion:       "abc123",
		FixtureCorpusVersion: "def456",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	}
	r1 := BuildReport(in)

	in.GeneratedAt = in.GeneratedAt.Add(7 * time.Hour)
	in.StaveVersion = "9.9.9"
	r2 := BuildReport(in)
	if r1.ReportID != r2.ReportID {
		t.Errorf("report_id changed when only generated_at/stave_version differed:\n  r1=%s\n  r2=%s",
			r1.ReportID, r2.ReportID)
	}

	in.CatalogVersion = "abc124"
	r3 := BuildReport(in)
	if r1.ReportID == r3.ReportID {
		t.Errorf("report_id unchanged when catalog_version differed: %s", r1.ReportID)
	}

	if !strings.HasPrefix(r1.ReportID, "sha256:") || len(r1.ReportID) != len("sha256:")+16 {
		t.Errorf("report_id shape wrong: %q (want sha256:<16 hex>)", r1.ReportID)
	}
}

// TestBuildReport_Determinism: two builds of the same inputs (same
// generated_at) yield byte-identical JSON. Cross-machine reproducibility
// rests on this being true.
func TestBuildReport_Determinism(t *testing.T) {
	in := redundancyInputs()
	a, _ := BuildReport(in).Marshal()
	b, _ := BuildReport(in).Marshal()
	if string(a) != string(b) {
		t.Errorf("two builds of same inputs differ:\n  a=%s\n  b=%s", a, b)
	}
}

// TestBuildReport_WitnessesAreSortedInOutput is the cross-machine drift
// insurance the user explicitly asked for in the Node 3d guidance.
// Lex-selection is deterministic in the renderer; this test guards
// against a future "diversity-aware" selector that re-orders witnesses
// without re-sorting before emit.
func TestBuildReport_WitnessesAreSortedInOutput(t *testing.T) {
	// Build a CONTRADICTION pair with disagreement witnesses presented
	// in REVERSE lex order to evaluate.go's contract — this should not
	// happen in production (EvaluatePairs sorts), but the renderer must
	// still emit sorted witnesses regardless.
	cp := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				Overlap:  []string{"public_access"},
				Relation: RelationOverlapping,
			},
			FixturesEvaluated: 3,
			FixturesMatched:   3,
			CoEvaluations: []CoEvaluation{
				// reversed
				ceMix("z.json", "z3", true, false),
				ceMix("m.json", "m1", true, false),
				ceMix("a.json", "a1", true, false),
			},
		},
		Category:                 CategoryContradiction,
		ContradictionSubcategory: SubcategoryLogicBug,
	}
	in := ReportInputs{
		Classified:           []ClassifiedPair{cp},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	}
	r := BuildReport(in)

	if len(r.Pairs) != 1 {
		t.Fatalf("want 1 pair, got %d", len(r.Pairs))
	}
	pl, ok := r.Pairs[0].Payload.(ContradictionPayload)
	if !ok {
		t.Fatalf("payload type = %T, want ContradictionPayload", r.Pairs[0].Payload)
	}
	got := pl.DisagreementWitnesses
	want := []string{"a.json", "m.json", "z.json"}
	for i, w := range got {
		if w.FixturePath != want[i] {
			t.Errorf("witness[%d] FixturePath = %q, want %q", i, w.FixturePath, want[i])
		}
	}
	// Verify the property holds in the marshaled JSON too — a future
	// post-Marshal mutation cannot silently re-order.
	raw, _ := r.Marshal()
	idxA := strings.Index(string(raw), `"a.json"`)
	idxM := strings.Index(string(raw), `"m.json"`)
	idxZ := strings.Index(string(raw), `"z.json"`)
	if idxA >= idxM || idxM >= idxZ {
		t.Errorf("witnesses out of lex order in JSON: a@%d m@%d z@%d", idxA, idxM, idxZ)
	}
}

// TestBuildReport_WitnessTruncation caps at MaxWitnesses and sets the
// truncated flag.
func TestBuildReport_WitnessTruncation(t *testing.T) {
	var coevals []CoEvaluation
	for i := range 7 {
		coevals = append(coevals, ceMix(
			"f.json", string(rune('a'+i)), true, false))
	}
	cp := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				Overlap: []string{"x"}, Relation: RelationOverlapping,
			},
			FixturesEvaluated: 7,
			FixturesMatched:   7,
			CoEvaluations:     coevals,
		},
		Category:                 CategoryContradiction,
		ContradictionSubcategory: SubcategoryLogicBug,
	}
	r := BuildReport(ReportInputs{
		Classified:           []ClassifiedPair{cp},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	})
	pl := r.Pairs[0].Payload.(ContradictionPayload)
	if len(pl.DisagreementWitnesses) != MaxWitnesses {
		t.Errorf("witness count = %d, want %d", len(pl.DisagreementWitnesses), MaxWitnesses)
	}
	if !pl.WitnessesTruncated {
		t.Error("WitnessesTruncated = false, want true")
	}
}

// TestBuildReport_AnalysisGapsIncludeBothCategories: a single report
// must surface BOTH the catalog-level ALIASED_PREDICATE gap and the
// pair-level NO_FIXTURE_COVERAGE gap. This is the wiring requirement
// the user called out — aliased controls were filtered out before
// overlap analysis, so they need a separate input.
func TestBuildReport_AnalysisGapsIncludeBothCategories(t *testing.T) {
	zeroCovPair := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.NOCOV.B", ControlB: "CTL.NOCOV.A",
				Overlap: []string{"some.path"}, Relation: RelationIdentical,
			},
			// CoEvaluations empty → NO_FIXTURE_COVERAGE
		},
	}
	in := ReportInputs{
		Classified:      []ClassifiedPair{zeroCovPair},
		AliasedControls: []string{"CTL.ALIASED.X", "CTL.ALIASED.Y"},
		ExtractionFailures: []ExtractionFailure{
			{ControlID: "CTL.BROKEN", Err: "boom"},
		},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	}
	r := BuildReport(in)

	reasonsSeen := map[GapReason]int{}
	for _, g := range r.AnalysisGaps {
		reasonsSeen[g.Reason]++
	}
	if reasonsSeen[GapAliasedPredicate] != 2 {
		t.Errorf("ALIASED_PREDICATE gaps = %d, want 2", reasonsSeen[GapAliasedPredicate])
	}
	if reasonsSeen[GapExtractionFailed] != 1 {
		t.Errorf("EXTRACTION_FAILED gaps = %d, want 1", reasonsSeen[GapExtractionFailed])
	}
	if reasonsSeen[GapNoFixtureCoverage] != 1 {
		t.Errorf("NO_FIXTURE_COVERAGE gaps = %d, want 1", reasonsSeen[GapNoFixtureCoverage])
	}

	// Gaps are sorted by (reason, first control id). Ensure that holds.
	for i := 1; i < len(r.AnalysisGaps); i++ {
		prev, cur := r.AnalysisGaps[i-1], r.AnalysisGaps[i]
		if prev.Reason > cur.Reason {
			t.Errorf("gaps not reason-sorted at i=%d: %s > %s", i, prev.Reason, cur.Reason)
		}
	}

	// Verify pair-level gap is lex-sorted regardless of original order.
	for _, g := range r.AnalysisGaps {
		if g.Reason != GapNoFixtureCoverage {
			continue
		}
		if !slices.IsSorted(g.Controls) {
			t.Errorf("NO_FIXTURE_COVERAGE controls not sorted: %v", g.Controls)
		}
	}

	// Zero-coverage pair must NOT appear as a finding.
	if len(r.Pairs) != 0 {
		t.Errorf("expected 0 pairs (zero-coverage suppressed), got %d", len(r.Pairs))
	}

	roundtripValidate(t, r)
}

// TestBuildReport_NoFixtureCoverageGapFiresOnZeroMatched pins the
// matched-vs-evaluated distinction for the gap detector. A pair that
// produced co-evaluations on every asset in a 1000-fixture corpus but
// never resolved the shared overlap on any of them is the same kind
// of coverage gap as a pair with zero co-evaluations — it just hides
// behind the noise of "1000 evaluated". The gap detector must catch it.
//
// Without this guard, unresolved-overlap-only pairs become
// uncategorized in the classifier (correct) but then disappear from
// the report entirely instead of surfacing as analysis gaps (silent
// data loss).
func TestBuildReport_NoFixtureCoverageGapFiresOnZeroMatched(t *testing.T) {
	matchedZeroPair := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				Overlap: []string{"properties.shared.path"}, Relation: RelationIdentical,
			},
			FixturesEvaluated: 1000,
			FixturesMatched:   0,
			CoEvaluations: []CoEvaluation{
				// Lots of co-evaluations, none with ReadOverlap=true.
				{FixturePath: "f1.json", AssetID: "a1", UnsafeA: true, UnsafeB: false, ReadOverlap: false},
				{FixturePath: "f2.json", AssetID: "a2", UnsafeA: false, UnsafeB: true, ReadOverlap: false},
			},
		},
		// Classifier returned uncategorized (matched=0).
	}
	in := ReportInputs{
		Classified:           []ClassifiedPair{matchedZeroPair},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	}
	r := BuildReport(in)

	if len(r.Pairs) != 0 {
		t.Errorf("expected 0 pair findings (matched=0 → no evidence), got %d", len(r.Pairs))
	}
	gaps := 0
	for _, g := range r.AnalysisGaps {
		if g.Reason == GapNoFixtureCoverage {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("NO_FIXTURE_COVERAGE gaps = %d, want 1 (matched=0 must surface as gap)", gaps)
	}
}

// TestBuildReport_WitnessesFilterUnresolvedOverlap pins that the
// renderer's witness selection (for both CONTRADICTION and DIVERGENCE
// payloads) filters out unresolved-overlap co-evaluations. Without
// this, payloads point maintainers at fixtures where the asset doesn't
// even carry the dependency the witness is supposed to demonstrate.
func TestBuildReport_WitnessesFilterUnresolvedOverlap(t *testing.T) {
	contradictionPair := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				Overlap: []string{"properties.x"}, Relation: RelationIdentical,
			},
			FixturesEvaluated: 2,
			FixturesMatched:   1,
			CoEvaluations: []CoEvaluation{
				// Real disagreement evidence.
				{FixturePath: "real.json", AssetID: "real", UnsafeA: true, UnsafeB: false, ReadOverlap: true,
					PathValues: map[string]any{"properties.x": true}},
				// Fake disagreement: same verdict split, but overlap unresolved.
				{FixturePath: "ghost.json", AssetID: "ghost", UnsafeA: false, UnsafeB: true, ReadOverlap: false},
			},
		},
		Category:                 CategoryContradiction,
		ContradictionSubcategory: SubcategoryLogicBug,
		MetadataA:                ControlMetadata{ControlID: "CTL.A"},
		MetadataB:                ControlMetadata{ControlID: "CTL.B"},
	}
	r := BuildReport(ReportInputs{
		Classified:           []ClassifiedPair{contradictionPair},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	})
	if len(r.Pairs) != 1 {
		t.Fatalf("Pairs len = %d, want 1", len(r.Pairs))
	}
	pl, ok := r.Pairs[0].Payload.(ContradictionPayload)
	if !ok {
		t.Fatalf("Payload type = %T, want ContradictionPayload", r.Pairs[0].Payload)
	}
	if len(pl.DisagreementWitnesses) != 1 {
		t.Fatalf("DisagreementWitnesses len = %d, want 1 (ghost must be filtered)",
			len(pl.DisagreementWitnesses))
	}
	if pl.DisagreementWitnesses[0].FixturePath != "real.json" {
		t.Errorf("kept witness fixture = %q, want real.json", pl.DisagreementWitnesses[0].FixturePath)
	}
}

// TestBuildReport_RedundancyHashesMatchCanonical pins that the renderer
// hashes through the canonical helpers — not raw strings, not its own
// concatenation. A regression here breaks downstream consumers that
// compare hashes across reports.
func TestBuildReport_RedundancyHashesMatchCanonical(t *testing.T) {
	in := redundancyInputs()
	r := BuildReport(in)
	if len(r.Pairs) != 1 {
		t.Fatalf("want 1 pair, got %d", len(r.Pairs))
	}
	pl, ok := r.Pairs[0].Payload.(RedundancyPayload)
	if !ok {
		t.Fatalf("payload type = %T, want RedundancyPayload", r.Pairs[0].Payload)
	}
	mdA, _ := pcMeta("CTL.A", "CTL.B")
	wantCH := HashSHA256(mdA.ComplianceCanonical)
	wantRH := HashSHA256(mdA.RemediationCanonical)
	if pl.SharedComplianceHash != wantCH {
		t.Errorf("compliance hash = %s, want %s", pl.SharedComplianceHash, wantCH)
	}
	if pl.SharedRemediationHash != wantRH {
		t.Errorf("remediation hash = %s, want %s", pl.SharedRemediationHash, wantRH)
	}
	roundtripValidate(t, r)
}

// TestBuildReport_ContradictionWitnessObservedValuesScoped: observed_values
// must be the OVERLAP subset of PathValues. A non-overlap path leaking
// in would conflate witness diagnostics with DIVERGENCE-style payload.
func TestBuildReport_ContradictionWitnessObservedValuesScoped(t *testing.T) {
	cp := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				DepsA:    []string{"acl.public", "owner.canonical_id"},
				DepsB:    []string{"acl.public", "policy.statement"},
				Overlap:  []string{"acl.public"},
				Relation: RelationOverlapping,
			},
			FixturesEvaluated: 1,
			FixturesMatched:   1,
			CoEvaluations: []CoEvaluation{
				{
					FixturePath: "f.json", AssetID: "b1",
					AssetType: kernel.AssetType("aws_s3_bucket"),
					UnsafeA:   true, UnsafeB: false,
					PathValues: map[string]any{
						"acl.public":         true,
						"owner.canonical_id": "owner-X",
						"policy.statement":   "Allow",
					},
					ReadOverlap: true,
				},
			},
		},
		Category:                 CategoryContradiction,
		ContradictionSubcategory: SubcategoryLogicBug,
	}
	r := BuildReport(ReportInputs{
		Classified:           []ClassifiedPair{cp},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	})
	pl := r.Pairs[0].Payload.(ContradictionPayload)
	w := pl.DisagreementWitnesses[0]
	if _, ok := w.ObservedValues["acl.public"]; !ok {
		t.Error("observed_values missing overlap path acl.public")
	}
	if _, ok := w.ObservedValues["owner.canonical_id"]; ok {
		t.Error("observed_values contains non-overlap path owner.canonical_id (leaked)")
	}
	if w.DifferingValues != nil {
		t.Errorf("DifferingValues set on CONTRADICTION witness: %v", w.DifferingValues)
	}
	roundtripValidate(t, r)
}

// TestBuildReport_DivergenceWitnessDifferingValuesScoped: differing_values
// is the NON-overlap subset — the fields that distinguish A's read set
// from B's. The complementary check to the CONTRADICTION test above.
func TestBuildReport_DivergenceWitnessDifferingValuesScoped(t *testing.T) {
	cp := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				DepsA:    []string{"acl.public", "owner.canonical_id"},
				DepsB:    []string{"acl.public", "policy.statement"},
				Overlap:  []string{"acl.public"},
				Relation: RelationOverlapping,
			},
			FixturesEvaluated: 2,
			FixturesMatched:   2,
			CoEvaluations: []CoEvaluation{
				// Asset 1: agree (boring)
				{
					FixturePath: "agree.json", AssetID: "a1",
					AssetType: kernel.AssetType("aws_s3_bucket"),
					UnsafeA:   false, UnsafeB: false,
					ReadOverlap: true,
				},
				// Asset 2: disagree (the witness)
				{
					FixturePath: "disagree.json", AssetID: "a1",
					AssetType: kernel.AssetType("aws_s3_bucket"),
					UnsafeA:   true, UnsafeB: false,
					PathValues: map[string]any{
						"acl.public":         true,
						"owner.canonical_id": "owner-X",
						"policy.statement":   "Allow",
					},
					ReadOverlap: true,
				},
			},
		},
		Category: CategoryDivergence,
	}
	r := BuildReport(ReportInputs{
		Classified:           []ClassifiedPair{cp},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	})
	pl := r.Pairs[0].Payload.(DivergencePayload)
	if len(pl.MinimalDisagreementFixtures) != 1 {
		t.Fatalf("want 1 witness, got %d", len(pl.MinimalDisagreementFixtures))
	}
	w := pl.MinimalDisagreementFixtures[0]
	if _, ok := w.DifferingValues["owner.canonical_id"]; !ok {
		t.Error("differing_values missing non-overlap path owner.canonical_id")
	}
	if _, ok := w.DifferingValues["policy.statement"]; !ok {
		t.Error("differing_values missing non-overlap path policy.statement")
	}
	if _, ok := w.DifferingValues["acl.public"]; ok {
		t.Error("differing_values contains overlap path acl.public (leaked)")
	}
	if w.ObservedValues != nil {
		t.Errorf("ObservedValues set on DIVERGENCE witness: %v", w.ObservedValues)
	}
	if pl.AgreementRate != 0.5 {
		t.Errorf("agreement_rate = %v, want 0.5", pl.AgreementRate)
	}
	roundtripValidate(t, r)
}

// TestBuildReport_EmpiricalSubsumptionDelta: dependency_delta is
// broader \ narrower, sorted, non-empty.
func TestBuildReport_EmpiricalSubsumptionDelta(t *testing.T) {
	cp := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.NARROW", ControlB: "CTL.WIDE",
				DepsA:    []string{"x"},
				DepsB:    []string{"x", "y", "z"},
				Overlap:  []string{"x"},
				Relation: RelationSubset,
				Narrower: "CTL.NARROW", Broader: "CTL.WIDE",
			},
			FixturesEvaluated: 5,
			FixturesMatched:   5,
			CoEvaluations: []CoEvaluation{
				ceMix("f.json", "a", false, false),
			},
		},
		Category: CategoryEmpiricalSubsumption,
	}
	r := BuildReport(ReportInputs{
		Classified:           []ClassifiedPair{cp},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	})
	pl := r.Pairs[0].Payload.(EmpiricalSubsumptionPayload)
	want := []string{"y", "z"}
	if !slices.Equal(pl.DependencyDelta, want) {
		t.Errorf("dependency_delta = %v, want %v", pl.DependencyDelta, want)
	}
	if pl.Narrower != "CTL.NARROW" || pl.Broader != "CTL.WIDE" {
		t.Errorf("narrower/broader = %s/%s", pl.Narrower, pl.Broader)
	}
	roundtripValidate(t, r)
}

// TestBuildReport_LowCoverageFlagDerivedFromThreshold: pairs evaluated
// against fewer than LowCoverageThreshold fixtures get low_coverage:
// true; pairs at or above the threshold get false.
func TestBuildReport_LowCoverageFlagDerivedFromThreshold(t *testing.T) {
	mk := func(n int) ClassifiedPair {
		return ClassifiedPair{
			EvaluatedPair: EvaluatedPair{
				CandidatePair: CandidatePair{
					ControlA: "CTL.A", ControlB: "CTL.B",
					Overlap: []string{"x"}, Relation: RelationOverlapping,
				},
				FixturesEvaluated: n,
				FixturesMatched:   n,
				CoEvaluations:     []CoEvaluation{ceMix("f.json", "a", true, false)},
			},
			Category:                 CategoryContradiction,
			ContradictionSubcategory: SubcategoryLogicBug,
		}
	}
	cases := []struct {
		evaluated int
		wantLow   bool
	}{
		{1, true},
		{LowCoverageThreshold - 1, true},
		{LowCoverageThreshold, false},
		{LowCoverageThreshold + 10, false},
	}
	for _, c := range cases {
		r := BuildReport(ReportInputs{
			Classified:           []ClassifiedPair{mk(c.evaluated)},
			CatalogVersion:       "cat",
			FixtureCorpusVersion: "corp",
			StaveVersion:         "0.1.0",
			GeneratedAt:          fixedTime(),
		})
		got := r.Pairs[0].CorpusCoverage.LowCoverage
		if got != c.wantLow {
			t.Errorf("evaluated=%d: LowCoverage=%v, want %v", c.evaluated, got, c.wantLow)
		}
	}
}

// TestBuildReport_LowCoverageKeysOnMatchedNotEvaluated pins the
// matched-vs-evaluated distinction in coverage flagging on pairs that
// reach the report as findings. A pair with 1000 evaluated and a low
// (but non-zero) matched count is genuine evidence on shaky footing —
// low_coverage must flag it, even though "1000 evaluated" looks
// well-covered. The matched=0 case is handled separately by the gap
// detector (TestBuildReport_NoFixtureCoverageGapFiresOnZeroMatched);
// findings always have matched>0 by construction.
//
// Without this guard, the Node 3f dry-run reports low_coverage=false
// on pairs whose disagreements are based on a handful of matched
// fixtures buried in noise.
func TestBuildReport_LowCoverageKeysOnMatchedNotEvaluated(t *testing.T) {
	mk := func(evaluated, matched int) ClassifiedPair {
		return ClassifiedPair{
			EvaluatedPair: EvaluatedPair{
				CandidatePair: CandidatePair{
					ControlA: "CTL.A", ControlB: "CTL.B",
					Overlap: []string{"x"}, Relation: RelationOverlapping,
				},
				FixturesEvaluated: evaluated,
				FixturesMatched:   matched,
				CoEvaluations:     []CoEvaluation{ceMix("f.json", "a", true, false)},
			},
			Category:                 CategoryContradiction,
			ContradictionSubcategory: SubcategoryLogicBug,
		}
	}
	cases := []struct {
		name               string
		evaluated, matched int
		wantLow            bool
	}{
		{"high-evaluated-low-matched", 1000, LowCoverageThreshold - 1, true},
		{"high-evaluated-at-threshold", 1000, LowCoverageThreshold, false},
		{"matched-equals-evaluated-above-threshold", 50, 50, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := BuildReport(ReportInputs{
				Classified:           []ClassifiedPair{mk(c.evaluated, c.matched)},
				CatalogVersion:       "cat",
				FixtureCorpusVersion: "corp",
				StaveVersion:         "0.1.0",
				GeneratedAt:          fixedTime(),
			})
			if len(r.Pairs) == 0 {
				t.Fatalf("evaluated=%d matched=%d: pair was dropped from report (expected to be a finding)",
					c.evaluated, c.matched)
			}
			got := r.Pairs[0].CorpusCoverage.LowCoverage
			if got != c.wantLow {
				t.Errorf("evaluated=%d matched=%d: LowCoverage=%v, want %v",
					c.evaluated, c.matched, got, c.wantLow)
			}
		})
	}
}

// TestBuildReport_PairsSortedByCategoryThenControls: schema requires
// pairs sorted lex by (category, control_a, control_b). Verify the
// renderer emits them in that order regardless of input order.
func TestBuildReport_PairsSortedByCategoryThenControls(t *testing.T) {
	mk := func(a, b string, cat ConflictCategory) ClassifiedPair {
		cp := ClassifiedPair{
			EvaluatedPair: EvaluatedPair{
				CandidatePair: CandidatePair{
					ControlA: a, ControlB: b,
					DepsA: []string{"x"}, DepsB: []string{"x"},
					Overlap: []string{"x"}, Relation: RelationIdentical,
				},
				FixturesEvaluated: 5,
				FixturesMatched:   5,
				CoEvaluations:     []CoEvaluation{ceMix("f.json", "a", true, true)},
			},
			Category: cat,
		}
		if cat == CategoryRedundancy {
			mdA, mdB := pcMeta(a, b)
			cp.MetadataA, cp.MetadataB = mdA, mdB
		}
		if cat == CategoryContradiction {
			cp.ContradictionSubcategory = SubcategoryLogicBug
			cp.CoEvaluations = []CoEvaluation{ceMix("f.json", "a", true, false)}
		}
		return cp
	}

	// Submit out of order: REDUNDANCY first, then CONTRADICTION.
	in := ReportInputs{
		Classified: []ClassifiedPair{
			mk("CTL.M", "CTL.N", CategoryRedundancy),
			mk("CTL.A", "CTL.B", CategoryContradiction),
			mk("CTL.A", "CTL.C", CategoryContradiction),
		},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	}
	r := BuildReport(in)
	if len(r.Pairs) != 3 {
		t.Fatalf("want 3 pairs, got %d", len(r.Pairs))
	}
	if r.Pairs[0].Category != CategoryContradiction || r.Pairs[1].Category != CategoryContradiction {
		t.Errorf("CONTRADICTIONs not first: %v", []string{
			string(r.Pairs[0].Category), string(r.Pairs[1].Category), string(r.Pairs[2].Category),
		})
	}
	if r.Pairs[0].ControlB != "CTL.B" || r.Pairs[1].ControlB != "CTL.C" {
		t.Errorf("contradictions not lex-sorted by control_b: %s, %s",
			r.Pairs[0].ControlB, r.Pairs[1].ControlB)
	}
	roundtripValidate(t, r)
}

// --- helpers below ---

// ceMix is a CoEvaluation builder for renderer tests.
func ceMix(path, id string, unsafeA, unsafeB bool) CoEvaluation {
	return CoEvaluation{
		FixturePath: path,
		AssetID:     id,
		AssetType:   kernel.AssetType("aws_s3_bucket"),
		UnsafeA:     unsafeA,
		UnsafeB:     unsafeB,
		ReadOverlap: true,
	}
}

// redundancyInputs constructs a single REDUNDANCY pair for tests that
// need a happy-path report.
func redundancyInputs() ReportInputs {
	mdA, mdB := pcMeta("CTL.A", "CTL.B")
	cp := ClassifiedPair{
		EvaluatedPair: EvaluatedPair{
			CandidatePair: CandidatePair{
				ControlA: "CTL.A", ControlB: "CTL.B",
				DepsA: []string{"x"}, DepsB: []string{"x"},
				Overlap: []string{"x"}, Relation: RelationIdentical,
			},
			FixturesEvaluated: 8,
			FixturesMatched:   8,
			CoEvaluations: []CoEvaluation{
				ceMix("f1.json", "a", true, true),
				ceMix("f2.json", "b", false, false),
			},
		},
		Category:  CategoryRedundancy,
		MetadataA: mdA,
		MetadataB: mdB,
	}
	return ReportInputs{
		Classified:           []ClassifiedPair{cp},
		CatalogVersion:       "cat",
		FixtureCorpusVersion: "corp",
		StaveVersion:         "0.1.0",
		GeneratedAt:          fixedTime(),
	}
}
