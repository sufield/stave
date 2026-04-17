package conflict

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// Renderer for the schema-conformant ConflictReport (ontology v0.1.4).
//
// The report is a *contract*: byte-identical input always yields a
// byte-identical report. Two properties carry that contract:
//
//   - Witness selection is deterministic: lex-sort by (fixture_path,
//     asset_id), cap at MaxWitnesses, set witnesses_truncated. Diversity
//     heuristics are deferred to a later iteration; lex-selection is
//     cheap and unambiguous.
//
//   - report_id is derived from (catalog_version, fixture_corpus_version)
//     only — it does NOT depend on generated_at or stave_version. Same
//     catalog + same corpus → same report_id, even across reruns hours
//     apart.
//
// analysis_gaps wiring is the third correctness-critical piece: it MUST
// surface BOTH the per-pair NO_FIXTURE_COVERAGE gaps and the catalog-
// level ALIASED_PREDICATE / EXTRACTION_FAILED gaps that were filtered out
// before pair enumeration. A missing gap class silently understates the
// analyzer's blind spots — a missing conflict is not a proved-absent
// conflict.

const (
	// MaxWitnesses caps the per-pair witness count. Controls the trade-off
	// between report size and diagnostic signal: 5 is enough to demonstrate
	// the disagreement without bloating the report. Downstream apps that
	// want the full set re-run conflict detection with increased limits.
	MaxWitnesses = 5

	// LowCoverageThreshold is the per-pair fixtures_matched cutoff for
	// the corpus_coverage.low_coverage flag. Keyed on *matched*, not
	// *evaluated*, so a pair with thousands of evaluated fixtures and
	// zero matched (the shared overlap path never resolved on any
	// asset) is correctly flagged as low-coverage rather than
	// well-covered. Stave policy decision; downstream consumers with
	// different cutoffs apply their own on the raw fixtures_matched
	// count.
	LowCoverageThreshold = 5
)

// Report is the in-memory model of a ConflictReport, marshaled to JSON
// matching ontology/v0.1/conflict-report.schema.json.
type Report struct {
	ReportID             string         `json:"report_id"`
	CatalogVersion       string         `json:"catalog_version"`
	FixtureCorpusVersion string         `json:"fixture_corpus_version"`
	GeneratedAt          string         `json:"generated_at"`
	StaveVersion         string         `json:"stave_version"`
	Pairs                []ConflictPair `json:"pairs"`
	AnalysisGaps         []AnalysisGap  `json:"analysis_gaps"`
}

// ConflictPair is one classified pair as it appears in the report.
// Payload is one of the four category-specific payload structs. The
// schema's if/then discriminator on category enforces this at validation.
type ConflictPair struct {
	Category       ConflictCategory `json:"category"`
	ControlA       string           `json:"control_a"`
	ControlB       string           `json:"control_b"`
	CorpusCoverage CorpusCoverage   `json:"corpus_coverage"`
	Payload        any              `json:"payload"`
}

// CorpusCoverage carries the per-pair evidence weight. low_coverage is
// derived from fixtures_evaluated and the Stave-level threshold so
// downstream apps don't have to re-derive it.
type CorpusCoverage struct {
	FixturesEvaluated int    `json:"fixtures_evaluated"`
	FixturesMatched   int    `json:"fixtures_matched"`
	CorpusVersion     string `json:"corpus_version"`
	LowCoverage       bool   `json:"low_coverage"`
}

// Witness is a single fixture observation in a CONTRADICTION or
// DIVERGENCE payload. ObservedValues populated for CONTRADICTION,
// DifferingValues for DIVERGENCE — only one is set per call site so the
// pointer-typed maps marshal as either present or absent (omitempty).
type Witness struct {
	FixturePath     string         `json:"fixture_path"`
	AssetID         string         `json:"asset_id"`
	VerdictA        string         `json:"verdict_a"`
	VerdictB        string         `json:"verdict_b"`
	ObservedValues  map[string]any `json:"observed_values,omitempty"`
	DifferingValues map[string]any `json:"differing_values,omitempty"`
	Diagnostic      string         `json:"diagnostic,omitempty"`
}

// ContradictionPayload — opposing verdicts on the shared dependency set.
// SharedDependencies is non-empty by construction.
type ContradictionPayload struct {
	Subcategory           ContradictionSubcategory `json:"subcategory"`
	SharedDependencies    []string                 `json:"shared_dependencies"`
	DisagreementWitnesses []Witness                `json:"disagreement_witnesses"`
	WitnessesTruncated    bool                     `json:"witnesses_truncated"`
}

// RedundancyPayload — identical behavior across every overlap dimension.
// Compliance and remediation are hashed (not inlined) so the report does
// not duplicate catalog content that can drift independently.
type RedundancyPayload struct {
	SharedDependencies    []string `json:"shared_dependencies"`
	SharedComplianceHash  string   `json:"shared_compliance_hash"`
	SharedAttackStage     string   `json:"shared_attack_stage"`
	SharedRemediationHash string   `json:"shared_remediation_hash"`
}

// EmpiricalSubsumptionPayload — narrower's deps strictly contained in
// broader's, and narrower's VIOLATIONs imply broader's VIOLATIONs across
// the current corpus. Empirical, not a static-subsumption proof.
type EmpiricalSubsumptionPayload struct {
	Narrower        string   `json:"narrower"`
	Broader         string   `json:"broader"`
	DependencyDelta []string `json:"dependency_delta"`
}

// DivergencePayload — overlapping deps with verdict agreement < 100%.
// Informational; surfaces minimal-disagreement witnesses with the
// differing-path values that explain the boundary.
type DivergencePayload struct {
	SharedDependencies          []string  `json:"shared_dependencies"`
	AgreementRate               float64   `json:"agreement_rate"`
	MinimalDisagreementFixtures []Witness `json:"minimal_disagreement_fixtures"`
	WitnessesTruncated          bool      `json:"witnesses_truncated"`
}

// GapReason matches the schema's AnalysisGap.reason enum.
type GapReason string

const (
	GapAliasedPredicate  GapReason = "ALIASED_PREDICATE"
	GapNoFixtureCoverage GapReason = "NO_FIXTURE_COVERAGE"
	GapExtractionFailed  GapReason = "EXTRACTION_FAILED"
)

// AnalysisGap is a single coverage gap. Control-level gaps
// (ALIASED_PREDICATE, EXTRACTION_FAILED) carry one control ID;
// pair-level gaps (NO_FIXTURE_COVERAGE) carry two, lex-sorted.
type AnalysisGap struct {
	Reason   GapReason `json:"reason"`
	Controls []string  `json:"controls"`
	Detail   string    `json:"detail"`
}

// ExtractionFailure is a per-control extraction error from the catalog
// pre-pass (Node 3a). Threaded into the renderer separately because
// pair enumeration filtered these controls out — they do not appear in
// any ClassifiedPair, so the renderer needs them as a distinct input.
type ExtractionFailure struct {
	ControlID string
	Err       string
}

// ReportInputs bundles everything BuildReport needs. Separating inputs
// from the Report struct itself keeps the renderer testable in isolation
// and makes it explicit that aliased / extraction-failed gaps must be
// passed in — they cannot be inferred from the ClassifiedPair slice.
type ReportInputs struct {
	Classified           []ClassifiedPair
	AliasedControls      []string            // from AnalysisStats.SkippedAliased
	ExtractionFailures   []ExtractionFailure // bugs to investigate
	CatalogVersion       string
	FixtureCorpusVersion string
	StaveVersion         string
	GeneratedAt          time.Time
}

// BuildReport assembles a Report from classified pairs and catalog-level
// gap inputs. Pure function: same inputs (modulo GeneratedAt, which does
// not feed report_id) produce a byte-identical report.
//
// Pairs are sorted by (category, control_a, control_b); witnesses are
// lex-sorted and capped at MaxWitnesses. Uncategorized pairs (empty
// Category) are dropped from the report — they are not a finding —
// except that their pair-level NO_FIXTURE_COVERAGE gaps surface in
// analysis_gaps.
func BuildReport(in ReportInputs) Report {
	pairs := make([]ConflictPair, 0, len(in.Classified))
	var coverageGaps []AnalysisGap

	sorted := SortByCategory(in.Classified)
	for i := range sorted {
		cp := &sorted[i]

		if cp.FixturesMatched == 0 {
			// Pair has no evidence on the shared overlap. Either the
			// corpus had zero fixtures touching these controls, or the
			// fixtures were evaluated but none carried the shared
			// dependency path. Both collapse to NO_FIXTURE_COVERAGE —
			// the latter case is the matched-vs-evaluated distinction
			// (see PRECEDENCE.md). Without it, a pair with 1000
			// co-evaluations and 0 matched silently disappears from
			// the report instead of surfacing as a gap.
			coverageGaps = append(coverageGaps, AnalysisGap{
				Reason:   GapNoFixtureCoverage,
				Controls: lexPair(cp.ControlA, cp.ControlB),
				Detail:   fmt.Sprintf("no fixture in the corpus resolved values for shared dependency paths: %v", cp.Overlap),
			})
			continue
		}

		if cp.Category == "" {
			continue
		}

		pairs = append(pairs, ConflictPair{
			Category:       cp.Category,
			ControlA:       cp.ControlA,
			ControlB:       cp.ControlB,
			CorpusCoverage: buildCoverage(cp, in.FixtureCorpusVersion),
			Payload:        buildPayload(cp),
		})
	}

	gaps := make([]AnalysisGap, 0,
		len(in.AliasedControls)+len(in.ExtractionFailures)+len(coverageGaps))
	for _, id := range in.AliasedControls {
		gaps = append(gaps, AnalysisGap{
			Reason:   GapAliasedPredicate,
			Controls: []string{id},
			Detail:   "control uses unsafe_predicate_alias; static dependency extraction does not yet expand aliases. Conflicts involving this control are not detected in this run.",
		})
	}
	for _, ef := range in.ExtractionFailures {
		gaps = append(gaps, AnalysisGap{
			Reason:   GapExtractionFailed,
			Controls: []string{ef.ControlID},
			Detail:   ef.Err,
		})
	}
	gaps = append(gaps, coverageGaps...)
	sortGaps(gaps)

	return Report{
		ReportID:             deriveReportID(in.CatalogVersion, in.FixtureCorpusVersion),
		CatalogVersion:       in.CatalogVersion,
		FixtureCorpusVersion: in.FixtureCorpusVersion,
		GeneratedAt:          in.GeneratedAt.UTC().Format(time.RFC3339),
		StaveVersion:         in.StaveVersion,
		Pairs:                pairs,
		AnalysisGaps:         gaps,
	}
}

// Marshal returns the canonical JSON encoding of the report. Field order
// is fixed by the struct declarations; map keys are sorted alphabetically
// by encoding/json. Indented for human inspection — downstream consumers
// that want compact form can re-marshal.
func (r Report) Marshal() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// deriveReportID returns "sha256:" plus the first 16 hex characters of
// SHA-256(catalog_version + "|" + fixture_corpus_version). Same inputs →
// same ID. Truncation matches the schema: a 16-char prefix is enough to
// distinguish reports across a reasonable corpus history without padding
// every CLI line.
func deriveReportID(catalog, corpus string) string {
	sum := sha256.Sum256([]byte(catalog + "|" + corpus))
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

func buildCoverage(cp *ClassifiedPair, corpusVersion string) CorpusCoverage {
	return CorpusCoverage{
		FixturesEvaluated: cp.FixturesEvaluated,
		FixturesMatched:   cp.FixturesMatched,
		CorpusVersion:     corpusVersion,
		LowCoverage:       cp.FixturesMatched < LowCoverageThreshold,
	}
}

func buildPayload(cp *ClassifiedPair) any {
	switch cp.Category {
	case CategoryContradiction:
		return buildContradiction(cp)
	case CategoryRedundancy:
		return buildRedundancy(cp)
	case CategoryEmpiricalSubsumption:
		return buildEmpiricalSubsumption(cp)
	case CategoryDivergence:
		return buildDivergence(cp)
	default:
		return nil
	}
}

func buildContradiction(cp *ClassifiedPair) ContradictionPayload {
	disagreements := disagreementWitnesses(matchedCoEvaluations(cp.CoEvaluations))
	witnesses, truncated := selectWitnesses(disagreements, cp.Overlap, true)
	return ContradictionPayload{
		Subcategory:           cp.ContradictionSubcategory,
		SharedDependencies:    cloneSorted(cp.Overlap),
		DisagreementWitnesses: witnesses,
		WitnessesTruncated:    truncated,
	}
}

func buildRedundancy(cp *ClassifiedPair) RedundancyPayload {
	return RedundancyPayload{
		SharedDependencies:    cloneSorted(cp.Overlap),
		SharedComplianceHash:  HashSHA256(cp.MetadataA.ComplianceCanonical),
		SharedAttackStage:     cp.MetadataA.AttackStage,
		SharedRemediationHash: HashSHA256(cp.MetadataA.RemediationCanonical),
	}
}

func buildEmpiricalSubsumption(cp *ClassifiedPair) EmpiricalSubsumptionPayload {
	narrowerDeps, broaderDeps := cp.DepsA, cp.DepsB
	if cp.Narrower == cp.ControlB {
		narrowerDeps, broaderDeps = cp.DepsB, cp.DepsA
	}
	return EmpiricalSubsumptionPayload{
		Narrower:        cp.Narrower,
		Broader:         cp.Broader,
		DependencyDelta: subtractSorted(broaderDeps, narrowerDeps),
	}
}

func buildDivergence(cp *ClassifiedPair) DivergencePayload {
	disagreements := disagreementWitnesses(matchedCoEvaluations(cp.CoEvaluations))
	witnesses, truncated := selectWitnesses(disagreements, cp.Overlap, false)
	return DivergencePayload{
		SharedDependencies:          cloneSorted(cp.Overlap),
		AgreementRate:               cp.AgreementRate(),
		MinimalDisagreementFixtures: witnesses,
		WitnessesTruncated:          truncated,
	}
}

// selectWitnesses picks up to MaxWitnesses from the disagreements,
// lex-sorted by (fixture_path, asset_id), and packs values per category:
// contradiction=true → observed_values from the overlap subset of
// PathValues; contradiction=false (DIVERGENCE) → differing_values from
// PathValues outside the overlap. Returns the chosen witnesses and the
// truncated flag (true when len(disagreements) > MaxWitnesses).
//
// Precondition: disagreements are already lex-sorted by (FixturePath,
// AssetID) (EvaluatePairs guarantees this); we re-sort defensively so a
// future caller that bypasses EvaluatePairs cannot silently produce
// non-deterministic output.
func selectWitnesses(disagreements []CoEvaluation, overlap []string, contradiction bool) ([]Witness, bool) {
	sorted := slices.Clone(disagreements)
	slices.SortFunc(sorted, func(a, b CoEvaluation) int {
		if c := compareString(a.FixturePath, b.FixturePath); c != 0 {
			return c
		}
		return compareString(a.AssetID, b.AssetID)
	})

	truncated := len(sorted) > MaxWitnesses
	if truncated {
		sorted = sorted[:MaxWitnesses]
	}

	overlapSet := make(map[string]struct{}, len(overlap))
	for _, p := range overlap {
		overlapSet[p] = struct{}{}
	}

	witnesses := make([]Witness, 0, len(sorted))
	for i := range sorted {
		ce := &sorted[i]
		w := Witness{
			FixturePath: ce.FixturePath,
			AssetID:     ce.AssetID,
			VerdictA:    verdictString(ce.UnsafeA),
			VerdictB:    verdictString(ce.UnsafeB),
		}
		if contradiction {
			w.ObservedValues = filterMap(ce.PathValues, overlapSet, true)
		} else {
			w.DifferingValues = filterMap(ce.PathValues, overlapSet, false)
		}
		witnesses = append(witnesses, w)
	}
	return witnesses, truncated
}

// filterMap returns a subset of values whose keys are (in/out) of the
// overlap set. Returns nil rather than an empty map so encoding/json
// omits the field via omitempty when no relevant values exist.
func filterMap(values map[string]any, overlap map[string]struct{}, inOverlap bool) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for k, v := range values {
		_, ok := overlap[k]
		if ok == inOverlap {
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func verdictString(unsafe bool) string {
	if unsafe {
		return "VIOLATION"
	}
	return "PASS"
}

// sortGaps orders gaps by (reason, first control id) per the schema.
func sortGaps(gaps []AnalysisGap) {
	slices.SortFunc(gaps, func(a, b AnalysisGap) int {
		if c := compareString(string(a.Reason), string(b.Reason)); c != 0 {
			return c
		}
		if len(a.Controls) == 0 || len(b.Controls) == 0 {
			return len(a.Controls) - len(b.Controls)
		}
		if c := compareString(a.Controls[0], b.Controls[0]); c != 0 {
			return c
		}
		// Stable secondary key for pair-level gaps (NO_FIXTURE_COVERAGE).
		if len(a.Controls) > 1 && len(b.Controls) > 1 {
			return compareString(a.Controls[1], b.Controls[1])
		}
		return 0
	})
}

func lexPair(a, b string) []string {
	if a <= b {
		return []string{a, b}
	}
	return []string{b, a}
}

func cloneSorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// subtractSorted returns a \ b assuming both are lex-sorted. Output is
// sorted. Used for EmpiricalSubsumption.dependency_delta (broader \ narrower).
func subtractSorted(a, b []string) []string {
	out := make([]string, 0, len(a))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			i++
			j++
		case a[i] < b[j]:
			out = append(out, a[i])
			i++
		default:
			j++
		}
	}
	out = append(out, a[i:]...)
	return out
}
