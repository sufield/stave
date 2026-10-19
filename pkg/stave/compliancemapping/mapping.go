// Package compliancemapping loads a framework→Stave control mapping and turns a
// set of Stave findings into a per-framework-control coverage report: which
// framework controls Stave verified (PASS/FAIL), which are in scope but have no
// Stave control yet (gaps), and which are out of Stave's scope
// (organizational/runtime/physical).
//
// The mapping data is embedded JSON (see embed.go); the input is the set of
// Stave control IDs that produced a violation finding. The logic is pure — it
// holds no Stave evaluation types — so it unit-tests without the engine.
package compliancemapping

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Mapping is the embedded framework→Stave mapping document.
type Mapping struct {
	Framework        string   `json:"framework"`
	FrameworkVersion string   `json:"framework_version"`
	MappingVersion   string   `json:"mapping_version"`
	TotalControls    int      `json:"total_controls"`
	Domains          []Domain `json:"domains"`
}

// Domain groups framework controls.
type Domain struct {
	Domain        string          `json:"domain"`
	TotalControls int             `json:"total_controls"`
	Controls      []MappedControl `json:"controls"`
}

// MappedControl is one framework control and its Stave mapping.
type MappedControl struct {
	ID            string   `json:"aicm_id"`
	Title         string   `json:"aicm_title"`
	Type          string   `json:"aicm_type"`
	Scope         string   `json:"scope"`
	StaveControls []string `json:"stave_controls"`
	Coverage      string   `json:"coverage"`
	Notes         string   `json:"notes"`
	// Confidence records HOW the mapping was determined: "direct" (the framework
	// control names the property Stave checks) or "inferred" (the framework
	// control implies it). Empty defaults to "inferred" for backward compatibility.
	Confidence string `json:"confidence,omitempty"`
	// UncoveredAspects names what a partial mapping does NOT cover. Expected
	// (warned if absent) when Coverage is "partial".
	UncoveredAspects string `json:"uncovered_aspects,omitempty"`
}

// Confidence values.
const (
	ConfidenceDirect   = "direct"
	ConfidenceInferred = "inferred"
)

// ConfidenceOrDefault returns the recorded confidence, defaulting an empty
// value to "inferred" (backward compatibility with mappings authored before
// the field existed).
func (c MappedControl) ConfidenceOrDefault() string {
	if c.Confidence == "" {
		return ConfidenceInferred
	}
	return c.Confidence
}

// Coverage values used in the mapping.
const (
	coverageFull        = "full"
	coveragePartial     = "partial"
	coverageNone        = "none"
	coverageOOSRuntime  = "out_of_scope_runtime"
	coverageOOSOrgnztnl = "out_of_scope_organizational"
)

// Status is the per-framework-control outcome.
type Status string

const (
	StatusPass        Status = "PASS"         // mapped controls ran, none violated
	StatusFail        Status = "FAIL"         // ≥1 mapped control violated
	StatusNotVerified Status = "NOT_VERIFIED" // in scope, no Stave control yet (gap)
	StatusOutOfScope  Status = "OUT_OF_SCOPE" // organizational/runtime/physical
)

// Bucket is the actionability section a control lands in.
type Bucket string

const (
	BucketCovered    Bucket = "covered"
	BucketGap        Bucket = "gap"
	BucketOutOfScope Bucket = "out_of_scope"
)

// CoveragePercent encapsulates compliance mapping coverage percentage in [0.0, 100.0].
type CoveragePercent float64

// Float64 returns the raw float64 percentage value.
func (cp CoveragePercent) Float64() float64 {
	return float64(cp)
}

// Ratio returns the coverage percentage expressed as a ratio in [0.0, 1.0].
func (cp CoveragePercent) Ratio() float64 {
	return float64(cp) / 100.0
}

// IsComplete reports whether coverage is 100%.
func (cp CoveragePercent) IsComplete() bool {
	return cp >= 100.0
}

// IsZero reports whether coverage is zero.
func (cp CoveragePercent) IsZero() bool {
	return cp <= 0.0
}

// ControlResult is the evaluated outcome for one framework control.
type ControlResult struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Type           string   `json:"type"`
	Status         Status   `json:"status"`
	Bucket         Bucket   `json:"bucket"`
	Partial        bool     `json:"partial,omitempty"`           // covered, but mapping is partial
	StaveControls  []string `json:"stave_controls,omitempty"`    // mapped controls run
	FailedControls []string `json:"failed_controls,omitempty"`   // subset that violated (FAIL)
	OutOfScopeKind string   `json:"out_of_scope_kind,omitempty"` // ORGANIZATIONAL | RUNTIME
	Detail         string   `json:"detail,omitempty"`            // gap/OOS rationale (from notes)
	Confidence     string   `json:"confidence,omitempty"`        // direct | inferred (covered only)
	Uncovered      string   `json:"uncovered_aspects,omitempty"` // partial coverage: what's not covered
}

// IsPassing reports whether the framework control passed verification.
func (c ControlResult) IsPassing() bool {
	return c.Status == StatusPass
}

// IsFailing reports whether the framework control failed verification.
func (c ControlResult) IsFailing() bool {
	return c.Status == StatusFail
}

// IsNotVerified reports whether the framework control is not verified (gap).
func (c ControlResult) IsNotVerified() bool {
	return c.Status == StatusNotVerified
}

// IsOutOfScope reports whether the framework control is out of scope.
func (c ControlResult) IsOutOfScope() bool {
	return c.Status == StatusOutOfScope
}

// CoveredDetail returns a human-readable description of how the control is covered.
func (c ControlResult) CoveredDetail() string {
	var base string
	switch {
	case c.IsFailing():
		base = fmt.Sprintf("%d Stave control(s) failed", len(c.FailedControls))
	case c.Partial:
		base = fmt.Sprintf("%d control(s) verified, partial mapping", len(c.StaveControls))
	default:
		base = fmt.Sprintf("%d Stave control(s) verified", len(c.StaveControls))
	}
	if c.Confidence != "" {
		base += " [" + c.Confidence + "]"
	}
	if c.Partial && c.Uncovered != "" {
		base += ": " + c.Uncovered
	}
	return base
}

// ControlResults is a domain collection of ControlResult items with querying methods.
type ControlResults []ControlResult

// Len returns the count of control results in the collection.
func (cr ControlResults) Len() int {
	return len(cr)
}

// IsEmpty reports whether the collection contains no control results.
func (cr ControlResults) IsEmpty() bool {
	return len(cr) == 0
}

// HasControls reports whether the collection contains at least one control result.
func (cr ControlResults) HasControls() bool {
	return len(cr) > 0
}

// Passing returns a new collection containing only passing control results.
func (cr ControlResults) Passing() ControlResults {
	if len(cr) == 0 {
		return nil
	}
	var filtered ControlResults
	for i := range cr {
		if cr[i].IsPassing() {
			filtered = append(filtered, cr[i])
		}
	}
	return filtered
}

// Failing returns a new collection containing only failing control results.
func (cr ControlResults) Failing() ControlResults {
	if len(cr) == 0 {
		return nil
	}
	var filtered ControlResults
	for i := range cr {
		if cr[i].IsFailing() {
			filtered = append(filtered, cr[i])
		}
	}
	return filtered
}

// Partial returns a new collection containing only partially covered control results.
func (cr ControlResults) Partial() ControlResults {
	if len(cr) == 0 {
		return nil
	}
	var filtered ControlResults
	for i := range cr {
		if cr[i].Partial {
			filtered = append(filtered, cr[i])
		}
	}
	return filtered
}

// Report is the three-list coverage outcome.
type Report struct {
	Framework        string           `json:"framework"`
	FrameworkVersion string           `json:"framework_version"`
	TotalControls    int              `json:"total_controls"`
	Covered          ControlResults   `json:"covered"`
	Gaps             ControlResults   `json:"gaps"`
	OutOfScope       ControlResults   `json:"out_of_scope"`
	InScope          int              `json:"in_scope"` // covered + gaps
	Verified         int              `json:"verified"` // == len(covered)
	Passed           int              `json:"passed"`
	Failed           int              `json:"failed"`
	CoveragePercent  CoveragePercent  `json:"coverage_percent"` // verified / in_scope * 100
	Integrity        *IntegrityReport `json:"integrity,omitempty"`
	VerifyOnly       bool             `json:"-"` // --verify-mapping: render only the integrity block
}

// HasGaps reports whether there are in-scope controls without Stave verification.
func (r Report) HasGaps() bool {
	return r.Gaps.HasControls()
}

// IsFullyCovered reports whether all in-scope controls are verified (100% coverage).
func (r Report) IsFullyCovered() bool {
	return r.InScope > 0 && r.CoveragePercent.IsComplete()
}

// IntegrityReport is the mapping self-check: does the mapping file reference
// only real catalog controls, have unique IDs, and carry well-formed
// confidence/uncovered_aspects metadata. It is the deterministic, premise-
// independent part of "self-verifying mapping" — it does NOT cross-check the
// curated framework mapping against controls' own compliance: keys, because in
// this catalog those are an independent attribution layer (CCM/SOC2), not a
// second source of the same framework's IDs.
type IntegrityReport struct {
	Framework         string            `json:"framework"`
	DanglingRefs      []DanglingRef     `json:"dangling_refs"`       // ERROR: maps a non-existent control
	DuplicateIDs      []string          `json:"duplicate_ids"`       // ERROR: aicm_id appears twice
	InvalidConfidence []ConfidenceIssue `json:"invalid_confidence"`  // ERROR: confidence not direct|inferred
	PartialNoReason   []string          `json:"partial_no_reason"`   // WARN: partial coverage, empty uncovered_aspects
	ReferencedControl int               `json:"referenced_controls"` // distinct Stave controls the mapping uses
	CatalogTotal      int               `json:"catalog_total"`       // controls in the catalog (0 = not loaded)
}

// DanglingRef is a mapping entry pointing at a control that is not in the catalog.
type DanglingRef struct {
	FrameworkID  string `json:"framework_id"`
	StaveControl string `json:"stave_control"`
}

// ConfidenceIssue is a mapping entry with an unrecognized confidence value.
type ConfidenceIssue struct {
	FrameworkID string `json:"framework_id"`
	Value       string `json:"value"`
}

// HasErrors reports gating problems (dangling refs, duplicate IDs, invalid
// confidence). These are what --strict refuses to produce a report over.
func (r IntegrityReport) HasErrors() bool {
	return len(r.DanglingRefs) > 0 || len(r.DuplicateIDs) > 0 || len(r.InvalidConfidence) > 0
}

// HasWarnings reports non-gating issues (partial coverage missing a reason).
func (r IntegrityReport) HasWarnings() bool { return len(r.PartialNoReason) > 0 }

// Verify cross-references the mapping against the real control catalog. Pass
// the set of catalog control IDs; an empty set skips the dangling-reference
// check (so a failed catalog load does not flag every reference). Pure: no
// Stave evaluation types, unit-testable without the engine.
func (m *Mapping) Verify(catalogIDs map[string]bool) IntegrityReport {
	rep := IntegrityReport{
		Framework:         m.Framework,
		DanglingRefs:      []DanglingRef{},
		DuplicateIDs:      []string{},
		InvalidConfidence: []ConfidenceIssue{},
		PartialNoReason:   []string{},
		CatalogTotal:      len(catalogIDs),
	}
	seen := map[string]bool{}
	distinct := map[string]bool{}
	for di := range m.Domains {
		for ci := range m.Domains[di].Controls {
			c := &m.Domains[di].Controls[ci]
			if seen[c.ID] {
				rep.DuplicateIDs = append(rep.DuplicateIDs, c.ID)
			}
			seen[c.ID] = true
			if c.Confidence != "" && c.Confidence != ConfidenceDirect && c.Confidence != ConfidenceInferred {
				rep.InvalidConfidence = append(rep.InvalidConfidence, ConfidenceIssue{FrameworkID: c.ID, Value: c.Confidence})
			}
			if c.Coverage == coveragePartial && strings.TrimSpace(c.UncoveredAspects) == "" {
				rep.PartialNoReason = append(rep.PartialNoReason, c.ID)
			}
			for _, sc := range c.StaveControls {
				distinct[sc] = true
				if len(catalogIDs) > 0 && !catalogIDs[sc] {
					rep.DanglingRefs = append(rep.DanglingRefs, DanglingRef{FrameworkID: c.ID, StaveControl: sc})
				}
			}
		}
	}
	rep.ReferencedControl = len(distinct)
	slices.Sort(rep.DuplicateIDs)
	slices.Sort(rep.PartialNoReason)
	slices.SortFunc(rep.DanglingRefs, func(a, b DanglingRef) int {
		if c := cmp.Compare(a.FrameworkID, b.FrameworkID); c != 0 {
			return c
		}
		return cmp.Compare(a.StaveControl, b.StaveControl)
	})
	slices.SortFunc(rep.InvalidConfidence, func(a, b ConfidenceIssue) int {
		return cmp.Compare(a.FrameworkID, b.FrameworkID)
	})
	return rep
}

// HasFailures reports whether any covered control failed — used to map to exit 3.
func (r Report) HasFailures() bool { return r.Failed > 0 }

// Load returns the embedded mapping for a framework name (e.g. "aicm-v1.1").
func Load(framework string) (*Mapping, error) {
	name, ok := frameworkFiles[framework]
	if !ok {
		return nil, fmt.Errorf("unknown framework %q (supported: %s)", framework, SupportedFrameworks())
	}
	data, err := dataFS.ReadFile("data/" + name)
	if err != nil {
		return nil, fmt.Errorf("read embedded mapping %q: %w", name, err)
	}
	var m Mapping
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse embedded mapping %q: %w", name, err)
	}
	return &m, nil
}

// Evaluate classifies every framework control into covered/gap/out-of-scope,
// deriving PASS/FAIL for covered controls from the set of Stave control IDs that
// produced a violation. Lists come back sorted by framework control ID.
func (m *Mapping) Evaluate(violated map[string]bool) Report {
	rep := Report{
		Framework:        m.Framework,
		FrameworkVersion: m.FrameworkVersion,
		TotalControls:    m.TotalControls,
		// Non-nil so JSON renders [] (not null) when a bucket is empty — e.g.
		// zero in-scope gaps. The empty-array shape is part of the contract.
		Covered:    []ControlResult{},
		Gaps:       []ControlResult{},
		OutOfScope: []ControlResult{},
	}
	for di := range m.Domains {
		for ci := range m.Domains[di].Controls {
			c := &m.Domains[di].Controls[ci]
			switch c.Coverage {
			case coverageFull, coveragePartial:
				res := ControlResult{
					ID: c.ID, Title: c.Title, Type: c.Type,
					Bucket: BucketCovered, Partial: c.Coverage == coveragePartial,
					StaveControls: c.StaveControls,
					Confidence:    c.ConfidenceOrDefault(),
					Uncovered:     c.UncoveredAspects,
				}
				var failed []string
				for _, sc := range c.StaveControls {
					if violated[sc] {
						failed = append(failed, sc)
					}
				}
				if len(failed) > 0 {
					res.Status = StatusFail
					res.FailedControls = failed
					rep.Failed++
				} else {
					res.Status = StatusPass
					rep.Passed++
				}
				rep.Covered = append(rep.Covered, res)
			case coverageNone:
				rep.Gaps = append(rep.Gaps, ControlResult{
					ID: c.ID, Title: c.Title, Type: c.Type,
					Status: StatusNotVerified, Bucket: BucketGap, Detail: c.Notes,
				})
			case coverageOOSRuntime, coverageOOSOrgnztnl:
				kind := "ORGANIZATIONAL"
				if c.Coverage == coverageOOSRuntime {
					kind = "RUNTIME"
				}
				rep.OutOfScope = append(rep.OutOfScope, ControlResult{
					ID: c.ID, Title: c.Title, Type: c.Type,
					Status: StatusOutOfScope, Bucket: BucketOutOfScope,
					OutOfScopeKind: kind, Detail: c.Notes,
				})
			}
		}
	}
	byID := func(s []ControlResult) {
		slices.SortFunc(s, func(a, b ControlResult) int { return cmp.Compare(a.ID, b.ID) })
	}
	byID(rep.Covered)
	byID(rep.Gaps)
	byID(rep.OutOfScope)

	rep.Verified = len(rep.Covered)
	rep.InScope = len(rep.Covered) + len(rep.Gaps)
	if rep.InScope > 0 {
		rep.CoveragePercent = CoveragePercent(float64(rep.Verified) / float64(rep.InScope) * 100)
	}
	return rep
}
