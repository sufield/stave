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
	"encoding/json"
	"fmt"
	"sort"
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

// Report is the three-list coverage outcome.
type Report struct {
	Framework        string           `json:"framework"`
	FrameworkVersion string           `json:"framework_version"`
	TotalControls    int              `json:"total_controls"`
	Covered          []ControlResult  `json:"covered"`
	Gaps             []ControlResult  `json:"gaps"`
	OutOfScope       []ControlResult  `json:"out_of_scope"`
	InScope          int              `json:"in_scope"` // covered + gaps
	Verified         int              `json:"verified"` // == len(covered)
	Passed           int              `json:"passed"`
	Failed           int              `json:"failed"`
	CoveragePercent  float64          `json:"coverage_percent"` // verified / in_scope * 100
	Integrity        *IntegrityReport `json:"integrity,omitempty"`
	VerifyOnly       bool             `json:"-"` // --verify-mapping: render only the integrity block
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
	sort.Strings(rep.DuplicateIDs)
	sort.Strings(rep.PartialNoReason)
	sort.Slice(rep.DanglingRefs, func(i, j int) bool {
		if rep.DanglingRefs[i].FrameworkID != rep.DanglingRefs[j].FrameworkID {
			return rep.DanglingRefs[i].FrameworkID < rep.DanglingRefs[j].FrameworkID
		}
		return rep.DanglingRefs[i].StaveControl < rep.DanglingRefs[j].StaveControl
	})
	sort.Slice(rep.InvalidConfidence, func(i, j int) bool {
		return rep.InvalidConfidence[i].FrameworkID < rep.InvalidConfidence[j].FrameworkID
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
	byID := func(s []ControlResult) { sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID }) }
	byID(rep.Covered)
	byID(rep.Gaps)
	byID(rep.OutOfScope)

	rep.Verified = len(rep.Covered)
	rep.InScope = len(rep.Covered) + len(rep.Gaps)
	if rep.InScope > 0 {
		rep.CoveragePercent = float64(rep.Verified) / float64(rep.InScope) * 100
	}
	return rep
}
