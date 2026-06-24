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
}

// Report is the three-list coverage outcome.
type Report struct {
	Framework        string          `json:"framework"`
	FrameworkVersion string          `json:"framework_version"`
	TotalControls    int             `json:"total_controls"`
	Covered          []ControlResult `json:"covered"`
	Gaps             []ControlResult `json:"gaps"`
	OutOfScope       []ControlResult `json:"out_of_scope"`
	InScope          int             `json:"in_scope"` // covered + gaps
	Verified         int             `json:"verified"` // == len(covered)
	Passed           int             `json:"passed"`
	Failed           int             `json:"failed"`
	CoveragePercent  float64         `json:"coverage_percent"` // verified / in_scope * 100
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
	for _, d := range m.Domains {
		for _, c := range d.Controls {
			switch c.Coverage {
			case coverageFull, coveragePartial:
				res := ControlResult{
					ID: c.ID, Title: c.Title, Type: c.Type,
					Bucket: BucketCovered, Partial: c.Coverage == coveragePartial,
					StaveControls: c.StaveControls,
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
