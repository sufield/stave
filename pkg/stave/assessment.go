package stave

import (
	"time"

	"github.com/sufield/stave/internal/core/evaluation/coverage"
)

// Assessment is the full result of [Apply]. The shape is a trimmed
// view of the internal evaluation report; fields not listed here
// are omitted by design. Add fields when a consumer demonstrates a
// concrete need.
type Assessment struct {
	// SchemaVersion identifies the evaluation output schema
	// version (e.g. "out.v0.1").
	SchemaVersion string

	// Status is the high-level security posture.
	Status Status

	// Run records metadata about the evaluation execution.
	Run RunInfo

	// Summary is the aggregate counts view.
	Summary Summary

	// Findings is every per-(control, asset) violation, ordered
	// by ExposureScore descending with deterministic tiebreakers.
	Findings []Finding

	// MarkerFindings are fact-recording findings emitted by
	// TypeMarker controls (e.g. "this S3 bucket is tagged
	// data-classification=phi"). They participate in chain
	// detection so cross-resource compounds can compose them with
	// violation findings, but never count toward Status,
	// Summary.Violations, or exit codes. Empty when the catalog
	// has no marker controls.
	MarkerFindings []Finding

	// Issues consolidates findings that share a root cause. One
	// underlying misconfiguration produces one Issue regardless
	// of how many controls fire on it. Every finding is a member
	// of exactly one Issue.
	Issues []Issue

	// Coverage aggregates per-tool, per-domain coverage posture
	// derived from the control catalog's alternatives annotations.
	// Empty when no alternatives are authored or no inventories
	// are bundled.
	Coverage CoveragePosture

	// SilentRiskControls lists controls that may have produced
	// false PASS verdicts because required observation fields were
	// absent. When non-empty, the assessment's violation count may
	// undercount the true risk. Consumers should treat these as
	// "findings we can't produce yet" rather than "no problem."
	SilentRiskControls []SilentRiskControl

	// ChainFindings are compound-risk chains detected during
	// evaluation — sets of co-failing controls that together
	// represent a compound attack path. Each ChainFinding
	// references individual member findings via ControlsFailing
	// (and every matching finding carries the reverse link in its
	// ChainMembership slice).
	//
	// Empty when Config.ChainsDir is unset and no embedded chain
	// catalog is bundled, OR when no chain's escalation threshold
	// was met on the observation set.
	ChainFindings []ChainFinding

	// SLABreaches counts the findings whose dwell time exceeded
	// their severity-specific SLA deadline. Always 0 when
	// [Config.SLAConfig] is nil. Use this for high-level
	// dashboards; per-finding breach context lives on
	// [Finding.SLABreached] / SLAOverdueHours.
	SLABreaches int
}

// RunInfo records execution metadata for the evaluation.
type RunInfo struct {
	// StaveVersion is the engine version that produced this
	// assessment.
	StaveVersion string

	// Now is the evaluator's effective current time (either the
	// caller-supplied Config.Now or the real clock at run time).
	Now time.Time

	// MaxUnsafe is the maximum-unsafe-duration threshold used
	// during evaluation.
	MaxUnsafe time.Duration

	// Snapshots is the number of observation snapshots consumed.
	Snapshots int
}

// Summary is the aggregate counts view over an evaluation run.
type Summary struct {
	// TotalAssets is the count of distinct assets evaluated.
	TotalAssets int

	// ExposedResources is the count of assets with at least one
	// finding.
	ExposedResources int

	// Violations is the total finding count (per-control,
	// per-asset). Equal to len(Assessment.Findings).
	Violations int

	// FrameworkReadiness reports per-framework compliance scoring.
	// Populated when controls in the catalog declare framework
	// citations; empty otherwise. Used by [Score] for the
	// coverage component when a Compliance filter is supplied.
	FrameworkReadiness []FrameworkReadiness
}

// FrameworkReadiness is the per-framework readiness summary.
// Mirrored from the internal evaluation type so the public surface
// stays stable across engine refactors.
type FrameworkReadiness struct {
	Framework        string
	TotalControls    int
	PassingControls  int
	ReadinessPercent int
}

// CoveragePosture is the per-tool, per-domain coverage aggregation.
// Aliased from the internal coverage package; shape is consumer-
// friendly (outer key: tool identifier; inner key: domain).
type CoveragePosture = coverage.CoverageIndex

// DomainCoverage is the per-(tool, domain) coverage summary.
// Aliased for the same reason as [CoveragePosture].
type DomainCoverage = coverage.DomainCoverage
