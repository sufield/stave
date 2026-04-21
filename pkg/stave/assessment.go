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
}

// CoveragePosture is the per-tool, per-domain coverage aggregation.
// Aliased from the internal coverage package; shape is consumer-
// friendly (outer key: tool identifier; inner key: domain).
type CoveragePosture = coverage.CoverageIndex

// DomainCoverage is the per-(tool, domain) coverage summary.
// Aliased for the same reason as [CoveragePosture].
type DomainCoverage = coverage.DomainCoverage
