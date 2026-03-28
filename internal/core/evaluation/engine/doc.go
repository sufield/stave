// Package engine implements the core evaluation loop that processes observation
// snapshots against controls to detect safety violations.
//
// [Runner] orchestrates the evaluation: it builds per-asset timelines, detects
// unsafe-state transitions, and emits duration or recurrence findings when
// thresholds are exceeded. Supporting types handle finding construction
// ([FindingBuilder]), coverage metrics, accumulation across snapshots, and
// evaluation strategy selection.
package engine
