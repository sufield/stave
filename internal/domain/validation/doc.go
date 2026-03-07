// Package validation defines readiness prerequisite checks run before evaluation.
//
// [ReadinessReport] aggregates [PrereqCheck] results, each with a [PrereqStatus],
// to determine whether the evaluation inputs (controls, observations, schemas)
// are valid and complete enough to proceed.
package validation
