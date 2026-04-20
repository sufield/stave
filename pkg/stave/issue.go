package stave

import "github.com/sufield/stave/internal/core/evaluation"

// Issue consolidates findings on the same asset that share a
// root-cause signal. Aliased directly from the internal evaluation
// package — the shape is stable and already consumer-friendly.
//
// One underlying misconfiguration produces one Issue regardless of
// how many controls fire on it; MemberFindingIDs preserves
// per-control fidelity. The HeadlineFindingID is the member that
// best represents the Issue in single-line summaries.
type Issue = evaluation.Issue
