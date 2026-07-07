// Package gate hosts the gate-style use cases the CLI runs to
// answer "is the current state acceptable?" — overdue counts,
// baseline comparisons, and similar yes/no questions on assessment
// state. Pure domain logic; I/O wiring lives in
// internal/adapters/gate.
package gate

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

// OverdueRequest groups the inputs needed to compute the overdue
// count. Vendor-neutral; the caller (the gate adapter) loads
// observations + controls + CEL evaluator and hands them in.
type OverdueRequest struct {
	Controls                []policy.ControlDefinition
	Snapshots               []asset.Snapshot
	GlobalMaxUnsafeDuration time.Duration
	EvalTime                time.Time
	PredicateEval           policy.PredicateEval
}

// CountOverdue returns the number of upcoming-action items whose
// SLA deadline has lapsed. Wraps risk.ComputeItems +
// ThresholdItems.CountOverdue so the adapter is reduced to I/O
// orchestration; the business rule of "what is overdue" lives here.
func CountOverdue(req OverdueRequest) int {
	items := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                req.Controls,
		Snapshots:               req.Snapshots,
		GlobalMaxUnsafeDuration: req.GlobalMaxUnsafeDuration,
		EvalTime:                req.EvalTime,
		PredicateEval:           req.PredicateEval,
	})
	return items.CountOverdue()
}
