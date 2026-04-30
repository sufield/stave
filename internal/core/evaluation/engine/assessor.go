package engine

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Assessor orchestrates the evaluation of security controls against cloud resource states.
// It is the central engine that transforms raw snapshots into a verified ComplianceReport.
type Assessor struct {
	// Infrastructure — stateless services injected at construction.
	Logger          *slog.Logger
	Clock           ports.Clock
	Hasher          ports.Digester
	PredicateEval   policy.PredicateEval
	PredicateParser func(any) (*policy.UnsafePredicate, error)
	Confidence      evaluation.ConfidenceCalculator

	// Observability — optional logic trace for audit transparency.
	// When set, the engine records every decision step (predicate evaluation,
	// threshold check, coverage analysis) so security researchers can verify
	// the reasoning chain for both PASS and VIOLATION verdicts.
	Tracer ports.Tracer

	// Governance — the policy-set and override configurations.
	Controls        []policy.ControlDefinition
	Exemptions      *policy.ExemptionConfig
	Exceptions      *policy.ExceptionConfig
	Acknowledgments *policy.AcknowledgmentConfig

	// Risk Thresholds — global parameters for SLA and data continuity.
	SLAThreshold    time.Duration
	ContinuityLimit time.Duration
}

// NewAssessor creates an engine with sensible defaults for security
// evaluation. The Hasher field is intentionally left nil — the domain
// layer cannot import platform/crypto, so callers that need a non-empty
// PolicyFingerprint must inject a hasher explicitly. The composition
// roots in app/eval and cmd/* (which are allowed to depend on platform
// packages) wire crypto.NewHasher() onto the returned Assessor before
// calling Assess().
//
// Nil-receiver contract: Exemptions, Exceptions, and Acknowledgments
// may be left nil. Their *ShouldExempt / *ShouldExcept / *FindRule
// methods are nil-safe and treat a nil receiver as "no rules
// configured" — so the assessor never panics on a partially-wired
// configuration. Tests and integration callers that want fully empty
// configs can pass freshly constructed instances; the result is the
// same.
func NewAssessor() *Assessor {
	return &Assessor{
		Logger:          slog.Default(),
		ContinuityLimit: DefaultContinuityLimit,
		Confidence:      evaluation.DefaultConfidenceCalculator(),
	}
}

// sessionDeps wraps the Assessor to satisfy strategyDeps, adding the
// active trace span from the current assessmentSession.
type sessionDeps struct {
	*Assessor
	span ports.AssessmentSpan
}

func (d *sessionDeps) currentSpan() ports.AssessmentSpan { return d.span }

// Compile-time checks.
var (
	_ strategyDeps = (*sessionDeps)(nil)
	_ strategyDeps = (*Assessor)(nil)
)

func (a *Assessor) logger() *slog.Logger              { return a.Logger }
func (a *Assessor) currentSpan() ports.AssessmentSpan { return nopSpan{} }

// slaThresholdFor returns the effective SLA (Max Unsafe Duration) for a control.
func (a *Assessor) slaThresholdFor(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafeDuration(a.SLAThreshold)
}

func (a *Assessor) predicateParser() policy.PredicateParser {
	return a.PredicateParser
}

func (a *Assessor) confidenceCalculator() evaluation.ConfidenceCalculator { return a.Confidence }

// sortSnapshots returns a chronological copy of the snapshots.
// Uses stable sort with source as secondary key for determinism
// when timestamps are identical.
func (a *Assessor) sortSnapshots(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := slices.Clone(snapshots)
	slices.SortStableFunc(sorted, func(i, j asset.Snapshot) int {
		if cmp := i.CapturedAt.Compare(j.CapturedAt); cmp != 0 {
			return cmp
		}
		return strings.Compare(string(i.Source), string(j.Source))
	})
	return sorted
}

// referenceTime establishes the "audit now" timestamp.
// If --now was set (FixedClock), the user's explicit time takes precedence.
// Otherwise, the latest snapshot's CapturedAt is used for reproducibility.
//
// Assess validates a.Clock != nil before calling here, but a future
// caller that constructs an Assessor without going through Assess
// (or skips that gate) would otherwise panic on the type assertion
// and the .Now() calls below. Fall back to time.Now() when Clock is
// nil so the function is robust to misuse — the production caller
// always passes a non-nil Clock, but the fallback prevents a nil
// dereference from corrupting an in-flight evaluation.
func (a *Assessor) referenceTime(snapshots []asset.Snapshot) time.Time {
	if a.Clock == nil {
		if len(snapshots) > 0 {
			return snapshots[len(snapshots)-1].CapturedAt
		}
		return time.Now()
	}
	if _, isFixed := a.Clock.(ports.FixedClock); isFixed {
		return a.Clock.Now()
	}
	if len(snapshots) > 0 {
		return snapshots[len(snapshots)-1].CapturedAt
	}
	return a.Clock.Now()
}

// AssessmentOptions holds ephemeral parameters for a specific evaluation run.
type AssessmentOptions struct {
	StaveVersion     string
	InputHashes      *evaluation.InputHashes
	GenerateEvidence bool
}

// assessmentSession maintains the state of a single execution of the engine.
//
// Concurrency: applyControl is invoked sequentially from Assess, and the
// activeSpan field is mutated without synchronization. If a future
// change parallelizes per-control evaluation, activeSpan must be moved
// into per-call state (or guarded by a mutex) before doing so —
// otherwise concurrent writers will race and the strategy will see the
// wrong span. The collector's own RecordCheck path is mutex-protected
// independently, so it is safe to call from a future concurrent caller.
//
// applyControlInUse is the runtime assertion guard. It is set
// non-zero while applyControl is executing; a second concurrent
// caller would see it already non-zero and panic with a clear
// message identifying the contract violation. The cost is one
// atomic load/store per applyControl call, negligible against the
// per-asset CEL evaluation that dominates the runtime.
type assessmentSession struct {
	assessor          *Assessor
	snapshots         []asset.Snapshot
	auditTime         time.Time
	collector         *AssessmentCollector
	idIndex           IdentityIndex
	opts              AssessmentOptions
	activeSpan        ports.AssessmentSpan // current control×asset span for strategy access; sequential-only, see type doc
	applyControlInUse atomic.Bool
}

// beginTrace starts a trace span for a control×asset evaluation.
// Returns a nopSpan if no tracer is configured — avoids nil checks at call sites.
func (s *assessmentSession) beginTrace(resourceID, policyID string) ports.AssessmentSpan {
	if s.assessor.Tracer == nil {
		return nopSpan{}
	}
	return s.assessor.Tracer.BeginAssessment(resourceID, policyID)
}

// Assess processes the observation snapshots and returns a comprehensive ComplianceReport.
func (a *Assessor) Assess(snapshots []asset.Snapshot, opts ...AssessmentOptions) (evaluation.ComplianceReport, error) {
	if a.Clock == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a Clock")
	}
	if a.PredicateEval == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a PredicateEval")
	}
	if a.PredicateParser == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a PredicateParser")
	}
	var opt AssessmentOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	sequenced := a.sortSnapshots(snapshots)

	// Pre-pass: derive cross-resource properties (e.g., KMS key isolation).
	// This enriches asset properties with derived fields before control
	// evaluation, enabling cross-resource reasoning via standard predicates.
	sequenced = EnrichKeyIsolation(sequenced)

	lifecycles, err := BuildLifecyclesPerControl(a.Controls, sequenced, a.PredicateEval)
	if err != nil {
		return evaluation.ComplianceReport{}, fmt.Errorf("lifecycle analysis failed: %w", err)
	}

	assetHint := 0
	if len(sequenced) > 0 {
		assetHint = len(sequenced[0].Assets)
	}

	sess := &assessmentSession{
		assessor:  a,
		snapshots: sequenced,
		auditTime: a.referenceTime(sequenced),
		collector: NewCollector(assetHint),
		idIndex:   BuildIdentityIndex(sequenced),
		opts:      opt,
	}

	for i := range a.Controls {
		ctl := &a.Controls[i]
		if !ctl.IsEvaluatable() {
			sess.collector.RecordSkippedControl(
				ctl.ID,
				ctl.Name,
				"control type cannot be evaluated: "+ctl.Type.String(),
			)
			continue
		}
		sess.applyControl(ctl, lifecycles[ctl.ID])
	}

	return sess.compileReport(), nil
}

// applyControl evaluates a single control across the asset set.
//
// Concurrency contract: this method MUST remain sequential. It writes
// `s.activeSpan` mid-loop without synchronization, so any future
// parallelization (e.g., one goroutine per control) would race the
// per-asset span assignment with the strategy's read of activeSpan.
// If parallelization becomes necessary, move activeSpan into a per-
// call local that the strategy receives as a parameter — do NOT add a
// mutex around the field assignment, because that only serializes the
// write and the strategy still reads the wrong span.
func (s *assessmentSession) applyControl(
	ctl *policy.ControlDefinition,
	lifecycles map[asset.ID]*asset.ExposureLifecycle,
) {
	// Detect any future caller that violates the sequential
	// contract. CompareAndSwap returns false when the flag is
	// already set, which means another goroutine is in
	// applyControl right now — bug, not a recoverable runtime
	// condition, so panic with a message that points at the
	// type-doc explanation.
	if !s.applyControlInUse.CompareAndSwap(false, true) {
		panic("engine: applyControl invoked concurrently — see assessmentSession concurrency contract; activeSpan is not goroutine-safe")
	}
	defer s.applyControlInUse.Store(false)

	// Ensure deterministic output by processing assets in ID order.
	assetIDs := make([]asset.ID, 0, len(lifecycles))
	for id := range lifecycles {
		assetIDs = append(assetIDs, id)
	}
	slices.Sort(assetIDs)

	for _, id := range assetIDs {
		lifecycle := lifecycles[id]
		span := s.beginTrace(string(id), ctl.ID.String())

		// 1. Check for organizational exemptions (Policy Overrides)
		if rule := s.assessor.Exemptions.ShouldExempt(id); rule != nil {
			span.RecordStep("exemption_check", map[string]any{
				"pattern": rule.Pattern,
			}, map[string]any{
				"exempted": true,
				"reason":   rule.Reason,
			})
			span.SetVerdict(string(evaluation.VerdictSkipped), string(evaluation.ConfidenceHigh))
			span.End()

			if s.collector.RecordExemption(id) {
				s.collector.RecordExemptedAsset(id, rule.Pattern, rule.Reason)
			}
			// A nil lifecycle here is unexpected — the lifecycle map is
			// produced by BuildLifecyclesPerControl and the caller
			// iterates its keys. Record the check with empty type
			// metadata rather than panicking, and emit a debug log so
			// the upstream invariant violation is traceable.
			check := evaluation.ResourceCheck{
				ControlID:  ctl.ID,
				AssetID:    id,
				Verdict:    evaluation.VerdictSkipped,
				Confidence: evaluation.ConfidenceHigh,
				Reason:     rule.Reason,
			}
			if lifecycle != nil {
				check.AssetType = lifecycle.Asset().Type
				check.AssetDomain = lifecycle.Asset().Type.Domain()
			} else {
				s.assessor.logger().Debug("exemption check: nil lifecycle",
					"control", ctl.ID, "asset", id)
			}
			s.collector.RecordCheck(check)
			continue
		}
		span.RecordStep("exemption_check", nil, map[string]any{"exempted": false})

		// 2. Track evaluated snapshots through the collector's
		//    mutex-protected entry points. The collector itself is
		//    concurrent-safe; applyControl is currently called
		//    sequentially from Assess (see assessmentSession type doc).
		s.collector.RecordSeenAsset(id)
		if lifecycle != nil && lifecycle.IsExposed() {
			s.collector.RecordNonCompliantAsset(id)
		}

		// 3. Evaluate the security strategy against the asset lifecycle.
		//    Set the active span so strategies can record their decision steps,
		//    then create the strategy (which captures the span via sessionDeps).
		s.activeSpan = span
		// Defensive nil-check: strategy.Evaluate dereferences lifecycle.
		// A nil here would panic the assessor; record an inconclusive
		// check + log instead.
		if lifecycle == nil {
			s.assessor.logger().Warn("strategy evaluation: nil lifecycle",
				"control", ctl.ID, "asset", id)
			s.collector.RecordCheck(evaluation.ResourceCheck{
				ControlID:  ctl.ID,
				AssetID:    id,
				Verdict:    evaluation.VerdictInconclusive,
				Confidence: evaluation.ConfidenceInconclusive,
				Reason:     "lifecycle missing for asset",
			})
			span.End()
			continue
		}
		strat := s.strategyFor(ctl)
		check, findings := strat.Evaluate(lifecycle, s.auditTime, s.idIndex)

		// 4. Record verdict and finding linkage in the trace span
		span.SetVerdict(string(check.Verdict), string(check.Confidence))
		if len(findings) > 0 {
			span.SetFindingID(findings[0].ControlID.String() + "@" + string(findings[0].AssetID))
		}
		span.End()

		s.collector.RecordCheck(check)
		s.collector.RecordFindings(findings)
	}
}

func (s *assessmentSession) compileReport() evaluation.ComplianceReport {
	evaluation.SortFindings(s.collector.findings)

	slices.SortFunc(s.collector.exemptedAssets, func(a, b asset.ExemptedAsset) int {
		return cmp.Compare(a.ID, b.ID)
	})

	slices.SortFunc(s.collector.checks, func(a, b evaluation.ResourceCheck) int {
		if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})

	// Filter findings through active security exceptions.
	activeFindings, exceptedFindings := partitionFindings(
		s.collector.findings,
		s.assessor.Exceptions,
		s.auditTime,
	)

	// Apply acknowledgments.
	activeFindings, acknowledgedFindings := applyAcknowledgments(
		activeFindings,
		s.assessor.Acknowledgments,
		s.auditTime,
	)

	// Calculate environmental risk based on pending violations.
	// Pass Exemptions so the risk pipeline filters exempted assets
	// the same way the main finding pipeline does — otherwise an
	// exempted asset can still flip overall posture to AT_RISK
	// through risk signals.
	riskSignals := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                s.assessor.Controls,
		Snapshots:               s.snapshots,
		GlobalMaxUnsafeDuration: s.assessor.SLAThreshold,
		Now:                     s.auditTime,
		PredicateEval:           s.assessor.PredicateEval,
		Exemptions:              s.assessor.Exemptions,
	})

	posture := evaluation.DeriveSecurityState(len(activeFindings), riskSignals)

	report := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      s.opts.StaveVersion,
			Offline:           true,
			Now:               s.auditTime,
			MaxUnsafeDuration: kernel.Duration(s.assessor.SLAThreshold),
			Snapshots:         len(s.snapshots),
			InputHashes:       s.opts.InputHashes,
			PolicyFingerprint: s.assessor.FingerprintPolicy(),
			EvaluatedState:    evaluatedState(s.snapshots),
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      s.collector.SeenAssetCount(),
			ExposedResources: s.collector.NonCompliantAssetCount(),
			Violations:       len(activeFindings),
		},
		SecurityState:        posture,
		RiskSignals:          riskSignals,
		Findings:             activeFindings,
		ExceptedFindings:     exceptedFindings,
		AcknowledgedFindings: acknowledgedFindings,
		SkippedControls:      s.collector.skippedControls,
		ExemptedAssets:       s.collector.exemptedAssets,
		Checks:               s.collector.checks,
	}

	if s.opts.GenerateEvidence && len(s.snapshots) > 0 {
		latestSnap := &s.snapshots[len(s.snapshots)-1]
		report.EvidencePackage = buildEvidencePackage(
			activeFindings,
			s.collector.checks,
			s.assessor.Controls,
			latestSnap,
			s.auditTime,
		)
	}

	return report
}

// partitionFindings separates violations into active findings and accepted exceptions.
func partitionFindings(
	findings []evaluation.Finding,
	exceptions *policy.ExceptionConfig,
	now time.Time,
) ([]evaluation.Finding, []evaluation.ExceptedFinding) {
	var active []evaluation.Finding
	var excepted []evaluation.ExceptedFinding
	for i := range findings {
		f := &findings[i]
		if rule := exceptions.ShouldExcept(f.ControlID, f.AssetID, now); rule != nil {
			excepted = append(excepted, evaluation.ExceptedFinding{
				ControlID: f.ControlID,
				AssetID:   f.AssetID,
				Reason:    rule.Reason,
				Expires:   rule.Expires,
			})
		} else {
			active = append(active, *f)
		}
	}
	return active, excepted
}

// applyAcknowledgments separates acknowledged findings from active findings.
// Returns remaining active findings and a slice of acknowledged finding records.
// Compensating control validation uses the active findings set — already-excepted
// findings are not counted as failing, so they don't block valid acknowledgments.
func applyAcknowledgments(
	findings []evaluation.Finding,
	acks *policy.AcknowledgmentConfig,
	now time.Time,
) ([]evaluation.Finding, []policy.AcknowledgedFinding) {
	if acks == nil {
		return findings, nil
	}

	// Build set of failing control IDs from the active (non-excepted) findings only.
	// Using allFindings here would allow already-excepted findings to invalidate
	// unrelated acknowledgments whose compensating controls were also excepted.
	failingControls := make(map[kernel.ControlID]bool)
	for i := range findings {
		failingControls[findings[i].ControlID] = true
	}

	var active []evaluation.Finding
	var acknowledged []policy.AcknowledgedFinding

	for i := range findings {
		f := &findings[i]
		rule := acks.FindRule(f.ControlID, f.AssetID)
		if rule == nil {
			active = append(active, *f)
			continue
		}

		af := policy.AcknowledgedFinding{
			FindingID:        f.FindingID,
			ControlID:        f.ControlID,
			AssetID:          f.AssetID,
			Severity:         f.ControlSeverity,
			Rationale:        rule.Rationale,
			AcknowledgedBy:   rule.AcknowledgedBy,
			AcknowledgedDate: rule.AcknowledgedDate,
			ExpiryDate:       rule.ExpiryDate,
		}

		// Check expiry.
		if rule.IsExpired(now) {
			af.Verdict = "fail"
			af.Valid = false
			af.InvalidReason = "expired"
			acknowledged = append(acknowledged, af)
			active = append(active, *f) // revert to active
			continue
		}

		// Check compensating controls.
		allCompPassing := true
		for _, cc := range rule.CompensatingControls {
			status := "pass"
			if failingControls[cc] {
				status = "fail"
				allCompPassing = false
			}
			af.CompensatingControls = append(af.CompensatingControls,
				policy.CompensatingControlStatus{ControlID: cc, Status: status})
		}

		if !allCompPassing {
			af.Verdict = "fail"
			af.Valid = false
			af.InvalidReason = "compensating_controls_failing"
			acknowledged = append(acknowledged, af)
			active = append(active, *f) // revert to active
			continue
		}

		// Valid acknowledgment.
		af.Verdict = "acknowledged"
		af.Valid = true
		acknowledged = append(acknowledged, af)
		// Finding is NOT added to active — it's acknowledged.
	}

	return active, acknowledged
}

// FingerprintPolicy returns a deterministic hash of the active control-set.
// This provides an integrity check for auditors to verify which rules were enforced.
func (a *Assessor) FingerprintPolicy() kernel.Digest {
	if len(a.Controls) == 0 || a.Hasher == nil {
		return ""
	}
	// Include evaluator identity — prevents silent evaluator swap.
	// Hash per-control fingerprints (which include predicate, severity,
	// type — not just IDs) sorted by ID for determinism.
	fingerprints := make([]string, 0, len(a.Controls)+1)
	fingerprints = append(fingerprints, "eval_version:"+stavecel.EvalVersion)
	for i := range a.Controls {
		ctl := &a.Controls[i]
		fingerprints = append(fingerprints, string(ctl.ID)+":"+string(ctl.Fingerprint(a.Hasher)))
	}
	slices.Sort(fingerprints)
	return a.Hasher.Digest(fingerprints, '\n')
}

// DefaultContinuityLimit defines the maximum gap allowed between scans
// before results are considered INCONCLUSIVE.
const DefaultContinuityLimit = 12 * time.Hour

func (a *Assessor) continuityLimit() time.Duration { return a.ContinuityLimit }

// evaluatedState extracts the source context from the latest snapshot.
func evaluatedState(snapshots []asset.Snapshot) string {
	if len(snapshots) == 0 {
		return ""
	}
	return string(snapshots[len(snapshots)-1].Source)
}
