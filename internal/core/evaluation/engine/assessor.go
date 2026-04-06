package engine

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

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

	// Governance — the policy-set and override configurations.
	Controls   []policy.ControlDefinition
	Exemptions *policy.ExemptionConfig
	Exceptions *policy.ExceptionConfig

	// Risk Thresholds — global parameters for SLA and data continuity.
	SLAThreshold    time.Duration
	ContinuityLimit time.Duration
}

// NewAssessor creates an engine with sensible defaults for security evaluation.
func NewAssessor() *Assessor {
	return &Assessor{
		Logger:          slog.Default(),
		ContinuityLimit: DefaultContinuityLimit,
		Confidence:      evaluation.DefaultConfidenceCalculator(),
	}
}

// Compile-time check: Assessor satisfies the internal strategy dependency interface.
var _ strategyDeps = (*Assessor)(nil)

func (a *Assessor) logger() *slog.Logger { return a.Logger }

// slaThresholdFor returns the effective SLA (Max Unsafe Duration) for a control.
func (a *Assessor) slaThresholdFor(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafeDuration(a.SLAThreshold)
}

func (a *Assessor) predicateParser() policy.PredicateParser {
	return a.PredicateParser
}

func (a *Assessor) confidenceCalculator() evaluation.ConfidenceCalculator { return a.Confidence }

// sequenceInventory returns a chronological copy of the snapshots.
func (a *Assessor) sequenceInventory(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := slices.Clone(snapshots)
	slices.SortFunc(sorted, func(i, j asset.Snapshot) int {
		return i.CapturedAt.Compare(j.CapturedAt)
	})
	return sorted
}

// referenceTime establishes the "audit now" timestamp, using the latest snapshot
// for reproducibility in historical audits.
func (a *Assessor) referenceTime(inventory []asset.Snapshot) time.Time {
	if len(inventory) > 0 {
		return inventory[len(inventory)-1].CapturedAt
	}
	return a.Clock.Now()
}

// AssessmentOptions holds ephemeral parameters for a specific evaluation run.
type AssessmentOptions struct {
	StaveVersion string
	InputHashes  *evaluation.InputHashes
}

// assessmentSession maintains the state of a single execution of the engine.
type assessmentSession struct {
	assessor  *Assessor
	inventory []asset.Snapshot
	auditTime time.Time
	collector *AssessmentCollector
	idIndex   IdentityIndex
	opts      AssessmentOptions
}

// Assess processes the cloud inventory and returns a comprehensive ComplianceReport.
func (a *Assessor) Assess(inventory []asset.Snapshot, opts ...AssessmentOptions) (evaluation.ComplianceReport, error) {
	if a.Clock == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a Clock")
	}
	var opt AssessmentOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	sequenced := a.sequenceInventory(inventory)
	lifecycles, err := BuildTimelinesPerControl(a.Controls, sequenced, a.PredicateEval)
	if err != nil {
		return evaluation.ComplianceReport{}, fmt.Errorf("lifecycle analysis failed: %w", err)
	}

	assetHint := 0
	if len(sequenced) > 0 {
		assetHint = len(sequenced[0].Assets)
	}

	sess := &assessmentSession{
		assessor:  a,
		inventory: sequenced,
		auditTime: a.referenceTime(sequenced),
		collector: NewCollector(assetHint),
		idIndex:   BuildIdentityIndex(sequenced),
		opts:      opt,
	}

	for _, ctl := range a.Controls {
		if !ctl.IsEvaluatable() {
			sess.collector.RecordSkippedControl(
				ctl.ID,
				ctl.Name,
				"control type cannot be evaluated: "+ctl.Type.String(),
			)
			continue
		}
		sess.applyControl(&ctl, lifecycles[ctl.ID])
	}

	return sess.compileReport(), nil
}

func (s *assessmentSession) applyControl(
	ctl *policy.ControlDefinition,
	lifecycles map[asset.ID]*asset.ExposureLifecycle,
) {
	strategy := s.assessor.strategyFor(ctl)

	// Ensure deterministic output by processing assets in ID order.
	assetIDs := make([]asset.ID, 0, len(lifecycles))
	for id := range lifecycles {
		assetIDs = append(assetIDs, id)
	}
	slices.Sort(assetIDs)

	for _, id := range assetIDs {
		lifecycle := lifecycles[id]

		// 1. Check for organizational exemptions (Policy Overrides)
		if rule := s.assessor.Exemptions.ShouldExempt(id); rule != nil {
			if s.collector.RecordExemption(id) {
				s.collector.RecordExemptedAsset(id, rule.Pattern, rule.Reason)
			}
			s.collector.RecordCheck(evaluation.ResourceCheck{
				ControlID:   ctl.ID,
				AssetID:     id,
				AssetType:   lifecycle.Asset().Type,
				AssetDomain: lifecycle.Asset().Type.Domain(),
				Verdict:     evaluation.VerdictSkipped,
				Confidence:  evaluation.ConfidenceHigh,
				Reason:      rule.Reason,
			})
			continue
		}

		// 2. Track evaluated inventory
		s.collector.seenAssets.register(id)
		if lifecycle.IsExposed() {
			s.collector.nonCompliantAssets.register(id)
		}

		// 3. Evaluate the security strategy against the asset lifecycle
		check, findings := strategy.Evaluate(lifecycle, s.auditTime, s.idIndex)
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

	// Calculate environmental risk based on pending violations.
	riskSignals := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                s.assessor.Controls,
		Snapshots:               s.inventory,
		GlobalMaxUnsafeDuration: s.assessor.SLAThreshold,
		Now:                     s.auditTime,
		PredicateEval:           s.assessor.PredicateEval,
	})

	posture := evaluation.DeriveSecurityState(len(activeFindings), riskSignals)

	return evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      s.opts.StaveVersion,
			Offline:           true,
			Now:               s.auditTime,
			MaxUnsafeDuration: kernel.Duration(s.assessor.SLAThreshold),
			Snapshots:         len(s.inventory),
			InputHashes:       s.opts.InputHashes,
			PolicyFingerprint: s.assessor.FingerprintPolicy(),
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      len(s.collector.seenAssets),
			ExposedResources: len(s.collector.nonCompliantAssets),
			Violations:       len(activeFindings),
		},
		SecurityState:    posture,
		RiskSignals:      riskSignals,
		Findings:         activeFindings,
		ExceptedFindings: exceptedFindings,
		SkippedControls:  s.collector.skippedControls,
		ExemptedAssets:   s.collector.exemptedAssets,
		Checks:           s.collector.checks,
	}
}

// partitionFindings separates violations into active findings and accepted exceptions.
func partitionFindings(
	findings []evaluation.Finding,
	exceptions *policy.ExceptionConfig,
	now time.Time,
) ([]evaluation.Finding, []evaluation.ExceptedFinding) {
	var active []evaluation.Finding
	var excepted []evaluation.ExceptedFinding
	for _, f := range findings {
		if rule := exceptions.ShouldExcept(f.ControlID, f.AssetID, now); rule != nil {
			excepted = append(excepted, evaluation.ExceptedFinding{
				ControlID: f.ControlID,
				AssetID:   f.AssetID,
				Reason:    rule.Reason,
				Expires:   rule.Expires,
			})
		} else {
			active = append(active, f)
		}
	}
	return active, excepted
}

// FingerprintPolicy returns a deterministic hash of the active control-set.
// This provides an integrity check for auditors to verify which rules were enforced.
func (a *Assessor) FingerprintPolicy() kernel.Digest {
	if len(a.Controls) == 0 || a.Hasher == nil {
		return ""
	}
	ids := make([]string, len(a.Controls))
	for i, ctl := range a.Controls {
		ids[i] = string(ctl.ID)
	}
	slices.Sort(ids)
	return a.Hasher.Digest(ids, '\n')
}

// DefaultContinuityLimit defines the maximum gap allowed between scans
// before results are considered INCONCLUSIVE.
const DefaultContinuityLimit = 12 * time.Hour

func (a *Assessor) continuityLimit() time.Duration { return a.ContinuityLimit }
