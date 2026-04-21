package stave

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// ControlID identifies a control definition. Aliased from the
// internal kernel package — library consumers get the same type the
// evaluation engine uses, with zero conversion cost.
type ControlID = kernel.ControlID

// AssetID identifies an asset (e.g. an S3 bucket, an IAM policy).
// Aliased from the internal asset package.
type AssetID = asset.ID

// AssetType categorizes an asset (e.g. "storage_bucket",
// "iam_policy"). Aliased from the internal kernel package.
type AssetType = kernel.AssetType

// Vendor identifies the provider of an asset (e.g. "aws", "gcp").
// Aliased from the internal kernel package.
type Vendor = kernel.Vendor

// ScopeTag labels a control or finding with domain scope (e.g.
// "aws", "s3"). Aliased from the internal kernel package.
type ScopeTag = kernel.ScopeTag

// FindingID is the stable per-(control, asset) fingerprint the
// evaluation engine emits. See [evaluation.StableFindingID] for the
// derivation. Aliased from the internal kernel package so consumers
// can compare values from Finding.FindingID with elements of
// Issue.MemberFindingIDs (e.g. via [slices.Contains]) without
// string casts.
type FindingID = kernel.FindingID

// ChainID identifies a compound-risk chain definition (e.g.
// "privilege_escalation_path"). Aliased from the internal kernel
// package so consumers can compare values from ChainFinding.ChainID
// with elements of Finding.ChainMembership[i].ChainID without string
// casts.
type ChainID = kernel.ChainID

// Classification marks a control's semantic evaluation role.
// Aliased from the internal controldef package.
type Classification = policy.Classification

// Classification constants. These mirror the internal values —
// consumers can compare library findings against these names
// without importing internal packages.
const (
	StateAssertion     Classification = policy.ClassificationStateAssertion
	ParameterizedCheck Classification = policy.ClassificationParameterizedCheck
	AbsenceCheck       Classification = policy.ClassificationAbsenceCheck
	AggregateCheck     Classification = policy.ClassificationAggregateCheck
)

// Severity is the human-readable severity level of a control or
// finding. The internal engine uses an ordered int type; at the
// library boundary the string form is easier to consume.
type Severity string

// Severity constants in order from lowest to highest.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Status is the high-level security posture after evaluation.
type Status string

// Status constants matching the engine's SecurityState values.
const (
	StatusCompliant    Status = "COMPLIANT"
	StatusAtRisk       Status = "AT_RISK"
	StatusNonCompliant Status = "NON_COMPLIANT"
)
