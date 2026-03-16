package service

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"

	"github.com/sufield/stave/internal/domain/asset"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/platform/crypto"
	apptrace "github.com/sufield/stave/internal/app/trace"
	"github.com/sufield/stave/internal/trace"
)

func TestBuildFindingDetail_Success(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	firstUnsafe := time.Date(2026, 1, 14, 12, 0, 0, 0, time.UTC)
	lastSeen := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	ctl := policy.ControlDefinition{
		ID:          "CTL.S3.PUBLIC.001",
		Name:        "No Public S3 Bucket Read",
		Description: "Buckets must not allow public read access.",
		Severity:    policy.SeverityCritical,
		Domain:      "exposure",
		Type:        policy.TypeUnsafeState,
		Compliance:  map[string]string{"cis_aws_v1.4.0": "2.1.5"},
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: "properties.storage.access.public_read", Op: "eq", Value: true},
			},
		},
		Remediation: &policy.RemediationSpec{
			Description: "Bucket is publicly exposed.",
			Action:      "Enable Block Public Access.",
			Example:     `{"public_read": false}`,
		},
	}

	resource := asset.Asset{
		ID:   "res:aws:s3:bucket:test-bucket",
		Type: "aws:s3:bucket",
		Properties: map[string]any{
			"storage": map[string]any{
				"access": map[string]any{
					"public_read": true,
				},
			},
		},
	}

	snap := asset.Snapshot{
		CapturedAt: lastSeen,
		Assets:     []asset.Asset{resource},
	}
	earlierSnap := asset.Snapshot{
		CapturedAt: firstUnsafe,
		Assets:     []asset.Asset{resource},
	}

	violation := evaluation.Finding{
		ControlID:          kernel.ControlID("CTL.S3.PUBLIC.001"),
		ControlName:        "No Public S3 Bucket Read",
		ControlDescription: "Buckets must not allow public read access.",
		ControlSeverity:    policy.SeverityCritical,
		ControlCompliance:  policy.ComplianceMapping{"cis_aws_v1.4.0": "2.1.5"},
		AssetID:            asset.ID("res:aws:s3:bucket:test-bucket"),
		AssetType:          "aws:s3:bucket",
		AssetVendor:        "aws",
		Evidence: evaluation.Evidence{
			FirstUnsafeAt:       firstUnsafe,
			LastSeenUnsafeAt:    lastSeen,
			UnsafeDurationHours: 12.0,
			ThresholdHours:      24.0,
			WhyNow:              "unsafe duration 12h exceeds 0h",
		},
		ControlRemediation: &policy.RemediationSpec{
			Description: "Bucket is publicly exposed.",
			Action:      "Enable Block Public Access.",
			Example:     `{"public_read": false}`,
		},
	}

	_ = now // used for context
	detail, err := BuildFindingDetail(FindingDetailInput{
		ControlID:    kernel.ControlID("CTL.S3.PUBLIC.001"),
		AssetID:      asset.ID("res:aws:s3:bucket:test-bucket"),
		Controls:     policy.ControlDefinitions{ctl},
		Snapshots:    []asset.Snapshot{earlierSnap, snap},
		Result:       &evaluation.Result{Findings: []evaluation.Finding{violation}},
		TraceBuilder: apptrace.NewFindingTraceBuilder(nil),
		IDGen:        crypto.NewHasher(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Control summary
	if detail.Control.ID != "CTL.S3.PUBLIC.001" {
		t.Errorf("control ID = %q, want CTL.S3.PUBLIC.001", detail.Control.ID)
	}
	if detail.Control.Severity != policy.SeverityCritical {
		t.Errorf("severity = %q, want critical", detail.Control.Severity)
	}
	if detail.Control.Domain != "exposure" {
		t.Errorf("domain = %q, want exposure", detail.Control.Domain)
	}
	if detail.Control.Type != "unsafe_state" {
		t.Errorf("type = %q, want unsafe_state", detail.Control.Type)
	}

	// Asset summary
	if detail.Asset.ID != "res:aws:s3:bucket:test-bucket" {
		t.Errorf("resource ID = %q, want test-bucket", detail.Asset.ID)
	}
	if detail.Asset.Vendor != "aws" {
		t.Errorf("vendor = %q, want aws", detail.Asset.Vendor)
	}

	// Evidence
	if detail.Evidence.UnsafeDurationHours != 12.0 {
		t.Errorf("unsafe duration = %f, want 12.0", detail.Evidence.UnsafeDurationHours)
	}

	// Trace should be populated
	if detail.Trace == nil {
		t.Fatal("trace is nil, expected populated")
	}
	if !detail.Trace.FinalResult {
		t.Error("trace final result should be true (predicate matches)")
	}
	tr, ok := detail.Trace.Raw.(*trace.TraceResult)
	if !ok {
		t.Fatal("trace.Raw should be *trace.TraceResult")
	}
	if tr.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("trace control = %q", tr.ControlID)
	}

	// Remediation
	if detail.Remediation == nil {
		t.Fatal("remediation is nil")
	}
	if detail.Remediation.Action != "Enable Block Public Access." {
		t.Errorf("remediation action = %q", detail.Remediation.Action)
	}

	// Next steps
	if len(detail.NextSteps) == 0 {
		t.Error("expected next steps")
	}
}

func TestBuildFindingDetail_NotFound(t *testing.T) {
	_, err := BuildFindingDetail(FindingDetailInput{
		ControlID: kernel.ControlID("CTL.DOES.NOT.EXIST"),
		AssetID:   asset.ID("nonexistent"),
		Controls:  nil,
		Snapshots: nil,
		Result:    &evaluation.Result{},
		IDGen:     crypto.NewHasher(),
	})
	if err == nil {
		t.Fatal("expected error for missing finding")
	}
}

func TestBuildFindingDetail_NoControlDefinition(t *testing.T) {
	// Violation exists but control definition is missing.
	// Should fall back to violation-level metadata.
	violation := evaluation.Finding{
		ControlID:          kernel.ControlID("CTL.CUSTOM.001"),
		ControlName:        "Custom Rule",
		ControlDescription: "A custom control.",
		AssetID:            asset.ID("res:test"),
		AssetType:          "test:type",
	}

	detail, err := BuildFindingDetail(FindingDetailInput{
		ControlID: kernel.ControlID("CTL.CUSTOM.001"),
		AssetID:   asset.ID("res:test"),
		Controls:  nil,
		Snapshots: nil,
		Result:    &evaluation.Result{Findings: []evaluation.Finding{violation}},
		IDGen:     crypto.NewHasher(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail.Control.Name != "Custom Rule" {
		t.Errorf("control name = %q, want Custom Rule", detail.Control.Name)
	}
	if detail.Trace != nil {
		t.Error("trace should be nil when control definition is missing")
	}
}

func TestBuildFindingDetail_NoMatchingSnapshot(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:   "CTL.TEST.001",
		Name: "Test",
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: "properties.x", Op: "eq", Value: true},
			},
		},
	}
	violation := evaluation.Finding{
		ControlID: kernel.ControlID("CTL.TEST.001"),
		AssetID:   asset.ID("res:missing"),
		Evidence:  evaluation.Evidence{},
	}

	detail, err := BuildFindingDetail(FindingDetailInput{
		ControlID: kernel.ControlID("CTL.TEST.001"),
		AssetID:   asset.ID("res:missing"),
		Controls:  policy.ControlDefinitions{ctl},
		Snapshots: []asset.Snapshot{}, // no snapshots
		Result:    &evaluation.Result{Findings: []evaluation.Finding{violation}},
		IDGen:     crypto.NewHasher(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Trace should be nil (no snapshot to trace against)
	if detail.Trace != nil {
		t.Error("trace should be nil when resource not in any snapshot")
	}
}
