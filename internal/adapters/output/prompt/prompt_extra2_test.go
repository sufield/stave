package prompt

import (
	"strings"
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// ---------------------------------------------------------------------------
// BuildEvidenceSummary
// ---------------------------------------------------------------------------

func TestBuildEvidenceSummary_Empty(t *testing.T) {
	got := BuildEvidenceSummary(evaluation.Evidence{})
	if got != "No evidence details available." {
		t.Fatalf("got %q", got)
	}
}

func TestBuildEvidenceSummary_Full(t *testing.T) {
	ev := evaluation.Evidence{
		FirstUnsafeAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastSeenUnsafeAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		UnsafeDurationHours: 336.0,
		ThresholdHours:      168.0,
		EpisodeCount:        3,
		WindowDays:          30,
		RecurrenceLimit:     5,
		WhyNow:              "Asset has been unsafe for 336 hours",
	}
	got := BuildEvidenceSummary(ev)
	expects := []string{
		"First unsafe:",
		"Last seen unsafe:",
		"Unsafe duration: 336.0",
		"Threshold: 168.0",
		"Episodes: 3",
		"Window: 30",
		"Recurrence limit: 5",
		"Why now:",
	}
	for _, exp := range expects {
		if !strings.Contains(got, exp) {
			t.Errorf("missing %q in output: %s", exp, got)
		}
	}
}

// ---------------------------------------------------------------------------
// BuildRootCausesSummary
// ---------------------------------------------------------------------------

func TestBuildRootCausesSummary_Empty(t *testing.T) {
	if got := BuildRootCausesSummary(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildRootCausesSummary_Multiple(t *testing.T) {
	causes := []evaluation.RootCause{evaluation.RootCauseIdentity, evaluation.RootCauseResource}
	got := BuildRootCausesSummary(causes)
	if got != "identity, resource" {
		t.Fatalf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// BuildGuidanceSummary
// ---------------------------------------------------------------------------

func TestBuildGuidanceSummary_Full(t *testing.T) {
	spec := &policy.RemediationSpec{
		Description: "Disable public access",
		Action:      "Set block_public_access to true",
		Example:     "{ \"block_public_access\": true }",
	}
	got := BuildGuidanceSummary(spec)
	if !strings.Contains(got, "Disable public access") {
		t.Error("missing description")
	}
	if !strings.Contains(got, "**Action:**") {
		t.Error("missing action")
	}
	if !strings.Contains(got, "**Example:**") {
		t.Error("missing example")
	}
}

func TestBuildGuidanceSummary_Empty(t *testing.T) {
	spec := &policy.RemediationSpec{}
	got := BuildGuidanceSummary(spec)
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// summarizeMisconfigurations
// ---------------------------------------------------------------------------

func TestSummarizeMisconfigurations_Empty(t *testing.T) {
	if got := summarizeMisconfigurations(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestSummarizeMisconfigurations_NonEmpty(t *testing.T) {
	misconfigs := []policy.Misconfiguration{
		{Property: predicate.NewFieldPath("public_access"), ActualValue: true, Operator: "eq", UnsafeValue: true},
	}
	got := summarizeMisconfigurations(misconfigs)
	if got == "" {
		t.Fatal("expected non-empty")
	}
}

// ---------------------------------------------------------------------------
// marshalControl
// ---------------------------------------------------------------------------

func TestMarshalControl(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:   kernel.ControlID("CTL.A.001"),
		Name: "Test Control",
	}
	got := marshalControl(ctl)
	if got == "" {
		t.Fatal("expected non-empty YAML")
	}
	if !strings.Contains(got, "CTL.A.001") {
		t.Errorf("missing control ID in YAML: %s", got)
	}
}

// ---------------------------------------------------------------------------
// PromptBuilder.Build
// ---------------------------------------------------------------------------

func TestPromptBuilder_Build(t *testing.T) {
	ctl := &policy.ControlDefinition{
		ID:   "CTL.A.001",
		Name: "Test",
		Remediation: &policy.RemediationSpec{
			Description: "Fix it",
			Action:      "Do stuff",
		},
	}
	builder := &PromptBuilder{
		AssetID:        "bucket-1",
		ControlsByID:   map[kernel.ControlID]*policy.ControlDefinition{"CTL.A.001": ctl},
		AssetPropsJSON: `{"public_access": true}`,
	}

	findings := []evaluation.Finding{
		{
			ControlID:   "CTL.A.001",
			ControlName: "Test",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
			Evidence: evaluation.Evidence{
				WhyNow: "unsafe",
			},
		},
	}

	data := builder.Build(findings)
	if data.FindingCount != 1 {
		t.Fatalf("FindingCount = %d", data.FindingCount)
	}
	if data.AssetID != "bucket-1" {
		t.Fatalf("AssetID = %q", data.AssetID)
	}
	if data.Findings[0].ControlYAML == "" {
		t.Error("expected control YAML")
	}
	if data.Findings[0].Guidance == "" {
		t.Error("expected guidance")
	}
}

// ---------------------------------------------------------------------------
// RenderPrompt
// ---------------------------------------------------------------------------

func TestRenderPrompt(t *testing.T) {
	data := PromptData{
		FindingCount: 1,
		AssetID:      "bucket-1",
		Findings: []FindingData{
			{
				ControlID:    "CTL.A.001",
				ControlName:  "Test",
				Description:  "Test desc",
				AssetID:      "bucket-1",
				AssetType:    "s3_bucket",
				Evidence:     "- First unsafe: 2026-01-01",
				MatchedProps: "- public_access eq true",
				RootCauses:   "resource",
				ControlYAML:  "id: CTL.A.001",
				Guidance:     "Fix public access",
			},
		},
		AssetProperties: `{"public_access": true}`,
	}

	got := RenderPrompt(data)
	expects := []string{
		"# Stave Finding Analysis",
		"**1 finding(s)**",
		"`bucket-1`",
		"## Finding: CTL.A.001",
		"### Evidence",
		"### Misconfigurations",
		"### Root Causes",
		"### Control Definition (YAML)",
		"### Control Guidance",
		"## Asset Properties",
		"## What I Need",
		"Root cause analysis",
	}
	for _, exp := range expects {
		if !strings.Contains(got, exp) {
			t.Errorf("missing %q in output", exp)
		}
	}
}

func TestRenderPrompt_Minimal(t *testing.T) {
	data := PromptData{
		FindingCount: 0,
		AssetID:      "none",
	}
	got := RenderPrompt(data)
	if !strings.Contains(got, "**0 finding(s)**") {
		t.Error("missing finding count")
	}
}
