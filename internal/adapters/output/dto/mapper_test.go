package dto

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/exposure"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func TestFromEvaluation_MinimalEnvelope(t *testing.T) {
	env := safetyenvelope.NewEvaluation(safetyenvelope.EvaluationRequest{
		Run: evaluation.RunInfo{
			StaveVersion:      "test",
			Offline:           true,
			Now:               time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
			MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
			Snapshots:         2,
		},
		Summary: evaluation.Summary{
			AssetsEvaluated: 3,
			AttackSurface:   1,
			Violations:      0,
		},
		SafetyStatus: evaluation.StatusSafe,
		Findings:     []remediation.Finding{},
	})

	dto := FromEvaluation(env)

	if dto.SchemaVersion != kernel.SchemaOutput {
		t.Errorf("SchemaVersion = %q, want %q", dto.SchemaVersion, kernel.SchemaOutput)
	}
	if dto.Kind != "evaluation" {
		t.Errorf("Kind = %q, want evaluation", dto.Kind)
	}
	if dto.Run.StaveVersion != "test" {
		t.Errorf("Run.StaveVersion = %q", dto.Run.StaveVersion)
	}
	if !dto.Run.Offline {
		t.Error("Run.Offline = false, want true")
	}
	if dto.Run.Snapshots != 2 {
		t.Errorf("Run.Snapshots = %d", dto.Run.Snapshots)
	}
	if dto.Summary.AssetsEvaluated != 3 {
		t.Errorf("Summary.AssetsEvaluated = %d", dto.Summary.AssetsEvaluated)
	}
	if dto.SafetyStatus != evaluation.StatusSafe {
		t.Errorf("SafetyStatus = %q", dto.SafetyStatus)
	}
	if len(dto.Findings) != 0 {
		t.Errorf("len(Findings) = %d", len(dto.Findings))
	}
	if dto.AtRisk != nil {
		t.Error("AtRisk should be nil for empty items")
	}
	if dto.Skipped != nil {
		t.Error("Skipped should be nil for empty input")
	}
	if dto.ExemptedAssets != nil {
		t.Error("ExemptedAssets should be nil for empty input")
	}
	if dto.ExceptedFindings != nil {
		t.Error("ExceptedFindings should be nil for empty input")
	}
	if dto.RemediationGroups != nil {
		t.Error("RemediationGroups should be nil for empty input")
	}
	if dto.Extensions != nil {
		t.Error("Extensions should be nil for empty input")
	}
}

func TestFromFinding_AllFields(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	f := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:          "CTL.S3.PUBLIC.001",
			ControlName:        "No Public S3 Bucket Read",
			ControlDescription: "Buckets must not allow public read access.",
			AssetID:            "res:aws:s3:bucket:test-bucket",
			AssetType:          kernel.AssetType("aws:s3:bucket"),
			AssetVendor:        kernel.Vendor("aws"),
			Source:             &asset.SourceRef{File: "/tmp/main.tf", Line: 42},
			Evidence: evaluation.Evidence{
				FirstUnsafeAt:       now.Add(-48 * time.Hour),
				LastSeenUnsafeAt:    now.Add(-1 * time.Hour),
				UnsafeDurationHours: 47,
				ThresholdHours:      24,
				WhyNow:              "Threshold exceeded",
				Misconfigurations: []policy.Misconfiguration{
					{Property: "storage.access.public_read", ActualValue: true, Operator: "eq", UnsafeValue: true},
				},
				RootCauses: []evaluation.RootCause{evaluation.RootCauseIdentity},
				SourceEvidence: &evaluation.SourceEvidence{
					IdentityStatements: []kernel.StatementID{"arn:aws:iam::123456789012:user/admin"},
					ResourceGrantees:   []kernel.GranteeID{"AllUsers"},
				},
			},
			ControlSeverity:   policy.SeverityCritical,
			ControlCompliance: policy.ComplianceMapping{"cis_aws": "2.1.5"},
			Exposure: &policy.Exposure{
				Type:           exposure.Type("public_read"),
				PrincipalScope: kernel.ScopePublic,
			},
			PostureDrift: &evaluation.PostureDrift{
				Pattern:      evaluation.DriftIntermittent,
				EpisodeCount: 3,
			},
		},
		RemediationSpec: policy.RemediationSpec{
			Description: "Disable public read access",
			Action:      "Block public access",
			Example:     `{"public_read": false}`,
		},
		RemediationPlan: &evaluation.RemediationPlan{
			ID: "fix-001",
			Target: evaluation.RemediationTarget{
				AssetID:   "res:aws:s3:bucket:test-bucket",
				AssetType: kernel.AssetType("aws:s3:bucket"),
			},
			Preconditions:  []string{"bucket exists"},
			ExpectedEffect: "removes public access",
			Actions: []evaluation.RemediationAction{
				{ActionType: "set", Path: ".public_read", Value: false},
			},
		},
	}

	dto := FromFinding(f)

	if dto.ControlID != "CTL.S3.PUBLIC.001" {
		t.Errorf("ControlID = %q", dto.ControlID)
	}
	if dto.ControlName != "No Public S3 Bucket Read" {
		t.Errorf("ControlName = %q", dto.ControlName)
	}
	if dto.AssetID != "res:aws:s3:bucket:test-bucket" {
		t.Errorf("AssetID = %q", dto.AssetID)
	}
	if dto.Source == nil || dto.Source.File != "/tmp/main.tf" || dto.Source.Line != 42 {
		t.Errorf("Source = %+v", dto.Source)
	}
	if dto.Evidence.UnsafeDurationHours != 47 {
		t.Errorf("Evidence.UnsafeDurationHours = %f", dto.Evidence.UnsafeDurationHours)
	}
	if dto.Evidence.WhyNow != "Threshold exceeded" {
		t.Errorf("Evidence.WhyNow = %q", dto.Evidence.WhyNow)
	}
	if len(dto.Evidence.Misconfigurations) != 1 {
		t.Fatalf("len(Evidence.Misconfigurations) = %d", len(dto.Evidence.Misconfigurations))
	}
	if dto.Evidence.Misconfigurations[0].Property != "storage.access.public_read" {
		t.Errorf("Misconfiguration.Property = %q", dto.Evidence.Misconfigurations[0].Property)
	}
	if len(dto.Evidence.RootCauses) != 1 || dto.Evidence.RootCauses[0] != "identity" {
		t.Errorf("Evidence.RootCauses = %v", dto.Evidence.RootCauses)
	}
	if dto.Evidence.SourceEvidence == nil {
		t.Fatal("Evidence.SourceEvidence is nil")
	}
	if len(dto.Evidence.SourceEvidence.IdentityStatements) != 1 {
		t.Errorf("IdentityStatements = %v", dto.Evidence.SourceEvidence.IdentityStatements)
	}
	if dto.ControlSeverity != "critical" {
		t.Errorf("ControlSeverity = %q", dto.ControlSeverity)
	}
	if dto.ControlCompliance["cis_aws"] != "2.1.5" {
		t.Errorf("ControlCompliance = %v", dto.ControlCompliance)
	}
	if dto.Exposure == nil || dto.Exposure.Type != "public_read" {
		t.Errorf("Exposure = %+v", dto.Exposure)
	}
	if dto.PostureDrift == nil || dto.PostureDrift.EpisodeCount != 3 {
		t.Errorf("PostureDrift = %+v", dto.PostureDrift)
	}
	if dto.Remediation.Description != "Disable public read access" {
		t.Errorf("Remediation.Description = %q", dto.Remediation.Description)
	}
	if dto.RemediationPlan == nil || dto.RemediationPlan.ID != "fix-001" {
		t.Errorf("RemediationPlan = %+v", dto.RemediationPlan)
	}
	if len(dto.RemediationPlan.Actions) != 1 {
		t.Errorf("RemediationPlan.Actions = %v", dto.RemediationPlan.Actions)
	}
	if len(dto.RemediationPlan.Preconditions) != 1 {
		t.Errorf("RemediationPlan.Preconditions = %v", dto.RemediationPlan.Preconditions)
	}
}

func TestFromFinding_MinimalFields(t *testing.T) {
	f := remediation.Finding{
		Finding: evaluation.Finding{
			ControlID: "CTL.TEST.001",
			AssetID:   "res-1",
		},
	}
	dto := FromFinding(f)

	if dto.ControlID != "CTL.TEST.001" {
		t.Errorf("ControlID = %q", dto.ControlID)
	}
	if dto.Source != nil {
		t.Error("Source should be nil for missing source")
	}
	if dto.Exposure != nil {
		t.Error("Exposure should be nil for missing exposure")
	}
	if dto.PostureDrift != nil {
		t.Error("PostureDrift should be nil for missing drift")
	}
	if dto.RemediationPlan != nil {
		t.Error("RemediationPlan should be nil for missing plan")
	}
	if dto.ControlSeverity != "" {
		t.Errorf("ControlSeverity = %q, want empty", dto.ControlSeverity)
	}
	if dto.ControlCompliance != nil {
		t.Errorf("ControlCompliance = %v, want nil", dto.ControlCompliance)
	}
}

func TestFromFindings_NilInput(t *testing.T) {
	result := fromFindings(nil)
	if result != nil {
		t.Errorf("fromFindings(nil) = %v, want nil", result)
	}
}

func TestFromFindings_EmptySlice(t *testing.T) {
	result := fromFindings([]remediation.Finding{})
	if result == nil || len(result) != 0 {
		t.Errorf("fromFindings([]) = %v, want empty non-nil slice", result)
	}
}

func TestMapSlice_NilInput(t *testing.T) {
	result := mapSlice[int, string](nil, func(i int) string { return "" })
	if result != nil {
		t.Errorf("mapSlice(nil, ...) = %v, want nil", result)
	}
}

func TestMapSlice_EmptyInput(t *testing.T) {
	result := mapSlice([]int{}, func(i int) string { return "x" })
	if len(result) != 0 {
		t.Errorf("mapSlice([], ...) = %v, want empty", result)
	}
}

func TestMapSlice_Transform(t *testing.T) {
	result := mapSlice([]int{1, 2, 3}, func(i int) int { return i * 2 })
	if len(result) != 3 || result[0] != 2 || result[1] != 4 || result[2] != 6 {
		t.Errorf("mapSlice([1,2,3], *2) = %v", result)
	}
}

func TestFromExceptedFindings_Empty(t *testing.T) {
	result := fromExceptedFindings(nil)
	if result != nil {
		t.Error("fromExceptedFindings(nil) should be nil")
	}
	result = fromExceptedFindings([]evaluation.ExceptedFinding{})
	if result != nil {
		t.Error("fromExceptedFindings([]) should be nil")
	}
}

func TestFromExceptedFindings_WithData(t *testing.T) {
	input := []evaluation.ExceptedFinding{
		{ControlID: "CTL.A", AssetID: "res-1", Reason: "known", Expires: "2027-01-01"},
	}
	result := fromExceptedFindings(input)
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0].ControlID != "CTL.A" || result[0].Reason != "known" || result[0].Expires != "2027-01-01" {
		t.Errorf("result[0] = %+v", result[0])
	}
}

func TestFromSkippedControls_Empty(t *testing.T) {
	result := fromSkippedControls(nil)
	if result != nil {
		t.Error("fromSkippedControls(nil) should be nil")
	}
}

func TestFromSkippedControls_WithData(t *testing.T) {
	input := []evaluation.SkippedControl{
		{ControlID: "CTL.SKIP.001", ControlName: "Skipped", Reason: "no match"},
	}
	result := fromSkippedControls(input)
	if len(result) != 1 || result[0].ControlID != "CTL.SKIP.001" {
		t.Errorf("result = %+v", result)
	}
}

func TestFromExemptedAssets_Empty(t *testing.T) {
	result := fromExemptedAssets(nil)
	if result != nil {
		t.Error("fromExemptedAssets(nil) should be nil")
	}
}

func TestFromExemptedAssets_WithData(t *testing.T) {
	input := []asset.ExemptedAsset{
		{ID: "res-skip", Pattern: "*-skip", Reason: "excluded"},
	}
	result := fromExemptedAssets(input)
	if len(result) != 1 || result[0].AssetID != "res-skip" || result[0].Pattern != "*-skip" {
		t.Errorf("result = %+v", result)
	}
}

func TestFromRemediationGroups_Empty(t *testing.T) {
	result := fromRemediationGroups(nil)
	if result != nil {
		t.Error("fromRemediationGroups(nil) should be nil")
	}
}

func TestFromRemediationGroups_WithData(t *testing.T) {
	input := []remediation.Group{
		{
			AssetID:   "res-1",
			AssetType: "aws:s3:bucket",
			RemediationPlan: evaluation.RemediationPlan{
				ID: "grp-1",
				Target: evaluation.RemediationTarget{
					AssetID:   "res-1",
					AssetType: "aws:s3:bucket",
				},
			},
			ContributingControls: []kernel.ControlID{"CTL.A", "CTL.B"},
			FindingCount:         2,
		},
	}
	result := fromRemediationGroups(input)
	if len(result) != 1 || result[0].FindingCount != 2 {
		t.Errorf("result = %+v", result)
	}
	if len(result[0].ContributingControls) != 2 {
		t.Errorf("ContributingControls = %v", result[0].ContributingControls)
	}
}

func TestFromAtRiskItems_Empty(t *testing.T) {
	result := fromAtRiskItems(nil)
	if result != nil {
		t.Error("fromAtRiskItems(nil) should be nil")
	}
}

func TestFromAtRiskItems_WithData(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	input := risk.ThresholdItems{
		{
			ControlID:     "CTL.A",
			AssetID:       "res-1",
			AssetType:     "aws:s3:bucket",
			Status:        risk.StatusUpcoming,
			DueAt:         now.Add(2 * time.Hour),
			Remaining:     2 * time.Hour,
			FirstUnsafeAt: now.Add(-22 * time.Hour),
			Threshold:     24 * time.Hour,
		},
	}
	result := fromAtRiskItems(input)
	if len(result) != 1 {
		t.Fatalf("len = %d", len(result))
	}
	if result[0].ControlID != "CTL.A" {
		t.Errorf("ControlID = %q", result[0].ControlID)
	}
	if result[0].RemainingHours != 2 {
		t.Errorf("RemainingHours = %f", result[0].RemainingHours)
	}
	if result[0].ThresholdHours != 24 {
		t.Errorf("ThresholdHours = %f", result[0].ThresholdHours)
	}
	if result[0].Status != string(risk.StatusUpcoming) {
		t.Errorf("Status = %q", result[0].Status)
	}
}

func TestFromRunInfo_WithInputHashes(t *testing.T) {
	ri := evaluation.RunInfo{
		StaveVersion:      "v1",
		Offline:           false,
		Now:               time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: kernel.Duration(24 * time.Hour),
		Snapshots:         3,
		InputHashes: &evaluation.InputHashes{
			Files:   map[evaluation.FilePath]kernel.Digest{"a.json": "sha256:abc"},
			Overall: "sha256:def",
		},
	}
	dto := fromRunInfo(ri)
	if dto.InputHashes == nil {
		t.Fatal("InputHashes is nil")
	}
	if dto.InputHashes.Files["a.json"] != "sha256:abc" {
		t.Errorf("Files = %v", dto.InputHashes.Files)
	}
	if dto.InputHashes.Overall != "sha256:def" {
		t.Errorf("Overall = %q", dto.InputHashes.Overall)
	}
}

func TestFromRunInfo_NilInputHashes(t *testing.T) {
	ri := evaluation.RunInfo{StaveVersion: "v1"}
	dto := fromRunInfo(ri)
	if dto.InputHashes != nil {
		t.Error("InputHashes should be nil")
	}
}

func TestFromInputHashes_Nil(t *testing.T) {
	result := fromInputHashes(nil)
	if result != nil {
		t.Error("fromInputHashes(nil) should be nil")
	}
}

func TestFromExtensions_Nil(t *testing.T) {
	result := fromExtensions(nil)
	if result != nil {
		t.Error("fromExtensions(nil) should be nil")
	}
}

func TestFromExtensions_WithGit(t *testing.T) {
	ext := &evaluation.Extensions{
		SelectedSource: "dir",
		ContextName:    "dev",
		ResolvedPaths:  map[string]string{"controls": "/ctl"},
		EnabledPacks:   []string{"s3/public"},
		Git: &evaluation.GitMetadata{
			RepoRoot: "/repo",
			Head:     "abc123",
			Dirty:    true,
			Modified: []string{"main.tf"},
		},
	}
	dto := fromExtensions(ext)
	if dto == nil {
		t.Fatal("fromExtensions returned nil")
	}
	if dto.SelectedSource != "dir" {
		t.Errorf("SelectedSource = %q", dto.SelectedSource)
	}
	if dto.ContextName != "dev" {
		t.Errorf("ContextName = %q", dto.ContextName)
	}
	if dto.Git == nil {
		t.Fatal("Git is nil")
	}
	if dto.Git.RepoRoot != "/repo" {
		t.Errorf("Git.RepoRoot = %q", dto.Git.RepoRoot)
	}
	if !dto.Git.Dirty {
		t.Error("Git.Dirty = false, want true")
	}
	if len(dto.Git.Modified) != 1 {
		t.Errorf("Git.Modified = %v", dto.Git.Modified)
	}
}

func TestFromExtensions_WithoutGit(t *testing.T) {
	ext := &evaluation.Extensions{
		SelectedSource: "packs",
		EnabledPacks:   []string{"s3/all"},
	}
	dto := fromExtensions(ext)
	if dto == nil {
		t.Fatal("fromExtensions returned nil")
	}
	if dto.Git != nil {
		t.Error("Git should be nil")
	}
	if len(dto.EnabledPacks) != 1 || dto.EnabledPacks[0] != "s3/all" {
		t.Errorf("EnabledPacks = %v", dto.EnabledPacks)
	}
}

func TestFromSummary(t *testing.T) {
	s := evaluation.Summary{AssetsEvaluated: 5, AttackSurface: 2, Violations: 1}
	dto := fromSummary(s)
	if dto.AssetsEvaluated != 5 || dto.AttackSurface != 2 || dto.Violations != 1 {
		t.Errorf("Summary = %+v", dto)
	}
}

func TestFromEvidence_WithAllFields(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	ev := evaluation.Evidence{
		FirstUnsafeAt:       now.Add(-48 * time.Hour),
		LastSeenUnsafeAt:    now,
		UnsafeDurationHours: 48,
		ThresholdHours:      24,
		EpisodeCount:        2,
		WindowDays:          30,
		RecurrenceLimit:     3,
		FirstEpisodeAt:      now.Add(-72 * time.Hour),
		LastEpisodeAt:       now,
		WhyNow:              "threshold exceeded",
		Misconfigurations: []policy.Misconfiguration{
			{Property: "x", ActualValue: true, Operator: "eq"},
		},
		RootCauses: []evaluation.RootCause{evaluation.RootCauseIdentity},
		SourceEvidence: &evaluation.SourceEvidence{
			IdentityStatements: []kernel.StatementID{"user"},
			ResourceGrantees:   []kernel.GranteeID{"all"},
		},
	}
	dto := fromEvidence(ev)
	if dto.UnsafeDurationHours != 48 {
		t.Errorf("UnsafeDurationHours = %f", dto.UnsafeDurationHours)
	}
	if dto.EpisodeCount != 2 {
		t.Errorf("EpisodeCount = %d", dto.EpisodeCount)
	}
	if len(dto.Misconfigurations) != 1 {
		t.Errorf("len(Misconfigurations) = %d", len(dto.Misconfigurations))
	}
	if len(dto.RootCauses) != 1 {
		t.Errorf("len(RootCauses) = %d", len(dto.RootCauses))
	}
	if dto.SourceEvidence == nil {
		t.Fatal("SourceEvidence is nil")
	}
}

func TestFromRemediationAction(t *testing.T) {
	a := evaluation.RemediationAction{
		ActionType: "set",
		Path:       ".public",
		Value:      false,
	}
	dto := fromRemediationAction(a)
	if dto.ActionType != "set" || dto.Path != ".public" || dto.Value != false {
		t.Errorf("dto = %+v", dto)
	}
}

func TestFromMisconfiguration(t *testing.T) {
	m := policy.Misconfiguration{
		Property:    "storage.access.public_read",
		ActualValue: true,
		Operator:    "eq",
		UnsafeValue: true,
	}
	dto := fromMisconfiguration(m)
	if dto.Property != "storage.access.public_read" {
		t.Errorf("Property = %q", dto.Property)
	}
	if dto.Operator != "eq" {
		t.Errorf("Operator = %q", dto.Operator)
	}
}

func TestFromRemediationSpec(t *testing.T) {
	s := policy.RemediationSpec{
		Description: "fix it",
		Action:      "do something",
		Example:     "example code",
	}
	dto := fromRemediationSpec(s)
	if dto.Description != "fix it" || dto.Action != "do something" || dto.Example != "example code" {
		t.Errorf("dto = %+v", dto)
	}
}
