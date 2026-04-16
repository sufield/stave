package rank

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestBuildIdentityRanking_ReachableResources(t *testing.T) {
	now := time.Now()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:role-finding",
				ControlID:       "CTL.IAM.NEP.ESCALATION.001",
				AssetID:         "arn:aws:iam::123:role/data-pipeline",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityCritical,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 240,
					ThresholdHours:      168,
					FirstUnsafeAt:       now.Add(-240 * time.Hour),
					LastSeenUnsafeAt:    now,
				},
			},
			RemediationSpec: policy.RemediationSpec{Action: "Remove escalation primitives"},
		},
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:lambda-finding",
				ControlID:       "CTL.LAMBDA.ROLE.LEASTPRIV.001",
				AssetID:         "arn:aws:lambda:us-east-1:123:function/api-handler",
				AssetType:       "aws_lambda_function",
				ControlSeverity: policy.SeverityHigh,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 240,
					ThresholdHours:      168,
					FirstUnsafeAt:       now.Add(-240 * time.Hour),
					LastSeenUnsafeAt:    now,
				},
			},
		},
	}

	// Snapshot links Lambda → role via execution_role.role_arn.
	snapshots := []asset.Snapshot{
		{
			CapturedAt: now,
			Assets: []asset.Asset{
				{
					ID:     "arn:aws:iam::123:role/data-pipeline",
					Type:   "aws_iam_role",
					Vendor: "aws",
					Properties: map[string]any{
						"identity": map[string]any{
							"kind": "role",
							"nep": map[string]any{
								"has_escalation_path": true,
								"privilege_level":     "elevated",
							},
						},
					},
				},
				{
					ID:     "arn:aws:lambda:us-east-1:123:function/api-handler",
					Type:   "aws_lambda_function",
					Vendor: "aws",
					Properties: map[string]any{
						"compute": map[string]any{
							"kind": "function",
							"execution_role": map[string]any{
								"role_arn":          "arn:aws:iam::123:role/data-pipeline",
								"is_overprivileged": true,
							},
						},
					},
				},
			},
		},
	}

	ranking := BuildIdentityRanking(IdentityRankingConfig{Findings: findings, Snapshots: snapshots})

	if ranking.IdentitiesEvaluated != 1 {
		t.Fatalf("expected 1 identity, got %d", ranking.IdentitiesEvaluated)
	}
	if len(ranking.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ranking.Entries))
	}

	entry := ranking.Entries[0]
	if entry.IdentityARN != "arn:aws:iam::123:role/data-pipeline" {
		t.Errorf("identity = %s, want data-pipeline role", entry.IdentityARN)
	}
	if entry.PrivilegeLevel != "elevated" {
		t.Errorf("privilege = %s, want elevated", entry.PrivilegeLevel)
	}
	if len(entry.DirectFindingIDs) != 1 {
		t.Errorf("direct findings = %d, want 1", len(entry.DirectFindingIDs))
	}
	if entry.ReachableCount != 1 {
		t.Errorf("reachable = %d, want 1 (the Lambda function)", entry.ReachableCount)
	}
	if len(entry.TransitiveFindingIDs) != 1 {
		t.Errorf("transitive findings = %d, want 1", len(entry.TransitiveFindingIDs))
	}
	if entry.RiskReductionPercent <= 0 {
		t.Error("risk reduction should be > 0")
	}
	if entry.Rank != 1 {
		t.Errorf("rank = %d, want 1", entry.Rank)
	}
}

func TestBuildIdentityRanking_DirectFindingsOnly(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:admin-finding",
				ControlID:       "CTL.IAM.NEP.ADMIN.001",
				AssetID:         "arn:aws:iam::123:role/admin-role",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityCritical,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 48,
					ThresholdHours:      168,
				},
			},
			RemediationSpec: policy.RemediationSpec{Action: "Remove admin permissions"},
		},
	}

	ranking := BuildIdentityRanking(IdentityRankingConfig{Findings: findings})

	if len(ranking.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(ranking.Entries))
	}
	entry := ranking.Entries[0]
	if entry.ReachableCount != 0 {
		t.Errorf("reachable = %d, want 0 (no snapshot)", entry.ReachableCount)
	}
	if len(entry.DirectFindingIDs) != 1 {
		t.Errorf("direct findings = %d, want 1", len(entry.DirectFindingIDs))
	}
	if entry.RiskReductionPercent != 100 {
		t.Errorf("risk reduction = %.1f%%, want 100%% (only finding)", entry.RiskReductionPercent)
	}
}

func TestBuildIdentityRanking_SortOrder(t *testing.T) {
	now := time.Now()
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:low-risk",
				ControlID:       "CTL.IAM.NEP.ESCALATION.001",
				AssetID:         "arn:aws:iam::123:role/low-risk-role",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityLow,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 10,
					ThresholdHours:      168,
					FirstUnsafeAt:       now.Add(-10 * time.Hour),
					LastSeenUnsafeAt:    now,
				},
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:high-risk",
				ControlID:       "CTL.IAM.NEP.ADMIN.001",
				AssetID:         "arn:aws:iam::123:role/high-risk-role",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityCritical,
				Evidence: evaluation.Evidence{
					UnsafeDurationHours: 500,
					ThresholdHours:      168,
					FirstUnsafeAt:       now.Add(-500 * time.Hour),
					LastSeenUnsafeAt:    now,
				},
			},
		},
	}

	ranking := BuildIdentityRanking(IdentityRankingConfig{Findings: findings})

	if len(ranking.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(ranking.Entries))
	}

	// Higher risk should rank first.
	if ranking.Entries[0].IdentityARN != "arn:aws:iam::123:role/high-risk-role" {
		t.Errorf("rank 1 = %s, want high-risk-role", ranking.Entries[0].IdentityARN)
	}
	if ranking.Entries[1].IdentityARN != "arn:aws:iam::123:role/low-risk-role" {
		t.Errorf("rank 2 = %s, want low-risk-role", ranking.Entries[1].IdentityARN)
	}
	if ranking.Entries[0].RiskReductionScore <= ranking.Entries[1].RiskReductionScore {
		t.Error("rank 1 should have higher risk reduction score")
	}
}

func TestBuildIdentityRanking_TopN(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:a",
				ControlID:       "CTL.A",
				AssetID:         "arn:aws:iam::123:role/role-a",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityHigh,
				Evidence:        evaluation.Evidence{UnsafeDurationHours: 100},
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:b",
				ControlID:       "CTL.B",
				AssetID:         "arn:aws:iam::123:role/role-b",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityLow,
				Evidence:        evaluation.Evidence{UnsafeDurationHours: 10},
			},
		},
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:c",
				ControlID:       "CTL.C",
				AssetID:         "arn:aws:iam::123:role/role-c",
				AssetType:       "aws_iam_role",
				ControlSeverity: policy.SeverityMedium,
				Evidence:        evaluation.Evidence{UnsafeDurationHours: 50},
			},
		},
	}

	ranking := BuildIdentityRanking(IdentityRankingConfig{Findings: findings, TopN: 2})

	if len(ranking.Entries) != 2 {
		t.Fatalf("expected 2 entries (topN=2), got %d", len(ranking.Entries))
	}
}

func TestBuildIdentityRanking_EmptyFindings(t *testing.T) {
	ranking := BuildIdentityRanking(IdentityRankingConfig{})
	if len(ranking.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(ranking.Entries))
	}
}

func TestBuildIdentityRanking_NonIdentityFindingsExcluded(t *testing.T) {
	findings := []remediation.Finding{
		{
			Finding: evaluation.Finding{
				FindingID:       "sha256:s3-finding",
				ControlID:       "CTL.S3.PUBLIC.001",
				AssetID:         "arn:aws:s3:::my-bucket",
				AssetType:       "aws_s3_bucket",
				ControlSeverity: policy.SeverityHigh,
				Evidence:        evaluation.Evidence{UnsafeDurationHours: 100},
			},
		},
	}

	ranking := BuildIdentityRanking(IdentityRankingConfig{Findings: findings})

	// S3 bucket is not an identity — should produce no entries.
	if len(ranking.Entries) != 0 {
		t.Errorf("expected 0 identity entries for S3 finding, got %d", len(ranking.Entries))
	}
}
