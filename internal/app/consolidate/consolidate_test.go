package consolidate

import (
	"context"
	"strings"
	"testing"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/core/access"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// testAccountIDFromARN is a minimal ARN account-ID extractor for
// tests. Production wires iam.ExtractAccountID via cmd/consolidate;
// the test injects this thin equivalent so consolidate's
// cross-account analysis runs without taking a dependency on the
// AWS provider package.
//
// ARN shape: arn:partition:service:region:account-id:resource
func testAccountIDFromARN(s string) string {
	parts := strings.Split(s, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[4]
}

// testEmptyResourceAccessIndex is a no-op index builder. The
// execution-role cross-account pass does not consult the index, so
// returning an empty one is sufficient to satisfy the Run-level
// gate.
func testEmptyResourceAccessIndex(*asset.Snapshot) *access.ResourceAccessIndex {
	return access.NewResourceAccessIndex()
}

func makeControl(id string, severity policy.Severity) policy.ControlDefinition {
	return policy.ControlDefinition{
		DSLVersion: "ctrl.v1",
		ID:         kernel.ControlID(id),
		Name:       id,
		Severity:   severity,
		Type:       policy.TypeUnsafeState,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.test.unsafe"), Op: "eq", Value: policy.Bool(true)},
			},
		},
	}
}

func makeSnapshot(capturedAt time.Time, assets []asset.Asset) asset.Snapshot {
	return asset.Snapshot{
		SchemaVersion: "obs.v0.1",
		CapturedAt:    capturedAt,
		Source:        "deployed",
		Assets:        assets,
	}
}

func TestRun_TwoAccounts(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	controls := []policy.ControlDefinition{
		makeControl("CTL.TEST.001", policy.SeverityCritical),
	}

	input := Input{
		Accounts: []AccountInput{
			{
				AccountID:   "111111111111",
				AccountName: "production",
				Environment: "production",
				Snapshots: []asset.Snapshot{
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:s3:::prod-bucket", Type: "aws_s3_bucket", Vendor: "aws",
							Properties: map[string]any{"test": map[string]any{"unsafe": true}}},
					}),
					makeSnapshot(t2, []asset.Asset{
						{ID: "arn:aws:s3:::prod-bucket", Type: "aws_s3_bucket", Vendor: "aws",
							Properties: map[string]any{"test": map[string]any{"unsafe": true}}},
					}),
				},
			},
			{
				AccountID:   "222222222222",
				AccountName: "development",
				Environment: "non-production",
				Snapshots: []asset.Snapshot{
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:s3:::dev-bucket", Type: "aws_s3_bucket", Vendor: "aws",
							Properties: map[string]any{"test": map[string]any{"unsafe": true}}},
					}),
					makeSnapshot(t2, []asset.Asset{
						{ID: "arn:aws:s3:::dev-bucket", Type: "aws_s3_bucket", Vendor: "aws",
							Properties: map[string]any{"test": map[string]any{"unsafe": true}}},
					}),
				},
			},
		},
		Controls:     controls,
		CELEvaluator: stavecel.MustPredicateEval(),
		OrgName:      "Test Org",
		Now:          time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	report, warnings, err := Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
	if report.AccountCount != 2 {
		t.Errorf("AccountCount = %d, want 2", report.AccountCount)
	}
	if report.OrgPosture.TotalFindings != 2 {
		t.Errorf("TotalFindings = %d, want 2", report.OrgPosture.TotalFindings)
	}
	if report.OrgPosture.CriticalFindings != 2 {
		t.Errorf("CriticalFindings = %d, want 2", report.OrgPosture.CriticalFindings)
	}
	if len(report.Accounts) != 2 {
		t.Fatalf("Accounts = %d, want 2", len(report.Accounts))
	}
	// Both accounts should have rank 1 and 2.
	if report.Accounts[0].OrgRiskRank != 1 || report.Accounts[1].OrgRiskRank != 2 {
		t.Error("accounts should be ranked")
	}
}

func TestRun_SnapshotStalenessWarning(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 12, 12, 0, 0, 0, time.UTC) // 60h later

	input := Input{
		Accounts: []AccountInput{
			{
				AccountID: "111111111111",
				Snapshots: []asset.Snapshot{makeSnapshot(t1, nil), makeSnapshot(t1, nil)},
			},
			{
				AccountID: "222222222222",
				Snapshots: []asset.Snapshot{makeSnapshot(t2, nil), makeSnapshot(t2, nil)},
			},
		},
		Controls:     []policy.ControlDefinition{makeControl("CTL.TEST.001", policy.SeverityLow)},
		CELEvaluator: stavecel.MustPredicateEval(),
		Now:          time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	_, warnings, err := Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, w := range warnings {
		if w != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected staleness warning for 60h gap")
	}
}

func TestRun_SingleAccount(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

	input := Input{
		Accounts: []AccountInput{
			{
				AccountID:   "111111111111",
				AccountName: "solo",
				Snapshots: []asset.Snapshot{
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:s3:::bucket", Type: "aws_s3_bucket", Vendor: "aws",
							Properties: map[string]any{"test": map[string]any{"unsafe": true}}},
					}),
					makeSnapshot(t2, []asset.Asset{
						{ID: "arn:aws:s3:::bucket", Type: "aws_s3_bucket", Vendor: "aws",
							Properties: map[string]any{"test": map[string]any{"unsafe": true}}},
					}),
				},
			},
		},
		Controls:     []policy.ControlDefinition{makeControl("CTL.TEST.001", policy.SeverityHigh)},
		CELEvaluator: stavecel.MustPredicateEval(),
		Now:          time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
	}

	report, _, err := Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	if report.AccountCount != 1 {
		t.Errorf("AccountCount = %d, want 1", report.AccountCount)
	}
	if report.OrgPosture.TotalFindings != 1 {
		t.Errorf("TotalFindings = %d, want 1", report.OrgPosture.TotalFindings)
	}
}

func TestRun_EmptyAccounts(t *testing.T) {
	_, _, err := Run(context.Background(), Input{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestRun_CrossAccountExecutionRole(t *testing.T) {
	t1 := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	input := Input{
		Accounts: []AccountInput{
			{
				AccountID: "111111111111",
				Snapshots: []asset.Snapshot{
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:iam::111111111111:role/cross-role", Type: "aws_iam_role", Vendor: "aws",
							Properties: map[string]any{}},
					}),
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:iam::111111111111:role/cross-role", Type: "aws_iam_role", Vendor: "aws",
							Properties: map[string]any{}},
					}),
				},
			},
			{
				AccountID: "222222222222",
				Snapshots: []asset.Snapshot{
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:lambda:us-east-1:222222222222:function/api", Type: "aws_lambda_function", Vendor: "aws",
							Properties: map[string]any{
								"compute": map[string]any{
									"kind": "function",
									"execution_role": map[string]any{
										"role_arn": "arn:aws:iam::111111111111:role/cross-role",
									},
								},
							}},
					}),
					makeSnapshot(t1, []asset.Asset{
						{ID: "arn:aws:lambda:us-east-1:222222222222:function/api", Type: "aws_lambda_function", Vendor: "aws",
							Properties: map[string]any{
								"compute": map[string]any{
									"kind": "function",
									"execution_role": map[string]any{
										"role_arn": "arn:aws:iam::111111111111:role/cross-role",
									},
								},
							}},
					}),
				},
			},
		},
		Controls:     []policy.ControlDefinition{makeControl("CTL.TEST.001", policy.SeverityLow)},
		CELEvaluator: stavecel.MustPredicateEval(),
		Now:          time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),

		// Inject the provider-specific helpers so Run executes the
		// cross-account analysis. Production wires iam.* equivalents
		// in cmd/consolidate; the test stays vendor-neutral by
		// providing thin substitutes.
		AccountIDFromARN:         testAccountIDFromARN,
		BuildResourceAccessIndex: testEmptyResourceAccessIndex,
	}

	report, _, err := Run(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}

	if len(report.CrossAccount) == 0 {
		t.Error("expected cross-account finding for execution role spanning accounts")
	}
	if report.OrgPosture.CrossAccountIdentities == 0 {
		t.Error("expected cross-account identities > 0")
	}

	// Verify the finding details.
	found := false
	for _, cf := range report.CrossAccount {
		if cf.Type == "cross_account_role_chain" &&
			cf.SourceAccountID == "111111111111" &&
			cf.TargetAccountID == "222222222222" {
			found = true
		}
	}
	if !found {
		t.Error("cross-account role chain finding not found with correct account attribution")
	}
}
