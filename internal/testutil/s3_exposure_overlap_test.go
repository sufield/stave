package testutil

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/domain/kernel"
)

type overlapInput struct {
	Buckets []exposure.ExposureBucketInput `json:"buckets"`
}

func TestS3ExposureOverlapCases(t *testing.T) {
	// Load input
	inputData, err := os.ReadFile(filepath.Join(TestdataDir(t), "s3_exposure", "overlap_cases.json"))
	if err != nil {
		t.Fatalf("failed to read overlap_cases.json: %v", err)
	}
	var input overlapInput
	if err = json.Unmarshal(inputData, &input); err != nil {
		t.Fatalf("failed to parse overlap_cases.json: %v", err)
	}

	// Load expected
	expectedData, err := os.ReadFile(filepath.Join(TestdataDir(t), "s3_exposure", "expected", "overlap_cases.findings.json"))
	if err != nil {
		t.Fatalf("failed to read expected findings: %v", err)
	}
	var expected exposure.Classifications
	if err = json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatalf("failed to parse expected findings: %v", err)
	}

	// Run evaluator
	actual := exposure.ClassifyExposure(input.Buckets)

	// Compare as JSON for golden comparison
	actualJSON, err := json.MarshalIndent(exposure.Classifications{Classifications: actual}, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal actual findings: %v", err)
	}
	expectedJSON, err := json.MarshalIndent(expected, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal expected findings: %v", err)
	}

	if string(actualJSON) != string(expectedJSON) {
		t.Errorf("findings mismatch\n--- expected ---\n%s\n--- actual ---\n%s", expectedJSON, actualJSON)
	}
}

func TestS3ExposureNoDuplicateREAD(t *testing.T) {
	// policy+acl_read_bucket: both policy and ACL grant read → only one READ finding
	bucket := exposure.ExposureBucketInput{
		Name:    "test-dedup",
		Exists:  true,
		Website: exposure.WebsiteConfig{Enabled: false},
		Policy: exposure.PolicyConfig{
			Statements: []exposure.StatementInput{
				{Effect: "Allow", Principal: "*", Actions: []string{"s3:GetObject"}},
			},
		},
		ACL: exposure.ACLConfig{
			Grants: []exposure.ACLGrant{
				{Grantee: "AllUsers", Permission: "READ", Scope: "object"},
			},
		},
	}

	findings := exposure.ClassifyExposure([]exposure.ExposureBucketInput{bucket})

	readCount := 0
	for _, f := range findings {
		if f.ID == "CTL.S3.PUBLIC.READ.001" {
			readCount++
		}
	}
	if readCount != 1 {
		t.Errorf("expected 1 READ finding, got %d", readCount)
	}
}

func TestS3ExposureWebsiteSuppressesREAD(t *testing.T) {
	bucket := exposure.ExposureBucketInput{
		Name:    "test-website",
		Exists:  true,
		Website: exposure.WebsiteConfig{Enabled: true},
		Policy:  exposure.PolicyConfig{Statements: []exposure.StatementInput{}},
		ACL: exposure.ACLConfig{
			Grants: []exposure.ACLGrant{
				{Grantee: "AllUsers", Permission: "READ", Scope: "object"},
			},
		},
	}

	findings := exposure.ClassifyExposure([]exposure.ExposureBucketInput{bucket})

	for _, f := range findings {
		if f.ID == "CTL.S3.PUBLIC.READ.001" {
			t.Error("PUBLIC.READ should be suppressed when WEBSITE.PUBLIC is emitted")
		}
	}

	websiteCount := 0
	for _, f := range findings {
		if f.ID == "CTL.S3.WEBSITE.PUBLIC.001" {
			websiteCount++
		}
	}
	if websiteCount != 1 {
		t.Errorf("expected 1 WEBSITE.PUBLIC finding, got %d", websiteCount)
	}
}

func TestS3ExposureWriteScopeBlindVsFull(t *testing.T) {
	tests := []struct {
		name          string
		hasGet        bool
		hasList       bool
		expectedScope string
	}{
		{"blind_no_read", false, false, "blind"},
		{"full_with_read", true, false, "full"},
		{"full_with_list", false, true, "full"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmts := []exposure.StatementInput{
				{Effect: "Allow", Principal: "*", Actions: []string{"s3:PutObject"}},
			}
			if tc.hasGet {
				stmts[0].Actions = append(stmts[0].Actions, "s3:GetObject")
			}
			if tc.hasList {
				stmts[0].Actions = append(stmts[0].Actions, "s3:ListBucket")
			}

			bucket := exposure.ExposureBucketInput{
				Name:    "test-scope",
				Exists:  true,
				Website: exposure.WebsiteConfig{Enabled: false},
				Policy:  exposure.PolicyConfig{Statements: stmts},
				ACL:     exposure.ACLConfig{Grants: []exposure.ACLGrant{}},
			}

			findings := exposure.ClassifyExposure([]exposure.ExposureBucketInput{bucket})

			for _, f := range findings {
				if f.ID == "CTL.S3.PUBLIC.WRITE.001" {
					if f.WriteScope != tc.expectedScope {
						t.Errorf("write_scope = %q, want %q", f.WriteScope, tc.expectedScope)
					}
					return
				}
			}
			t.Error("expected PUBLIC.WRITE finding")
		})
	}
}

func TestS3ExposureAuthenticatedScope(t *testing.T) {
	bucket := exposure.ExposureBucketInput{
		Name:    "test-auth",
		Exists:  true,
		Website: exposure.WebsiteConfig{Enabled: false},
		Policy: exposure.PolicyConfig{
			Statements: []exposure.StatementInput{
				{Effect: "Allow", Principal: "AWS:AuthenticatedUsers", Actions: []string{"s3:PutObject"}},
			},
		},
		ACL: exposure.ACLConfig{Grants: []exposure.ACLGrant{}},
	}

	findings := exposure.ClassifyExposure([]exposure.ExposureBucketInput{bucket})

	for _, f := range findings {
		if f.PrincipalScope != kernel.ScopeAuthenticated {
			t.Errorf("principal_scope = %q, want %q", f.PrincipalScope.String(), kernel.ScopeAuthenticated.String())
		}
	}
}
