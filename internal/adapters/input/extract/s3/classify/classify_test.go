package classify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/exposure"
	"github.com/sufield/stave/internal/testutil"
)

// loadExposureFixture loads a JSON fixture file and returns the S3 bucket inputs.
func loadExposureFixture(t *testing.T, filename string) []Bucket {
	t.Helper()
	path := filepath.Join(testutil.TestdataDir(t), "s3_exposure", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", filename, err)
	}
	var input struct {
		Buckets []Bucket `json:"buckets"`
	}
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatalf("failed to parse fixture %s: %v", filename, err)
	}
	return input.Buckets
}

// loadExpectedFindings loads expected findings from a JSON file.
func loadExpectedFindings(t *testing.T, filename string) []exposure.ExposureClassification {
	t.Helper()
	path := filepath.Join(testutil.TestdataDir(t), "s3_exposure", "expected", filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read expected %s: %v", filename, err)
	}
	var expected exposure.Classifications
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatalf("failed to parse expected %s: %v", filename, err)
	}
	return expected.Classifications
}

// compareFindings compares actual findings against expected, producing detailed diffs.
func compareFindings(t *testing.T, actual, expected []exposure.ExposureClassification) {
	t.Helper()
	actualJSON, _ := json.MarshalIndent(exposure.Classifications{Classifications: actual}, "", "  ")
	expectedJSON, _ := json.MarshalIndent(exposure.Classifications{Classifications: expected}, "", "  ")
	if string(actualJSON) != string(expectedJSON) {
		t.Errorf("findings mismatch\nexpected:\n%s\n\nactual:\n%s", expectedJSON, actualJSON)
	}
}

func TestClassifyExposure_PublicReadPolicy(t *testing.T) {
	buckets := loadExposureFixture(t, "public_read_policy.json")
	expected := loadExpectedFindings(t, "public_read_policy.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_PublicListACL(t *testing.T) {
	buckets := loadExposureFixture(t, "public_list_acl.json")
	expected := loadExpectedFindings(t, "public_list_acl.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_PublicWritePolicy(t *testing.T) {
	buckets := loadExposureFixture(t, "public_write_policy.json")
	expected := loadExpectedFindings(t, "public_write_policy.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_AuthenticatedUsersRead(t *testing.T) {
	buckets := loadExposureFixture(t, "authenticated_users_read.json")
	expected := loadExpectedFindings(t, "authenticated_users_read.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_ACLPublicRead(t *testing.T) {
	buckets := loadExposureFixture(t, "public_acl_read.json")
	expected := loadExpectedFindings(t, "public_acl_read.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_WebsitePublic(t *testing.T) {
	buckets := loadExposureFixture(t, "website_public.json")
	expected := loadExpectedFindings(t, "website_public.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_BucketTakeover(t *testing.T) {
	buckets := loadExposureFixture(t, "takeover_missing_bucket.json")
	expected := loadExpectedFindings(t, "takeover_missing_bucket.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_PublicACLReadPolicy(t *testing.T) {
	buckets := loadExposureFixture(t, "public_acl_read_policy.json")
	expected := loadExpectedFindings(t, "public_acl_read_policy.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_PublicACLWritePolicy(t *testing.T) {
	buckets := loadExposureFixture(t, "public_acl_write_policy.json")
	expected := loadExpectedFindings(t, "public_acl_write_policy.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_PublicDeletePolicy(t *testing.T) {
	buckets := loadExposureFixture(t, "public_delete_policy.json")
	expected := loadExpectedFindings(t, "public_delete_policy.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_PublicFullWritePolicy(t *testing.T) {
	buckets := loadExposureFixture(t, "public_full_write_policy.json")
	expected := loadExpectedFindings(t, "public_full_write_policy.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_AllCases(t *testing.T) {
	buckets := loadExposureFixture(t, "all_cases.json")
	expected := loadExpectedFindings(t, "all_cases.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

func TestClassifyExposure_OverlapCases(t *testing.T) {
	buckets := loadExposureFixture(t, "overlap_cases.json")
	expected := loadExpectedFindings(t, "overlap_cases.findings.json")
	actual := ClassifyS3Exposure(buckets)
	compareFindings(t, actual, expected)
}

// Golden comparison test: byte-for-byte JSON output comparison
func TestClassifyExposure_Golden(t *testing.T) {
	fixtures := []string{
		"public_read_policy",
		"public_list_acl",
		"public_write_policy",
		"public_full_write_policy",
		"public_acl_read_policy",
		"public_acl_write_policy",
		"public_delete_policy",
		"authenticated_users_read",
		"public_acl_read",
		"website_public",
		"takeover_missing_bucket",
		"overlap_cases",
		"all_cases",
	}

	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			buckets := loadExposureFixture(t, name+".json")
			expected := loadExpectedFindings(t, name+".findings.json")
			actual := ClassifyS3Exposure(buckets)

			actualJSON, _ := json.MarshalIndent(exposure.Classifications{Classifications: actual}, "", "  ")
			expectedJSON, _ := json.MarshalIndent(exposure.Classifications{Classifications: expected}, "", "  ")

			if string(actualJSON) != string(expectedJSON) {
				t.Errorf("golden mismatch for %s\nexpected:\n%s\n\nactual:\n%s", name, expectedJSON, actualJSON)
			}
		})
	}
}
