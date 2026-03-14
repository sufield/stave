package ingest

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/domain/asset"
)

func TestIngestProfilesRegistryNotEmpty(t *testing.T) {
	if len(AllProfiles()) == 0 {
		t.Fatal("expected at least one ingest profile")
	}
}

func TestIngestProfilesRegistryHasAWSS3(t *testing.T) {
	found := false
	for _, p := range AllProfiles() {
		if p.Name == ProfileAWSS3 {
			found = true
			if len(p.Inputs) == 0 {
				t.Error("aws-s3 profile has no inputs")
			}
			// Verify list-buckets.json is required
			for _, inp := range p.Inputs {
				if inp.Path == "list-buckets.json" && !inp.Required {
					t.Error("list-buckets.json should be required")
				}
			}
		}
	}
	if !found {
		t.Fatal("aws-s3 profile not found in registry")
	}
}

func TestRenderTextProfiles(t *testing.T) {
	var buf bytes.Buffer
	presenter := &RegistryPresenter{Stdout: &buf}
	if err := presenter.RenderText(); err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"aws-s3",
		"list-buckets.json",
		"(required)",
		"(optional)",
		"get-bucket-tagging/<bucket>.json",
		"get-bucket-policy/<bucket>.json",
		"get-bucket-acl/<bucket>.json",
		"get-public-access-block/<bucket>.json",
		"Expected inputs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderText output missing %q", want)
		}
	}
}

func TestPrintIngestCoverageAllFound(t *testing.T) {
	resources := []asset.Asset{
		{
			ID:   "my-bucket",
			Type: "s3.bucket",
			Properties: map[string]any{
				"evidence": []string{
					"tags from get-bucket-tagging/my-bucket.json",
					"policy from get-bucket-policy/my-bucket.json",
					"acl from get-bucket-acl/my-bucket.json",
					"public-access-block from get-public-access-block/my-bucket.json",
				},
			},
		},
	}

	var buf bytes.Buffer
	printIngestCoverage(&buf, resources)
	out := buf.String()

	if !strings.Contains(out, "Input coverage:") {
		t.Error("expected 'Input coverage:' header")
	}
	if !strings.Contains(out, "my-bucket") {
		t.Error("expected bucket name in output")
	}
	if !strings.Contains(out, "4/4") {
		t.Errorf("expected 4/4 coverage, got: %s", out)
	}
	if strings.Contains(out, "missing") {
		t.Error("expected no missing inputs")
	}
}

func TestPrintIngestCoverageWithMissing(t *testing.T) {
	resources := []asset.Asset{
		{
			ID:   "acme-logs",
			Type: "s3.bucket",
			Properties: map[string]any{
				"evidence": []string{
					"tags from get-bucket-tagging/acme-logs.json",
					"acl from get-bucket-acl/acme-logs.json",
					"public-access-block from get-public-access-block/acme-logs.json",
				},
				"missing_inputs": []string{
					"get-bucket-policy/acme-logs.json",
				},
			},
		},
	}

	var buf bytes.Buffer
	printIngestCoverage(&buf, resources)
	out := buf.String()

	if !strings.Contains(out, "3/4") {
		t.Errorf("expected 3/4 coverage, got: %s", out)
	}
	if !strings.Contains(out, "(missing: policy)") {
		t.Errorf("expected '(missing: policy)', got: %s", out)
	}
}

func TestPrintIngestCoverageEmpty(t *testing.T) {
	var buf bytes.Buffer
	printIngestCoverage(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("expected no output for nil resources, got: %s", buf.String())
	}
}

func TestEvidenceShortLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"tags from get-bucket-tagging/foo.json", "tags"},
		{"policy from get-bucket-policy/foo.json", "policy"},
		{"acl from get-bucket-acl/foo.json", "acl"},
		{"public-access-block from get-public-access-block/foo.json", "public-access-block"},
		{"get-bucket-policy/foo.json", "policy"},
		{"get-bucket-tagging/foo.json", "tagging"},
		{"get-bucket-acl/foo.json", "acl"},
	}

	for _, tt := range tests {
		got := evidenceShortLabel(tt.input)
		if got != tt.want {
			t.Errorf("evidenceShortLabel(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
