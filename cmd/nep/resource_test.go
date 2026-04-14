package nep

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/cli/ui"
)

// writeTestSnapshot writes a snapshot bundle JSON file and returns the path.
// The snapshot is wrapped in a bundle with schema_version and snapshots array.
func writeTestSnapshot(t *testing.T, snapshot map[string]any) string {
	t.Helper()
	bundle := map[string]any{
		"schema_version": "obs.v0.1",
		"snapshots":      []any{snapshot},
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	return path
}

func TestRunResource_PublicAccessDetected(t *testing.T) {
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets": []any{
			map[string]any{
				"id":     "arn:aws:s3:::phi-bucket",
				"type":   "storage_bucket",
				"vendor": "aws",
				"properties": map[string]any{
					"storage": map[string]any{
						"policy_json": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["*"]}]}`,
					},
				},
			},
		},
	}
	path := writeTestSnapshot(t, snap)

	var buf bytes.Buffer
	opts := &resourceOpts{
		Snapshot:    path,
		ResourceARN: "arn:aws:s3:::phi-bucket",
		Format:      "json",
	}
	err := runResource(&buf, opts)

	// Should return exit-1 error (non-designated public access)
	if !errors.Is(err, ui.ErrSecurityAuditFindings) {
		t.Fatalf("expected ErrSecurityAuditFindings, got: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"is_public": true`) {
		t.Error("expected public access flagged in output")
	}
}

func TestRunResource_DesignatedOnlyNoError(t *testing.T) {
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets": []any{
			map[string]any{
				"id":     "arn:aws:s3:::phi-bucket",
				"type":   "storage_bucket",
				"vendor": "aws",
				"properties": map[string]any{
					"storage": map[string]any{
						"policy_json": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:iam::123456789012:role/phi-processor"]}]}`,
					},
				},
			},
		},
		"identities": []any{
			map[string]any{
				"id":     "arn:aws:iam::123456789012:role/phi-processor",
				"type":   "iam_role",
				"vendor": "aws",
				"properties": map[string]any{
					"identity": map[string]any{
						"tags": map[string]any{
							"stave/role-type": "phi-processor",
						},
					},
				},
			},
		},
	}
	path := writeTestSnapshot(t, snap)

	var buf bytes.Buffer
	opts := &resourceOpts{
		Snapshot:    path,
		ResourceARN: "arn:aws:s3:::phi-bucket",
		Format:      "json",
	}
	err := runResource(&buf, opts)

	if err != nil {
		t.Fatalf("expected no error for designated-only access, got: %v", err)
	}
}

func TestRunResource_EmptyAccess(t *testing.T) {
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets": []any{
			map[string]any{
				"id":         "arn:aws:s3:::other-bucket",
				"type":       "storage_bucket",
				"vendor":     "aws",
				"properties": map[string]any{},
			},
		},
	}
	path := writeTestSnapshot(t, snap)

	var buf bytes.Buffer
	opts := &resourceOpts{
		Snapshot:    path,
		ResourceARN: "arn:aws:s3:::phi-bucket",
		Format:      "table",
	}
	err := runResource(&buf, opts)

	if err != nil {
		t.Fatalf("expected no error for empty access, got: %v", err)
	}
	if !strings.Contains(buf.String(), "No principals with effective access") {
		t.Error("expected empty access message")
	}
}

func TestRunResource_CrossAccountFlagged(t *testing.T) {
	// Use a KMS key ARN which includes account ID for cross-account detection.
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets": []any{
			map[string]any{
				"id":     "arn:aws:kms:us-east-1:123456789012:key/abc-123",
				"type":   "kms_key",
				"vendor": "aws",
				"properties": map[string]any{
					"encryption": map[string]any{
						"key_policy_json": `{"Statement":[{"Effect":"Allow","Action":["kms:Decrypt"],"Resource":["arn:aws:iam::999999999999:role/external"]}]}`,
					},
				},
			},
		},
	}
	path := writeTestSnapshot(t, snap)

	var buf bytes.Buffer
	opts := &resourceOpts{
		Snapshot:    path,
		ResourceARN: "arn:aws:kms:us-east-1:123456789012:key/abc-123",
		Format:      "json",
	}
	_ = runResource(&buf, opts)

	out := buf.String()
	if !strings.Contains(out, `"is_cross_account": true`) {
		t.Error("expected cross-account flagged in output")
	}
}

func TestExtractAccountID(t *testing.T) {
	tests := []struct {
		arn, want string
	}{
		{"arn:aws:s3:::my-bucket", ""},
		{"arn:aws:iam::123456789012:role/app", "123456789012"},
		{"not-an-arn", ""},
	}
	for _, tt := range tests {
		if got := extractAccountID(tt.arn); got != tt.want {
			t.Errorf("extractAccountID(%q) = %q, want %q", tt.arn, got, tt.want)
		}
	}
}

func TestExtractService(t *testing.T) {
	tests := []struct {
		arn, want string
	}{
		{"arn:aws:s3:::my-bucket", "s3"},
		{"arn:aws:lambda:us-east-1:123:function:f", "lambda"},
		{"not-an-arn", ""},
	}
	for _, tt := range tests {
		if got := extractService(tt.arn); got != tt.want {
			t.Errorf("extractService(%q) = %q, want %q", tt.arn, got, tt.want)
		}
	}
}
