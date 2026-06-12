package nepcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestSnapshot writes a snapshot bundle JSON file and returns the path.
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

func TestResolveResourceAccess_PublicAccessDetected(t *testing.T) {
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

	out, _, hasFindings, err := ResolveResourceAccess(ResourceConfig{
		Snapshot:    path,
		ResourceARN: "arn:aws:s3:::phi-bucket",
		Format:      "json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasFindings {
		t.Fatal("expected hasFindings=true for non-designated public access")
	}
	if !strings.Contains(string(out), `"is_public": true`) {
		t.Error("expected public access flagged in output")
	}
}

func TestResolveResourceAccess_DesignatedOnlyNoFindings(t *testing.T) {
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

	_, _, hasFindings, err := ResolveResourceAccess(ResourceConfig{
		Snapshot:    path,
		ResourceARN: "arn:aws:s3:::phi-bucket",
		Format:      "json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasFindings {
		t.Fatal("expected hasFindings=false for designated-only access")
	}
}

func TestResolveResourceAccess_EmptyAccess(t *testing.T) {
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

	out, _, hasFindings, err := ResolveResourceAccess(ResourceConfig{
		Snapshot:    path,
		ResourceARN: "arn:aws:s3:::phi-bucket",
		Format:      "table",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hasFindings {
		t.Fatal("expected hasFindings=false for empty access")
	}
	if !strings.Contains(string(out), "No principals with effective access") {
		t.Error("expected empty access message")
	}
}

func TestResolveResourceAccess_CrossAccountFlagged(t *testing.T) {
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

	out, _, _, err := ResolveResourceAccess(ResourceConfig{
		Snapshot:    path,
		ResourceARN: "arn:aws:kms:us-east-1:123456789012:key/abc-123",
		Format:      "json",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), `"is_cross_account": true`) {
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

func TestResolveResourceAccess_DefaultExcludesDesignated(t *testing.T) {
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets": []any{
			map[string]any{
				"id": "arn:aws:s3:::phi-bucket", "type": "storage_bucket", "vendor": "aws",
				"properties": map[string]any{
					"storage": map[string]any{
						"policy_json": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:iam::123456789012:role/phi-proc","arn:aws:iam::123456789012:role/rogue"]}]}`,
					},
				},
			},
		},
		"identities": []any{
			map[string]any{
				"id": "arn:aws:iam::123456789012:role/phi-proc", "type": "iam_role", "vendor": "aws",
				"properties": map[string]any{"identity": map[string]any{"tags": map[string]any{"stave/role-type": "phi-processor"}}},
			},
			map[string]any{
				"id": "arn:aws:iam::123456789012:role/rogue", "type": "iam_role", "vendor": "aws",
				"properties": map[string]any{"identity": map[string]any{"tags": map[string]any{}}},
			},
		},
	}
	path := writeTestSnapshot(t, snap)

	out, _, _, err := ResolveResourceAccess(ResourceConfig{
		Snapshot: path, ResourceARN: "arn:aws:s3:::phi-bucket",
		Format: "json", Classification: "phi", ShowDesignated: false,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(string(out), "phi-proc") {
		t.Error("designated principal phi-proc should be excluded in default mode")
	}
	if !strings.Contains(string(out), "rogue") {
		t.Error("non-designated principal rogue should be shown")
	}
}

func TestResolveResourceAccess_AllIncludesDesignated(t *testing.T) {
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"source":         "deployed",
		"captured_at":    "2026-01-15T00:00:00Z",
		"assets": []any{
			map[string]any{
				"id": "arn:aws:s3:::phi-bucket", "type": "storage_bucket", "vendor": "aws",
				"properties": map[string]any{
					"storage": map[string]any{
						"policy_json": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:iam::123456789012:role/phi-proc"]}]}`,
					},
				},
			},
		},
		"identities": []any{
			map[string]any{
				"id": "arn:aws:iam::123456789012:role/phi-proc", "type": "iam_role", "vendor": "aws",
				"properties": map[string]any{"identity": map[string]any{"tags": map[string]any{"stave/role-type": "phi-processor"}}},
			},
		},
	}
	path := writeTestSnapshot(t, snap)

	out, _, _, err := ResolveResourceAccess(ResourceConfig{
		Snapshot: path, ResourceARN: "arn:aws:s3:::phi-bucket",
		Format: "json", Classification: "phi", ShowDesignated: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "phi-proc") {
		t.Error("--all should show designated principal phi-proc")
	}
}

func TestDotQuote(t *testing.T) {
	tests := []struct{ input, want string }{
		{"hello", `"hello"`},
		{`say "hi"`, `"say \"hi\""`},
	}
	for _, tt := range tests {
		if got := dotQuote(tt.input); got != tt.want {
			t.Errorf("dotQuote(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
