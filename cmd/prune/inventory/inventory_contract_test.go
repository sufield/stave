package inventory_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestInventoryJSONContract verifies the per-file shape declared in
// docs/contracts/snapshot-inventory.schema.json. Same rationale as
// the plan contract test: catch contract drift at CI time before
// external integrators do.
func TestInventoryJSONContract(t *testing.T) {
	bin := buildStaveBinary(t)
	repoRoot := repoRootFor(t)
	fixtureObs := filepath.Join(repoRoot, "testdata", "e2e", "e2e-01-violation", "observations")

	cmd := exec.Command(bin,
		"snapshot", "inventory",
		"--observations-dir", fixtureObs,
		"--format", "json",
	)
	cmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("snapshot inventory failed: %v\nstderr: %s", err, stderr.String())
	}

	var envelope struct {
		Snapshots []map[string]any `json:"snapshots"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("parse inventory JSON: %v\noutput: %s", err, stdout.String())
	}
	if len(envelope.Snapshots) == 0 {
		t.Fatal("expected at least one snapshot in inventory")
	}

	allowedActions := map[string]bool{"keep": true, "delete": true, "archive": true, "review": true}
	allowedAssessment := map[string]bool{"evaluated": true, "pending": true, "unknown": true}
	required := []string{
		"file_path", "asset_id", "asset_type",
		"captured_at", "age", "age_seconds", "tier",
		"file_size_bytes", "schema_valid", "assessment_status",
		"quality_warnings", "action", "reason",
	}

	for i, entry := range envelope.Snapshots {
		for _, key := range required {
			if _, ok := entry[key]; !ok {
				t.Errorf("entry %d missing required field %q", i, key)
			}
		}
		if action, _ := entry["action"].(string); !allowedActions[action] {
			t.Errorf("entry %d action=%q not in {keep,delete,archive,review}", i, action)
		}
		if status, _ := entry["assessment_status"].(string); !allowedAssessment[status] {
			t.Errorf("entry %d assessment_status=%q not in {evaluated,pending,unknown}", i, status)
		}
		if captured, _ := entry["captured_at"].(string); captured != "" {
			if _, err := time.Parse(time.RFC3339, captured); err != nil {
				t.Errorf("entry %d captured_at=%q does not parse as RFC3339: %v", i, captured, err)
			}
		}
		if ageSeconds, ok := entry["age_seconds"].(float64); !ok {
			t.Errorf("entry %d age_seconds is not numeric (type %T)", i, entry["age_seconds"])
		} else if ageSeconds < 0 {
			t.Errorf("entry %d age_seconds=%v negative", i, ageSeconds)
		}
		if size, ok := entry["file_size_bytes"].(float64); !ok {
			t.Errorf("entry %d file_size_bytes is not numeric (type %T)", i, entry["file_size_bytes"])
		} else if size < 0 {
			t.Errorf("entry %d file_size_bytes=%v negative", i, size)
		}
		// quality_warnings must be an array, never null. JSON
		// unmarshals it to []any when present and non-empty, or to
		// nil when emitted as `null`. Empty arrays stay []any{}.
		if warnings, present := entry["quality_warnings"]; !present {
			t.Errorf("entry %d missing quality_warnings", i)
		} else if _, isArray := warnings.([]any); !isArray {
			t.Errorf("entry %d quality_warnings is not an array (type %T)", i, warnings)
		}
	}
}

func buildStaveBinary(t *testing.T) string {
	t.Helper()
	repoRoot := repoRootFor(t)
	bin := filepath.Join(t.TempDir(), "stave")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/stave")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build stave: %v\n%s", err, out)
	}
	return bin
}

func repoRootFor(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := string(bytes.TrimSpace(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Fatal("not inside a Go module")
	}
	return filepath.Dir(gomod)
}
