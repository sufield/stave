package snapshot_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestPlanJSONContract verifies that `stave snapshot plan --format json`
// emits each per-file entry with the field set declared in
// docs/contracts/snapshot-plan.schema.json. CI catches a contract
// breakage here before external tools (cron scripts, Terraform
// null_resource, CI cleanup jobs) discover it at parse time.
//
// The test shells out to the compiled stave binary — running the
// command through cobra gives us the same JSON path operators see in
// production, including any rendering hooks that don't fire from the
// in-process app/prune/snapshot.PlanRunner directly.
func TestPlanJSONContract(t *testing.T) {
	bin := buildStaveBinary(t)
	repoRoot := repoRootFor(t)
	fixtureObs := filepath.Join(repoRoot, "testdata", "e2e", "e2e-01-violation", "observations")

	cmd := exec.Command(bin,
		"snapshot", "plan",
		"--observations-root", fixtureObs,
		"--format", "json",
		"--now", "2026-02-01T00:00:00Z",
	)
	cmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("snapshot plan failed: %v\nstderr: %s", err, stderr.String())
	}

	var envelope struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("parse plan JSON: %v\noutput: %s", err, stdout.String())
	}
	if len(envelope.Files) == 0 {
		t.Fatal("expected at least one file in plan")
	}

	allowedActions := map[string]bool{"keep": true, "delete": true, "archive": true, "review": true}
	required := []string{
		"file_path", "rel_path", "asset_id", "asset_type",
		"captured_at", "age", "age_seconds", "tier", "action", "reason",
	}

	for i, entry := range envelope.Files {
		for _, key := range required {
			if _, ok := entry[key]; !ok {
				t.Errorf("entry %d missing required field %q", i, key)
			}
		}
		if action, _ := entry["action"].(string); !allowedActions[action] {
			t.Errorf("entry %d action=%q not in {keep,delete,archive,review}", i, action)
		}
		if captured, _ := entry["captured_at"].(string); captured != "" {
			if _, err := time.Parse(time.RFC3339, captured); err != nil {
				t.Errorf("entry %d captured_at=%q does not parse as RFC3339: %v", i, captured, err)
			}
		}
		// Numeric fields decode as float64 from encoding/json's
		// any-typed unmarshal. Verify age_seconds is a non-negative
		// integer-valued float.
		if ageSeconds, ok := entry["age_seconds"].(float64); !ok {
			t.Errorf("entry %d age_seconds is not numeric (type %T)", i, entry["age_seconds"])
		} else if ageSeconds < 0 {
			t.Errorf("entry %d age_seconds=%v negative", i, ageSeconds)
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
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git rev-parse: %v", err)
	}
	root := string(bytes.TrimSpace(out))
	// Inside the bizacademy monorepo, the CI runs from the stave/
	// subdirectory. git rev-parse may surface the parent repo, so
	// fall back to scanning upward for a go.mod.
	if _, err := exec.LookPath("go"); err != nil {
		return root
	}
	if _, err := exec.Command("go", "list", "-m").Output(); err == nil {
		modRoot, err := exec.Command("go", "env", "GOMOD").Output()
		if err == nil {
			gomod := string(bytes.TrimSpace(modRoot))
			if gomod != "" && gomod != "/dev/null" {
				return filepath.Dir(gomod)
			}
		}
	}
	return root
}
