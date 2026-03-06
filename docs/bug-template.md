```bash
#!/usr/bin/env bash
set -euo pipefail

# -----------------------------------------------------------------------------
# Stave Bug Reproduction Template (self-contained)
#
# Goal:
# - Produce a minimal, deterministic repro any contributor can run.
# - Share only sanitized inputs. No AWS creds. No raw AWS snapshots.
#
# Requirements:
# - Go 1.21+ (for stdlib only)
# - A local Stave binary (no network needed)
#
# Usage:
#   STAVE_BIN=/path/to/stave ./repro.sh
# -----------------------------------------------------------------------------

# 1) Point to your Stave binary (prefer a local build or a verified release)
STAVE_BIN="${STAVE_BIN:-stave}"

# 2) Fixed timestamp for deterministic output (must NOT use wall clock)
NOW="${NOW:-2026-02-18T00:00:00Z}"

# 3) Expected behavior (edit these for your bug)
EXPECTED_EXIT="${EXPECTED_EXIT:-3}"                # 0=no violations, 3=violations, 2=input error
EXPECTED_CONTROL_ID="${EXPECTED_CONTROL_ID:-CTL.S3.PUBLIC.001}"
EXPECTED_RESOURCE_ID="${EXPECTED_RESOURCE_ID:-res:aws:s3:bucket:SANITIZED_01}"

# 4) Create an isolated temp workspace
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

cd "$WORKDIR"

# -----------------------------------------------------------------------------
# A) Minimal sanitized input
# -----------------------------------------------------------------------------
mkdir -p repro

# NOTE:
# - Keep only fields needed to reproduce.
# - Replace real bucket names/ARNs/account ids/tags/policies with placeholders.
# - Preserve schema + booleans used by predicates.
cat > repro/observations.sanitized.json <<'JSON'
{
  "schema_version": "obs.v0.1",
  "kind": "observations",
  "captured_at": "2026-02-18T00:00:00Z",
  "resources": [
    {
      "id": "res:aws:s3:bucket:SANITIZED_01",
      "type": "storage_bucket",
      "vendor": "aws",
      "properties": {
        "storage": {
          "visibility": {
            "public_read": true,
            "public_list": false,
            "public_write": false
          }
        }
      }
    }
  ]
}
JSON

# -----------------------------------------------------------------------------
# B) Self-contained Go test harness (stdlib only)
# - Runs Stave as an external process
# - Asserts exit code + a few key JSON fields
# -----------------------------------------------------------------------------
cat > go.mod <<'MOD'
module repro

go 1.21
MOD

cat > repro/repro_test.go <<'GO'
package repro

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type Output struct {
	Summary struct {
		Violations int `json:"violations"`
	} `json:"summary"`
	Findings []struct {
		ControlID string `json:"control_id"`
		ResourceID  string `json:"resource_id"`
	} `json:"findings"`
}

func TestRepro(t *testing.T) {
	stave := os.Getenv("STAVE_BIN")
	if stave == "" {
		stave = "stave"
	}

	now := os.Getenv("NOW")
	if now == "" {
		now = "2026-02-18T00:00:00Z"
	}

	expectedExit := mustIntEnv(t, "EXPECTED_EXIT", 3)
	expectedControl := os.Getenv("EXPECTED_CONTROL_ID")
	if expectedControl == "" {
		expectedControl = "CTL.S3.PUBLIC.001"
	}
	expectedResource := os.Getenv("EXPECTED_RESOURCE_ID")
	if expectedResource == "" {
		expectedResource = "res:aws:s3:bucket:SANITIZED_01"
	}

	input := filepath.Join("repro", "observations.sanitized.json")

	// Keep flags minimal and deterministic.
	// Add/remove flags only as needed to reproduce the bug.
	cmd := exec.Command(stave,
		"apply", "--profile", "mvp1-s3",
		"--input", input,
		"--include-all",
		"--now", now,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	gotExit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			gotExit = ee.ExitCode()
		} else {
			t.Fatalf("failed to run stave: %v\nstderr:\n%s", err, stderr.String())
		}
	}

	// 1) Assert exit code
	if gotExit != expectedExit {
		t.Fatalf(
			"unexpected exit code\nwant: %d\ngot:  %d\nstderr:\n%s\nstdout:\n%s",
			expectedExit, gotExit, stderr.String(), stdout.String(),
		)
	}

	// Some bugs are “crash” bugs; for those you may expect non-JSON output.
	// If your bug should still produce JSON, keep this enabled.
	var out Output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout was not valid JSON: %v\nstderr:\n%s\nstdout:\n%s", err, stderr.String(), stdout.String())
	}

	// 2) Assert a minimal control/resource pair appears (edit for your bug)
	if len(out.Findings) == 0 {
		t.Fatalf("expected at least 1 finding\nstderr:\n%s\nstdout:\n%s", stderr.String(), stdout.String())
	}

	found := false
	for _, f := range out.Findings {
		if strings.TrimSpace(f.ControlID) == expectedControl &&
			strings.TrimSpace(f.ResourceID) == expectedResource {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf(
			"expected finding not present\nwant control_id=%q resource_id=%q\ngot findings=%v\nstderr:\n%s\nstdout:\n%s",
			expectedControl, expectedResource, out.Findings, stderr.String(), stdout.String(),
		)
	}

	// 3) Optional: assert summary.violations is consistent
	if out.Summary.Violations < 1 && expectedExit == 3 {
		t.Fatalf("expected violations>=1 when exit code is 3; got %d", out.Summary.Violations)
	}
}

func mustIntEnv(t *testing.T, key string, def int) int {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		t.Fatalf("invalid %s=%q: %v", key, v, err)
	}
	return i
}
GO

# -----------------------------------------------------------------------------
# C) Print versions for debugging
# -----------------------------------------------------------------------------
echo "WORKDIR: $WORKDIR"
echo "STAVE_BIN: $STAVE_BIN"
echo "NOW: $NOW"
echo "Go: $(go version)"
echo "Stave: $($STAVE_BIN --version 2>/dev/null || echo '(unable to run stave --version)')"
echo

# -----------------------------------------------------------------------------
# D) Run repro
# -----------------------------------------------------------------------------
STAVE_BIN="$STAVE_BIN" \
NOW="$NOW" \
EXPECTED_EXIT="$EXPECTED_EXIT" \
EXPECTED_CONTROL_ID="$EXPECTED_CONTROL_ID" \
EXPECTED_RESOURCE_ID="$EXPECTED_RESOURCE_ID" \
go test ./repro -v
```
