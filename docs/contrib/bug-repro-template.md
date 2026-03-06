---
title: "Bug Reproduction Template"
sidebar_label: "Bug Repro Template"
sidebar_position: 2
description: "Copy-paste template for creating a minimal Stave bug reproduction."
---

# Bug Reproduction Template

Copy this template to create a self-contained bug reproduction. It creates a temporary workspace, runs Stave with minimal inputs, and asserts the expected outcome.

## Shell Script Version

Save as `repro.sh` and run with `STAVE_BIN=/path/to/stave ./repro.sh`:

```bash
#!/usr/bin/env bash
set -uo pipefail

# ── Configuration ──────────────────────────────────────────────────
STAVE_BIN="${STAVE_BIN:-stave}"
NOW="${NOW:-2026-02-18T00:00:00Z}"
EXPECTED_EXIT="${EXPECTED_EXIT:-3}"

# ── Temp workspace ─────────────────────────────────────────────────
WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
cd "$WORKDIR"

# ── Versions ───────────────────────────────────────────────────────
echo "Stave: $($STAVE_BIN --version 2>/dev/null || echo '(unknown)')"
echo "NOW: $NOW"
echo "Expected exit: $EXPECTED_EXIT"
echo

# ── Minimal observation (edit for your bug) ────────────────────────
mkdir -p obs
cat > obs/2026-02-17T00:00:00Z.json <<'JSON'
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-02-17T00:00:00Z",
  "resources": [{
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
  }]
}
JSON

cat > obs/2026-02-18T00:00:00Z.json <<'JSON'
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-02-18T00:00:00Z",
  "resources": [{
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
  }]
}
JSON

# ── Run Stave ──────────────────────────────────────────────────────
rc=0
$STAVE_BIN apply \
  --controls controls/s3 \
  --observations obs/ \
  --now "$NOW" \
  --allow-unknown-input 2>stderr.log || rc=$?

echo "Actual exit: $rc"

# ── Assert ─────────────────────────────────────────────────────────
if [ "$rc" -ne "$EXPECTED_EXIT" ]; then
  echo "FAIL: expected exit $EXPECTED_EXIT, got $rc"
  echo "stderr:"
  cat stderr.log
  exit 1
fi

echo "PASS"
```

## Go Test Version

For more precise assertions, use a Go test that invokes Stave as an external process:

```bash
#!/usr/bin/env bash
set -euo pipefail

STAVE_BIN="${STAVE_BIN:-stave}"
NOW="${NOW:-2026-02-18T00:00:00Z}"
EXPECTED_EXIT="${EXPECTED_EXIT:-3}"
EXPECTED_CONTROL_ID="${EXPECTED_CONTROL_ID:-CTL.S3.PUBLIC.001}"
EXPECTED_RESOURCE_ID="${EXPECTED_RESOURCE_ID:-res:aws:s3:bucket:SANITIZED_01}"

WORKDIR="$(mktemp -d)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
cd "$WORKDIR"

# Print versions
echo "STAVE_BIN: $STAVE_BIN"
echo "Go: $(go version)"
echo "Stave: $($STAVE_BIN --version 2>/dev/null || echo '(unknown)')"
echo

# Create observation
mkdir -p repro
cat > repro/observations.sanitized.json <<'JSON'
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-02-18T00:00:00Z",
  "resources": [{
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
  }]
}
JSON

# Create Go test
cat > go.mod <<'MOD'
module repro

go 1.21
MOD

cat > repro/repro_test.go <<'GO'
package repro

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
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
	stave := envOr("STAVE_BIN", "stave")
	now := envOr("NOW", "2026-02-18T00:00:00Z")
	expectedExit := mustIntEnv(t, "EXPECTED_EXIT", 3)
	expectedControl := envOr("EXPECTED_CONTROL_ID", "CTL.S3.PUBLIC.001")
	expectedResource := envOr("EXPECTED_RESOURCE_ID", "res:aws:s3:bucket:SANITIZED_01")

	cmd := exec.Command(stave,
		"apply", "--profile", "mvp1-s3",
		"--input", "repro/observations.sanitized.json",
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

	if gotExit != expectedExit {
		t.Fatalf("exit code: want %d, got %d\nstderr:\n%s\nstdout:\n%s",
			expectedExit, gotExit, stderr.String(), stdout.String())
	}

	var out Output
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v\nstdout:\n%s", err, stdout.String())
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
		t.Fatalf("expected finding not present\nwant: %s / %s\ngot: %v",
			expectedControl, expectedResource, out.Findings)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

# Run the test
STAVE_BIN="$STAVE_BIN" NOW="$NOW" \
  EXPECTED_EXIT="$EXPECTED_EXIT" \
  EXPECTED_CONTROL_ID="$EXPECTED_CONTROL_ID" \
  EXPECTED_RESOURCE_ID="$EXPECTED_RESOURCE_ID" \
  go test ./repro -v
```

## Adapting the Template

1. **Edit the observation JSON** — keep only fields needed to reproduce your bug.
2. **Edit the assertions** — change `EXPECTED_EXIT`, `EXPECTED_CONTROL_ID`, `EXPECTED_RESOURCE_ID`.
3. **Add a second snapshot** if your bug involves duration or recurrence.
4. **Change the command** if using `apply` (generic) instead of `apply --profile mvp1-s3` (S3 healthcare profile).
