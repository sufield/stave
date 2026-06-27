package transform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Drives the whole pipeline (detect → embedded filter → scrub → envelope →
// obs.v0.1 validation) against a REAL committed lab snapshot, and checks the
// produced asset matches the one the lab ships. The fixture is the nccgroup IAM
// password policy — a clean single-file reshape — copied into testdata/ because
// the stave module syncs to the public sufield/stave repo without the repo-root
// ctf/ lab tree. The account ID is supplied via Options (the raw
// get-account-password-policy output carries no ARN).
func TestTransformFiles_NccgroupPasswordPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "iam_password_policy.json"))
	if err != nil {
		t.Fatal(err)
	}

	out, stats, err := TransformFiles(
		map[string][]byte{"iam_password_policy.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 || stats.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	var doc struct {
		Assets []json.RawMessage `json:"assets"`
	}
	if err = json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Assets) != 1 {
		t.Fatalf("want 1 asset, got %d", len(doc.Assets))
	}

	want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "iam_password_policy.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, doc.Assets[0], want) {
		t.Errorf("asset mismatch:\n got: %s\nwant: %s", doc.Assets[0], want)
	}
}

// jsonEqual compares two JSON documents structurally (key order / whitespace
// independent).
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xb) == string(yb)
}
