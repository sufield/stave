package transform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Proves runJQ reshapes a REAL committed lab snapshot into the exact obs.v0.1
// asset the lab ships. The fixture is the nccgroup IAM password policy — a clean
// single-file reshape, copied into testdata/ because the stave module syncs to
// the public sufield/stave repo without the repo-root ctf/ lab tree.
//
// The account ID is injected as a jq arg (it is not present in the raw
// get-account-password-policy output) — the same parameter aws-snapshot.sh
// supplies at capture time. This is the Iteration 1 filter pattern, validated
// here against working data.
func TestRunJQ_NccgroupPasswordPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "iam_password_policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input any
	if err = json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}

	// Extracted mapping (Iter 1 moves this into filters/iam-password-policy.jq).
	// $account is the only external input; everything else reshapes raw fields,
	// defaulting absent fields to 0 (AWS omits PasswordReusePrevention/MaxPasswordAge
	// when password reuse/expiry is unset).
	filter := `.PasswordPolicy | {
		id: ("arn:aws:iam::" + $account + ":password-policy"),
		type: "aws_iam_password_policy",
		vendor: "aws",
		properties: { identity: {
			kind: "password_policy",
			password_policy: {
				minimum_length: .MinimumPasswordLength,
				require_uppercase: .RequireUppercaseCharacters,
				require_lowercase: .RequireLowercaseCharacters,
				require_numbers: .RequireNumbers,
				require_symbols: .RequireSymbols,
				reuse_prevention_count: (.PasswordReusePrevention // 0),
				max_password_age: (.MaxPasswordAge // 0)
			}
		} }
	}`

	out, err := runJQWithArgs(filter, input, map[string]any{"account": "442426852386"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 asset, got %d", len(out))
	}

	want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "iam_password_policy.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, out[0], want) {
		t.Errorf("asset mismatch:\n got: %s\nwant: %s", out[0], want)
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
