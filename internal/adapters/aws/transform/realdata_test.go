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

// Computed shadow-logic signal (a NotAction over-grant) parity-tested against
// the two committed nccgroup inline-policy assets: a user inline policy
// (NotAction "s3:DeleteBucket", string form) and a group inline policy
// (NotAction ["ec2:*"], array form). The input files are self-describing.
func TestTransformFiles_NccgroupInlinePolicyShadowLogic(t *testing.T) {
	cases := []struct{ in, want string }{
		{"iam-user-inline-policy.json", "iam-user-inline-policy.expected-asset.json"},
		{"iam-group-inline-policy.json", "iam-group-inline-policy.expected-asset.json"},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", c.in))
		if err != nil {
			t.Fatal(err)
		}
		out, stats, err := TransformFiles(
			map[string][]byte{c.in: raw},
			Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
		)
		if err != nil {
			t.Fatal(err)
		}
		if stats.Assets != 1 {
			t.Fatalf("%s: want 1 asset, got %d", c.in, stats.Assets)
		}
		got := assets(t, out)[0]
		gotJSON, _ := json.Marshal(got)
		want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", c.want))
		if err != nil {
			t.Fatal(err)
		}
		if !jsonEqual(t, gotJSON, want) {
			t.Errorf("%s: asset mismatch:\n got: %s\nwant: %s", c.in, gotJSON, want)
		}
	}
}

// EBS volumes: single-call describe-volumes reshape, parity-tested against BOTH
// committed nccgroup volume assets (attached vs unattached). The region in the
// ARN is derived from the AvailabilityZone.
func TestTransformFiles_NccgroupEbsVolumes(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "ec2_volumes.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"ec2_volumes.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 2 {
		t.Fatalf("want 2 volume assets, got %d", stats.Assets)
	}

	got := map[string]json.RawMessage{}
	for _, a := range assets(t, out) {
		b, _ := json.Marshal(a)
		got[a["id"].(string)] = b
	}

	var want struct {
		Assets []map[string]any `json:"assets"`
	}
	wantRaw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "ec2_volumes.expected-assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatal(err)
	}
	for _, w := range want.Assets {
		wb, _ := json.Marshal(w)
		id := w["id"].(string)
		if !jsonEqual(t, got[id], wb) {
			t.Errorf("volume %s mismatch:\n got: %s\nwant: %s", id, got[id], wb)
		}
	}
}

// EC2 security groups: field-level parity against ALL 14 committed nccgroup SG
// assets. The obs is a manually-curated SELECTION (some all-false SGs are
// included, others excluded), so this validates the computed field LOGIC per SG
// id rather than the asset set. is_unused / has_broad_eastwest_rules are not
// emitted (documented) so they are not compared.
func TestTransformFiles_NccgroupSecurityGroups(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "ec2_security_groups.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := TransformFiles(
		map[string][]byte{"ec2_security_groups.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}

	gotSG := map[string]map[string]any{} // id -> security_group props
	for _, a := range assets(t, out) {
		sg := a["properties"].(map[string]any)["network"].(map[string]any)["security_group"].(map[string]any)
		gotSG[a["id"].(string)] = sg
	}

	wantRaw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "ec2_security_groups.expected-fields.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]map[string]bool
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatal(err)
	}

	for id, fields := range want {
		got, ok := gotSG[id]
		if !ok {
			t.Errorf("SG %s not produced by the filter", id)
			continue
		}
		for f, wantVal := range fields {
			if got[f] != wantVal {
				t.Errorf("SG %s field %s = %v, want %v", id, f, got[f], wantVal)
			}
		}
	}
}

// EC2 instances: the faithfully-derivable network signals (has_public_ip,
// imdsv2_required) parity-tested against the committed nccgroup instance.
// encryption.ebs_encrypted and user_data.has_secrets are not emitted (documented:
// not derivable from describe-instances), so they are not compared.
func TestTransformFiles_NccgroupEc2Instance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "ec2_instances.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"ec2_instances.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 instance asset, got %d", stats.Assets)
	}

	wantRaw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "ec2_instances.expected-network.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]map[string]bool
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatal(err)
	}
	for _, a := range assets(t, out) {
		net := a["properties"].(map[string]any)["compute"].(map[string]any)["network"].(map[string]any)
		for f, wantVal := range want[a["id"].(string)] {
			if net[f] != wantVal {
				t.Errorf("instance %s field %s = %v, want %v", a["id"], f, net[f], wantVal)
			}
		}
	}
}

// CloudTrail: the config signals (single-call describe-trails) parity-tested
// against the committed nccgroup trail. The expected asset is the obs trail minus
// data_events_s3 / has_s3_data_event_gap, which are not emitted (documented: need
// get-event-selectors) — so the emitted asset matches exactly.
func TestTransformFiles_NccgroupCloudTrail(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "cloudtrail_trails.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"cloudtrail_trails.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 trail asset, got %d", stats.Assets)
	}
	gotJSON, _ := json.Marshal(assets(t, out)[0])
	want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "cloudtrail_trails.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, gotJSON, want) {
		t.Errorf("trail asset mismatch:\n got: %s\nwant: %s", gotJSON, want)
	}
}

// AWS Config recorder: single-call full-asset parity against the committed
// nccgroup recorder. records_all_resources is computed (allSupported AND
// includeGlobalResourceTypes); the id is normalized to the config-recorder ARN.
func TestTransformFiles_NccgroupConfigRecorder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "config_recorders.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"config_recorders.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 recorder asset, got %d", stats.Assets)
	}
	gotJSON, _ := json.Marshal(assets(t, out)[0])
	want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "config_recorders.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, gotJSON, want) {
		t.Errorf("recorder asset mismatch:\n got: %s\nwant: %s", gotJSON, want)
	}
}

// OpenSearch domain: single detail-call full-asset parity against the committed
// nccgroup domain (empty AccessPolicies → policy_allows_wildcard true; no
// AUDIT_LOGS → audit_logs_enabled false).
func TestTransformFiles_NccgroupOpenSearch(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "es_domain_sadcloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"es_domain_sadcloud.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 domain asset, got %d", stats.Assets)
	}
	gotJSON, _ := json.Marshal(assets(t, out)[0])
	want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "es_domain_sadcloud.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, gotJSON, want) {
		t.Errorf("domain asset mismatch:\n got: %s\nwant: %s", gotJSON, want)
	}
}

// The wildcard-principal branch of opensearch-domains (not exercised by the
// committed empty-policy domain) detects a "*" principal in a non-empty policy.
func TestTransformFiles_OpenSearchWildcardPrincipal(t *testing.T) {
	raw := []byte(`{"DomainStatus":{"ARN":"arn:aws:es:us-east-1:1:domain/open",
		"AccessPolicies":"{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"}}]}"}}`)
	out, _, err := TransformFiles(map[string][]byte{"es_domain_open.json": raw},
		Options{Account: "1", CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	acc := assets(t, out)[0]["properties"].(map[string]any)["search_service"].(map[string]any)["access"].(map[string]any)
	if acc["policy_allows_wildcard"] != true {
		t.Errorf("wildcard principal not detected: %v", acc)
	}
}

// CloudWatch alarm: single-call full-asset parity against the committed nccgroup
// alarm (no actions configured -> has_any_action false).
func TestTransformFiles_NccgroupCloudWatchAlarm(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "cloudwatch_alarms.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"cloudwatch_alarms.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 alarm asset, got %d", stats.Assets)
	}
	gotJSON, _ := json.Marshal(assets(t, out)[0])
	want, err := os.ReadFile(filepath.Join("testdata", "nccgroup", "cloudwatch_alarms.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, gotJSON, want) {
		t.Errorf("alarm asset mismatch:\n got: %s\nwant: %s", gotJSON, want)
	}
}

// KMS: base (list-keys) + rotation enrichment + key-policy enrichment merge into
// the full key asset, parity-tested against the committed nccgroup KMS key. All
// inputs are real captures: list-keys + get-key-rotation-status from nccgroup,
// get-key-policy from lab1 (same key, same account). get-key-policy carries no
// key identity, so it is annotated with the KeyArn the collector supplies.
func TestTransformFiles_NccgroupKmsKey(t *testing.T) {
	const keyARN = "arn:aws:kms:us-east-1:442426852386:key/mrk-971fcb44ed554c9a9f5fc429d9d9d0d6"
	read := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", "nccgroup", n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	keys := read("kms_keys.json")
	rotation := read("kms-rotation-mrk-971.json")

	// Annotate the raw get-key-policy capture with the KeyArn (the join key the
	// collector adds), leaving the real Policy content untouched.
	var pol map[string]any
	if err := json.Unmarshal(read("kms-policy-mrk-971.json"), &pol); err != nil {
		t.Fatal(err)
	}
	pol["KeyArn"] = keyARN
	policy, _ := json.Marshal(pol)

	out, _, err := TransformFiles(map[string][]byte{
		"kms_keys.json":             keys,
		"kms-rotation-mrk-971.json": rotation,
		"kms-policy-mrk-971.json":   policy,
	}, Options{Account: "442426852386", CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	for _, a := range assets(t, out) {
		if a["id"] == keyARN {
			got = a
		}
	}
	if got == nil {
		t.Fatal("KMS key asset not produced (base+enrichment merge failed)")
	}
	gotJSON, _ := json.Marshal(got)
	want := read("kms-key.expected-asset.json")
	if !jsonEqual(t, gotJSON, want) {
		t.Errorf("kms key asset mismatch:\n got: %s\nwant: %s", gotJSON, want)
	}
}

// Lambda: single-call list-functions reshape, full-asset parity against the
// committed datadog lab2 function.
func TestTransformFiles_DatadogLambda(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "datadog", "lambda_functions.json"))
	if err != nil {
		t.Fatal(err)
	}
	out, stats, err := TransformFiles(
		map[string][]byte{"lambda_functions.json": raw},
		Options{Account: "442426852386", CapturedAt: "2026-05-30T00:00:00Z"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 function asset, got %d", stats.Assets)
	}
	gotJSON, _ := json.Marshal(assets(t, out)[0])
	want, err := os.ReadFile(filepath.Join("testdata", "datadog", "lambda.expected-asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, gotJSON, want) {
		t.Errorf("lambda asset mismatch:\n got: %s\nwant: %s", gotJSON, want)
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
