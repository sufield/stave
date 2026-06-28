package transform

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDetectFilter(t *testing.T) {
	cases := []struct {
		doc      string
		want     string
		wantOK   bool
		descName string
	}{
		{`{"PasswordPolicy":{}}`, "iam-password-policy", true, "password policy"},
		{`{"Roles":[]}`, "iam-roles", true, "roles"},
		{`{"Buckets":[]}`, "s3-buckets", true, "buckets"},
		{`{"Bucket":"b","PublicAccessBlockConfiguration":{}}`, "s3-public-access-block", true, "annotated PAB"},
		{`{"PublicAccessBlockConfiguration":{}}`, "", false, "un-annotated PAB -> skip"},
		{`{"Widgets":[]}`, "", false, "unrecognized -> skip"},
	}
	for _, c := range cases {
		var m map[string]any
		if err := json.Unmarshal([]byte(c.doc), &m); err != nil {
			t.Fatal(err)
		}
		got, ok := detectFilter(m)
		if got != c.want || ok != c.wantOK {
			t.Errorf("%s: detectFilter=%q,%v want %q,%v", c.descName, got, ok, c.want, c.wantOK)
		}
	}
}

// iam-roles filter: trusted_services extracted from AssumeRolePolicyDocument
// (string and array Principal.Service shapes), AWSServiceRole* excluded.
func TestTransformFiles_Roles(t *testing.T) {
	raw := []byte(`{"Roles":[
		{"RoleName":"app","Arn":"arn:aws:iam::1:role/app",
		 "AssumeRolePolicyDocument":{"Statement":[{"Principal":{"Service":"lambda.amazonaws.com"}}]}},
		{"RoleName":"multi","Arn":"arn:aws:iam::1:role/multi",
		 "AssumeRolePolicyDocument":{"Statement":[{"Principal":{"Service":["ec2.amazonaws.com","ecs.amazonaws.com"]}}]}},
		{"RoleName":"AWSServiceRoleForX","Arn":"arn:aws:iam::1:role/AWSServiceRoleForX",
		 "AssumeRolePolicyDocument":{"Statement":[]}}
	]}`)

	out, stats, err := TransformFiles(map[string][]byte{"iam_roles.json": raw},
		Options{Account: "1", CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	// AWSServiceRole* excluded -> 2 assets.
	if stats.Assets != 2 {
		t.Fatalf("want 2 role assets, got %d", stats.Assets)
	}

	var doc struct {
		Assets []map[string]any `json:"assets"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]any{}
	for _, a := range doc.Assets {
		id, _ := a["id"].(string)
		props := a["properties"].(map[string]any)["identity"].(map[string]any)
		trusted[id] = props["trusted_services"]
	}
	if got := trusted["arn:aws:iam::1:role/app"]; !equalStrSlice(got, []string{"lambda.amazonaws.com"}) {
		t.Errorf("app trusted_services = %v", got)
	}
	if got := trusted["arn:aws:iam::1:role/multi"]; !equalStrSlice(got, []string{"ec2.amazonaws.com", "ecs.amazonaws.com"}) {
		t.Errorf("multi trusted_services = %v", got)
	}
}

// Unrecognized files are skipped, not fatal; an all-skipped run still yields a
// valid (empty-assets) observation.
func TestTransformFiles_SkipsUnknown(t *testing.T) {
	out, stats, err := TransformFiles(map[string][]byte{
		"unknown.json": []byte(`{"Widgets":[{"id":1}]}`),
	}, Options{CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 1 || stats.Skipped != 1 || stats.Assets != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if !strings.Contains(string(out), `"schema_version": "obs.v0.1"`) {
		t.Errorf("expected a valid empty observation, got: %s", out)
	}
}

func equalStrSlice(got any, want []string) bool {
	arr, ok := got.([]any)
	if !ok || len(arr) != len(want) {
		return false
	}
	for i, w := range want {
		if s, _ := arr[i].(string); s != w {
			return false
		}
	}
	return true
}

// mergeByID deep-merges fragments sharing an id; nested objects merge, scalars
// overwrite, first-seen order is preserved.
func TestMergeByID(t *testing.T) {
	in := []json.RawMessage{
		json.RawMessage(`{"id":"a","type":"t","properties":{"x":{"p":1}}}`),
		json.RawMessage(`{"id":"b","type":"t","properties":{"y":2}}`),
		json.RawMessage(`{"id":"a","properties":{"x":{"q":2},"z":3}}`),
	}
	out, err := mergeByID(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 merged assets, got %d", len(out))
	}
	var a map[string]any
	if err := json.Unmarshal(out[0], &a); err != nil {
		t.Fatal(err)
	}
	if a["id"] != "a" {
		t.Fatalf("first-seen order not preserved: %s", out[0])
	}
	props := a["properties"].(map[string]any)
	x := props["x"].(map[string]any)
	if x["p"] != float64(1) || x["q"] != float64(2) { // nested merge keeps both
		t.Errorf("nested object not deep-merged: %v", x)
	}
	if props["z"] != float64(3) { // new key from the fragment
		t.Errorf("fragment field not merged: %v", props)
	}
}

// End-to-end cross-call merge: a base s3-buckets list plus a per-bucket
// public-access-block (annotated with the bucket name) compose into one asset.
func TestTransformFiles_S3CrossCallMerge(t *testing.T) {
	buckets := []byte(`{"Buckets":[{"Name":"data","CreationDate":"2026-01-01T00:00:00Z"}]}`)
	pab := []byte(`{"Bucket":"data","PublicAccessBlockConfiguration":{
		"BlockPublicAcls":true,"BlockPublicPolicy":true,
		"IgnorePublicAcls":true,"RestrictPublicBuckets":true}}`)

	out, stats, err := TransformFiles(map[string][]byte{
		"s3-buckets.json":  buckets,
		"s3-pab-data.json": pab,
	}, Options{CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 2 || stats.Assets != 1 { // two files, merged into one bucket
		t.Fatalf("unexpected stats: %+v", stats)
	}

	var doc struct {
		Assets []map[string]any `json:"assets"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	storage := doc.Assets[0]["properties"].(map[string]any)["storage"].(map[string]any)
	if storage["name"] != "data" { // from the base filter
		t.Errorf("base field missing after merge: %v", storage)
	}
	controls, ok := storage["controls"].(map[string]any) // from the enrichment
	if !ok {
		t.Fatalf("enrichment not merged in: %v", storage)
	}
	if controls["public_access_fully_blocked"] != true {
		t.Errorf("public_access_fully_blocked = %v", controls["public_access_fully_blocked"])
	}
}

// Full role assembly: list-roles base + annotated attached-policies + annotated
// role-tags merge into one role asset matching aws-snapshot.sh's field shape
// (trusted_services, attached_policy_arns, is_admin_equivalent, tags).
func TestTransformFiles_RoleEnrichment(t *testing.T) {
	roles := []byte(`{"Roles":[{"RoleName":"deploy","Arn":"arn:aws:iam::1:role/deploy",
		"AssumeRolePolicyDocument":{"Statement":[{"Principal":{"Service":"lambda.amazonaws.com"}}]}}]}`)
	attached := []byte(`{"RoleArn":"arn:aws:iam::1:role/deploy","AttachedPolicies":[
		{"PolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"},
		{"PolicyArn":"arn:aws:iam::aws:policy/AmazonS3FullAccess"}]}`)
	tags := []byte(`{"RoleArn":"arn:aws:iam::1:role/deploy","Tags":[{"Key":"team","Value":"platform"}]}`)

	out, stats, err := TransformFiles(map[string][]byte{
		"iam-roles.json":         roles,
		"iam-role-attached.json": attached,
		"iam-role-tags.json":     tags,
	}, Options{CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 { // three inputs, merged into one role
		t.Fatalf("want 1 role asset, got %d (stats %+v)", stats.Assets, stats)
	}

	id := assets(t, out)[0]["properties"].(map[string]any)["identity"].(map[string]any)
	if !equalStrSlice(id["trusted_services"], []string{"lambda.amazonaws.com"}) {
		t.Errorf("trusted_services = %v", id["trusted_services"])
	}
	if id["is_admin_equivalent"] != true {
		t.Errorf("is_admin_equivalent = %v (AdministratorAccess attached)", id["is_admin_equivalent"])
	}
	if !equalStrSlice(id["attached_policy_arns"], []string{
		"arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws:iam::aws:policy/AmazonS3FullAccess"}) {
		t.Errorf("attached_policy_arns = %v", id["attached_policy_arns"])
	}
	if tagsMap, _ := id["tags"].(map[string]any); tagsMap["team"] != "platform" {
		t.Errorf("tags = %v", id["tags"])
	}
}

// Full bucket assembly: list-buckets base + PAB + encryption + tags enrichments
// merge into one bucket asset.
func TestTransformFiles_S3FullEnrichment(t *testing.T) {
	files := map[string][]byte{
		"s3-buckets.json":   []byte(`{"Buckets":[{"Name":"data"}]}`),
		"s3-pab-data.json":  []byte(`{"Bucket":"data","PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"BlockPublicPolicy":true,"IgnorePublicAcls":true,"RestrictPublicBuckets":true}}`),
		"s3-enc-data.json":  []byte(`{"Bucket":"data","ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"key-123"}}]}}`),
		"s3-tags-data.json": []byte(`{"Bucket":"data","TagSet":[{"Key":"env","Value":"prod"}]}`),
	}
	out, stats, err := TransformFiles(files, Options{CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 {
		t.Fatalf("want 1 bucket asset, got %d", stats.Assets)
	}
	storage := assets(t, out)[0]["properties"].(map[string]any)["storage"].(map[string]any)
	if storage["name"] != "data" {
		t.Errorf("base name lost: %v", storage)
	}
	if c, _ := storage["controls"].(map[string]any); c["public_access_fully_blocked"] != true {
		t.Errorf("PAB enrichment missing: %v", storage["controls"])
	}
	if e, _ := storage["encryption"].(map[string]any); e["algorithm"] != "aws:kms" || e["kms_key_id"] != "key-123" {
		t.Errorf("encryption enrichment wrong: %v", storage["encryption"])
	}
	if tg, _ := storage["tags"].(map[string]any); tg["env"] != "prod" {
		t.Errorf("tags enrichment wrong: %v", storage["tags"])
	}
}

// Filename-derived key: a RAW per-call file (no Bucket in content) named
// s3-pab-<bucket>.json contributes its public-access-block to the base bucket
// asset — the key comes from the filename, no manual annotation.
func TestTransformFiles_FilenameDerivedKey(t *testing.T) {
	out, stats, err := TransformFiles(map[string][]byte{
		"s3-buckets.json": []byte(`{"Buckets":[{"Name":"data"}]}`),
		// raw get-public-access-block output — NO Bucket field in content:
		"s3-pab-data.json": []byte(`{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"BlockPublicPolicy":true,"IgnorePublicAcls":true,"RestrictPublicBuckets":true}}`),
	}, Options{CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Assets != 1 || stats.Skipped != 0 {
		t.Fatalf("filename key should merge raw PAB onto the bucket: %+v", stats)
	}
	storage := assets(t, out)[0]["properties"].(map[string]any)["storage"].(map[string]any)
	c, ok := storage["controls"].(map[string]any)
	if !ok || c["public_access_fully_blocked"] != true {
		t.Errorf("PAB not merged via filename key: %v", storage)
	}
}

// Content annotation wins over the filename: a file misleadingly named
// s3-pab-wrong.json but whose content says Bucket "right" keys to "right".
func TestInjectFilenameKey_ContentWins(t *testing.T) {
	parsed := map[string]any{"Bucket": "right", "PublicAccessBlockConfiguration": map[string]any{}}
	if injectFilenameKey("s3-pab-wrong.json", parsed) {
		t.Error("filename key should not override content-supplied Bucket")
	}
	if parsed["Bucket"] != "right" {
		t.Errorf("Bucket = %v, want right", parsed["Bucket"])
	}
}

// A file whose name matches no pattern is left untouched.
func TestInjectFilenameKey_NoMatch(t *testing.T) {
	parsed := map[string]any{"PublicAccessBlockConfiguration": map[string]any{}}
	if injectFilenameKey("random.json", parsed) {
		t.Error("no pattern should match random.json")
	}
	if _, ok := parsed["Bucket"]; ok {
		t.Error("Bucket should not be injected for an unmatched filename")
	}
}

func assets(t *testing.T, out []byte) []map[string]any {
	t.Helper()
	var doc struct {
		Assets []map[string]any `json:"assets"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Assets
}

// An un-annotated public-access-block (no Bucket key) has no join key and is
// skipped, not fatal.
func TestTransformFiles_UnannotatedPABSkipped(t *testing.T) {
	pab := []byte(`{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true}}`)
	_, stats, err := TransformFiles(map[string][]byte{"pab.json": pab},
		Options{CapturedAt: "2026-06-01T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Skipped != 1 || stats.Assets != 0 {
		t.Fatalf("unannotated PAB should be skipped: %+v", stats)
	}
}

func TestScrubAsset(t *testing.T) {
	// UserData, Lambda env Variables values, and secret-keyed tags are hashed;
	// policy documents, ARNs, names, and actions are left intact.
	in := `{
		"id":"arn:aws:lambda:us-east-1:1:function:f",
		"properties":{
			"compute":{
				"UserData":"#!/bin/bash\nexport TOKEN=abc",
				"environment":{"variables":{"DB_PASSWORD":"hunter2","LOG_LEVEL":"info"}},
				"tags":{"Name":"prod-fn","api_key":"sk-live-123"},
				"policy":{"Action":["s3:GetObject"],"Resource":"*"}
			}
		}
	}`
	var node any
	if err := json.Unmarshal([]byte(in), &node); err != nil {
		t.Fatal(err)
	}
	scrubAsset(node)

	compute := node.(map[string]any)["properties"].(map[string]any)["compute"].(map[string]any)
	if ud, _ := compute["UserData"].(string); !strings.HasPrefix(ud, "sha256:") {
		t.Errorf("UserData not hashed: %v", compute["UserData"])
	}
	vars := compute["environment"].(map[string]any)["variables"].(map[string]any)
	if pw, _ := vars["DB_PASSWORD"].(string); !strings.HasPrefix(pw, "sha256:") {
		t.Errorf("env value not hashed: %v", vars["DB_PASSWORD"])
	}
	// All env values are hashed by design — env vars routinely hold secrets and
	// the value can't be classified, so LOG_LEVEL is redacted too.
	if lvl, _ := vars["LOG_LEVEL"].(string); !strings.HasPrefix(lvl, "sha256:") {
		t.Errorf("env value not hashed: %v", vars["LOG_LEVEL"])
	}
	tags := compute["tags"].(map[string]any)
	if k, _ := tags["api_key"].(string); !strings.HasPrefix(k, "sha256:") {
		t.Errorf("secret tag not hashed: %v", tags["api_key"])
	}
	if n, _ := tags["Name"].(string); n != "prod-fn" {
		t.Errorf("benign tag scrubbed: %v", n)
	}
	// Policy document MUST be untouched — Stave controls read it.
	pol := compute["policy"].(map[string]any)
	if act, _ := pol["Action"].([]any); len(act) != 1 || act[0] != "s3:GetObject" {
		t.Errorf("policy Action was altered: %v", pol["Action"])
	}
}
