package policyexport

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBugHunt_PolicyExport_LatestSnapshotWins(t *testing.T) {
	tmp, err := os.MkdirTemp("", "stave-policyexport-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)

	// We name the files alphabetically such that 1_newer.json is loaded BEFORE 2_older.json.
	// But 1_newer.json has a newer timestamp (CapturedAt).
	// Latest snapshot wins on duplicate should ensure that the newer snapshot's properties win,
	// regardless of the alphabetical filename loading order.

	// 1_newer.json: newer CapturedAt, policy contains Sid "newer"
	newerContent := `{
		"schema_version": "obs.v0.1",
		"captured_at": "2026-07-08T12:00:00Z",
		"assets": [
			{
				"id": "arn:aws:s3:::my-bucket",
				"type": "bucket",
				"vendor": "aws",
				"properties": {
					"storage": {
						"policy_json": "{\"Statement\": [{\"Sid\": \"newer\", \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\"}]}"
					}
				}
			}
		]
	}`

	// 2_older.json: older CapturedAt, policy contains Sid "older"
	olderContent := `{
		"schema_version": "obs.v0.1",
		"captured_at": "2026-07-07T12:00:00Z",
		"assets": [
			{
				"id": "arn:aws:s3:::my-bucket",
				"type": "bucket",
				"vendor": "aws",
				"properties": {
					"storage": {
						"policy_json": "{\"Statement\": [{\"Sid\": \"older\", \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\"}]}"
					}
				}
			}
		]
	}`

	writeFile := func(name, content string) {
		if writeErr := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0644); writeErr != nil {
			t.Fatalf("failed to write %s: %v", name, writeErr)
		}
	}
	writeFile("1_newer.json", newerContent)
	writeFile("2_older.json", olderContent)

	res, err := Run(context.Background(), Config{SnapshotsDir: tmp})
	if err != nil {
		t.Fatalf("policyexport.Run: %v", err)
	}

	if len(res.ResourcePolicies) != 1 {
		t.Fatalf("expected 1 resource policy, got %d", len(res.ResourcePolicies))
	}

	policyDoc := res.ResourcePolicies[0]
	if len(policyDoc.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(policyDoc.Statements))
	}

	gotSid := policyDoc.Statements[0].Sid
	wantSid := "newer"
	if gotSid != wantSid {
		t.Errorf("expected latest snapshot's policy to win (Sid=%q), but got Sid=%q (filename ordering overrode latest-wins)", wantSid, gotSid)
	}
}
