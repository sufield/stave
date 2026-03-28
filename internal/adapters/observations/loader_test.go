package observations

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/integrity"
)

// TestObservationLoader_RejectsMissingSchemaVersion tests that LoadSnapshots returns an error
// when a snapshot is missing the required schema_version field.
func TestObservationLoader_RejectsMissingSchemaVersion(t *testing.T) {
	// Create temp dir with test file
	dir := t.TempDir()
	content := `{
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": []
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for missing schema_version")
	}

	// Check error message contains expected info
	errStr := err.Error()
	if !strings.Contains(errStr, "schema_version") {
		t.Errorf("error should mention schema_version, got: %s", errStr)
	}
	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %s", errStr)
	}
}

// TestObservationLoader_RejectsUnsupportedSchemaVersion tests that LoadSnapshots returns an error
// when a snapshot specifies an unsupported schema_version.
func TestObservationLoader_RejectsUnsupportedSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v99.0",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": []
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for unsupported schema_version")
	}

	// Schema validation should reject unsupported version via const constraint or version check
	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) && !strings.Contains(err.Error(), "UNSUPPORTED_SCHEMA_VERSION") {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

// TestObservationLoader_AcceptsSupportedSchemaVersion tests that LoadSnapshots successfully
// loads a snapshot with a supported schema_version.
func TestObservationLoader_AcceptsSupportedSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {"id": "res-1", "type": "test", "vendor": "aws", "properties": {}}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	result, err := loader.LoadSnapshots(context.Background(), dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Snapshots) != 1 {
		t.Errorf("expected 1 snapshot, got %d", len(result.Snapshots))
	}
	if result.Snapshots[0].SchemaVersion != "obs.v0.1" {
		t.Errorf("expected schema_version obs.v0.1, got %s", result.Snapshots[0].SchemaVersion)
	}
}

// TestObservationLoader_RejectsZeroCapturedAt ensures parser-level semantic
// validation rejects RFC3339 timestamps that decode to Go's zero time.
func TestObservationLoader_RejectsZeroCapturedAt(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "0001-01-01T00:00:00Z",
  "assets": []
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for zero captured_at")
	}
	if !errors.Is(err, ErrMissingTimestamp) {
		t.Fatalf("expected ErrMissingTimestamp, got: %v", err)
	}
}

func TestObservationLoader_LoadSnapshotFromReader_RejectsZeroCapturedAt(t *testing.T) {
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "0001-01-01T00:00:00Z",
  "assets": []
}`

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshotFromReader(context.Background(), strings.NewReader(content), "stdin")
	if err == nil {
		t.Fatal("expected error for zero captured_at")
	}
	if !errors.Is(err, ErrMissingTimestamp) {
		t.Fatalf("expected ErrMissingTimestamp, got: %v", err)
	}
}

// TestObservationLoader_RejectsMissingResourceVendor tests that schema validation
// catches missing required fields in assets.
func TestObservationLoader_RejectsMissingResourceVendor(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {"id": "res-1", "type": "test", "properties": {}}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for missing vendor")
	}

	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

// TestObservationLoader_RejectsMissingIdentityProperties tests that schema validation
// catches missing required properties field in identities.
func TestObservationLoader_RejectsMissingIdentityProperties(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [],
  "identities": [
    {"id": "id-1", "type": "iam_role", "vendor": "aws"}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for missing properties")
	}

	if !errors.Is(err, contractvalidator.ErrSchemaValidationFailed) {
		t.Errorf("error should be ErrSchemaValidationFailed, got: %v", err)
	}
}

func TestObservationLoader_RejectsTopLevelIdentityFields(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [],
  "identities": [
    {
      "id": "id-1",
      "type": "iam_role",
      "vendor": "aws",
      "owner": "team-a",
      "purpose": "runtime"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()

	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for top-level identity fields (owner, purpose) — these must be inside properties")
	}
}

// TestObservationLoader_RejectsWhitespaceVendor verifies that a whitespace-only
// vendor is rejected. With Vendor.UnmarshalJSON, this now fails during unmarshal
// rather than in a separate normalization pass.
func TestObservationLoader_RejectsWhitespaceVendor(t *testing.T) {
	dir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {"id": "res-1", "type": "storage_bucket", "vendor": "   ", "properties": {}}
  ]
}`
	if err := os.WriteFile(filepath.Join(dir, "test.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	_, err := loader.LoadSnapshots(context.Background(), dir)
	if err == nil {
		t.Fatal("expected error for whitespace vendor")
	}
	if !strings.Contains(err.Error(), "vendor") {
		t.Errorf("error should mention vendor, got: %s", err.Error())
	}
}

func TestObservationLoader_IntegrityManifest_Success(t *testing.T) {
	obsDir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {"id": "res-1", "type": "storage_bucket", "vendor": "aws", "properties": {}}
  ]
}`
	if err := os.WriteFile(filepath.Join(obsDir, "snapshot.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	seedResult, err := loader.LoadSnapshots(context.Background(), obsDir)
	if err != nil {
		t.Fatalf("seed load failed: %v", err)
	}
	hashes := seedResult.Hashes
	if hashes == nil {
		t.Fatal("expected input hashes")
	}

	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	manifest := integrity.Manifest{Files: hashes.Files, Overall: hashes.Overall}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	loader2 := NewObservationLoader()
	loader2.ConfigureIntegrityCheck(manifestPath, "")
	if _, err := loader2.LoadSnapshots(context.Background(), obsDir); err != nil {
		t.Fatalf("expected successful integrity verification, got: %v", err)
	}
}

func TestObservationLoader_IntegrityManifest_HashMismatch(t *testing.T) {
	obsDir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {"id": "res-1", "type": "storage_bucket", "vendor": "aws", "properties": {}}
  ]
}`
	if err := os.WriteFile(filepath.Join(obsDir, "snapshot.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	seedResult, err := loader.LoadSnapshots(context.Background(), obsDir)
	if err != nil {
		t.Fatalf("seed load failed: %v", err)
	}
	hashes := seedResult.Hashes
	manifestFiles := map[evaluation.FilePath]kernel.Digest{"snapshot.json": kernel.Digest(strings.Repeat("a", 64))}
	if hashes == nil {
		t.Fatal("expected input hashes")
	}
	manifest := integrity.Manifest{Files: manifestFiles, Overall: hashes.Overall}

	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	data, _ := json.Marshal(manifest)
	if writeErr := os.WriteFile(manifestPath, data, 0644); writeErr != nil {
		t.Fatal(writeErr)
	}

	loader2 := NewObservationLoader()
	loader2.ConfigureIntegrityCheck(manifestPath, "")
	_, err = loader2.LoadSnapshots(context.Background(), obsDir)
	if err == nil {
		t.Fatal("expected integrity verification error")
	}
	if !errors.Is(err, integrity.ErrIntegrityViolation) {
		t.Fatalf("expected ErrIntegrityViolation, got: %v", err)
	}
}

func TestObservationLoader_SignedIntegrityManifest_Success(t *testing.T) {
	obsDir := t.TempDir()
	content := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": [
    {"id": "res-1", "type": "storage_bucket", "vendor": "aws", "properties": {}}
  ]
}`
	if err := os.WriteFile(filepath.Join(obsDir, "snapshot.json"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	loader := NewObservationLoader()
	seedResult, err := loader.LoadSnapshots(context.Background(), obsDir)
	if err != nil {
		t.Fatalf("seed load failed: %v", err)
	}
	hashes := seedResult.Hashes
	if hashes == nil {
		t.Fatal("expected input hashes")
	}
	manifest := integrity.Manifest{Files: hashes.Files, Overall: hashes.Overall}
	manifestBytes, err := manifest.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, manifestBytes)
	signed := integrity.SignedManifest{
		Manifest:  manifest,
		Signature: kernel.Signature(hex.EncodeToString(signature)),
	}
	signedBytes, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	pubPKIX, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubPKIX})

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "signed-manifest.json")
	pubPath := filepath.Join(tmp, "manifest.pub.pem")
	if err := os.WriteFile(manifestPath, signedBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	loader2 := NewObservationLoader()
	loader2.ConfigureIntegrityCheck(manifestPath, pubPath)
	if _, err := loader2.LoadSnapshots(context.Background(), obsDir); err != nil {
		t.Fatalf("expected signed integrity verification success, got: %v", err)
	}
}
