package manifest

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/integrity"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

func TestCollectObservationHashes_FiltersNonObservationAndManifestArtifacts(t *testing.T) {
	dir := t.TempDir()

	validObs := `{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-01-01T00:00:00Z",
  "assets": []
}`
	nonObsJSON := `{"summary":{"violations":1}}`
	manifestJSON := `{"files":{"a.json":"abc"},"overall":"def"}`

	if err := os.WriteFile(filepath.Join(dir, "snapshot-1.json"), []byte(validObs), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snapshot-2.json"), []byte(validObs), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "evaluation.json"), []byte(nonObsJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifestJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signed-manifest.json"), []byte(manifestJSON), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "custom.manifest.json"), []byte(manifestJSON), 0644); err != nil {
		t.Fatal(err)
	}

	files, skipped, err := (&GenerateRunner{}).collectHashes(context.Background(), dir)
	if err != nil {
		t.Fatalf("collectObservationHashes failed: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 observation files, got %d: %#v", len(files), files)
	}
	if _, ok := files["snapshot-1.json"]; !ok {
		t.Fatalf("expected snapshot-1.json to be included")
	}
	if _, ok := files["snapshot-2.json"]; !ok {
		t.Fatalf("expected snapshot-2.json to be included")
	}
	if skipped != 1 {
		t.Fatalf("expected 1 skipped non-observation JSON file, got %d", skipped)
	}
}

func TestIsExcludedManifestArtifact(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "manifest.json", want: true},
		{name: "signed-manifest.json", want: true},
		{name: "custom.manifest.json", want: true},
		{name: "custom.signed-manifest.json", want: true},
		{name: "snapshot.json", want: false},
	}

	for _, tc := range cases {
		got := isManifestArtifact(tc.name)
		if got != tc.want {
			t.Fatalf("isManifestArtifact(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLoadPrivateKey_PEM(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey failed: %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privatePKCS8})

	path := filepath.Join(t.TempDir(), "manifest.private.pem")
	if err = os.WriteFile(path, privatePEM, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := loadPrivateKey(path)
	if err != nil {
		t.Fatalf("loadPrivateKey failed: %v", err)
	}
	if string(loaded) != string(privateKey) {
		t.Fatalf("loaded key does not match generated key")
	}
}

func TestValidateManifestOverall_Mismatch(t *testing.T) {
	manifest := integrity.Manifest{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": kernel.Digest(strings.Repeat("a", 64)),
		},
		Overall: kernel.Digest(strings.Repeat("b", 64)),
	}
	if err := manifest.ValidateOverall(); err == nil {
		t.Fatalf("expected overall mismatch error")
	}
}

func TestCanonicalManifestBytes_Deterministic(t *testing.T) {
	m1 := integrity.Manifest{
		Files: map[evaluation.FilePath]kernel.Digest{
			"b.json": kernel.Digest(strings.Repeat("b", 64)),
			"a.json": kernel.Digest(strings.Repeat("a", 64)),
		},
	}
	m1.Overall = integrity.ComputeOverall(m1.Files)

	m2 := integrity.Manifest{
		Files: map[evaluation.FilePath]kernel.Digest{
			"a.json": kernel.Digest(strings.Repeat("a", 64)),
			"b.json": kernel.Digest(strings.Repeat("b", 64)),
		},
	}
	m2.Overall = integrity.ComputeOverall(m2.Files)

	b1, err := m1.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalManifestBytes failed: %v", err)
	}
	b2, err := m2.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalManifestBytes failed: %v", err)
	}

	if string(b1) != string(b2) {
		t.Fatalf("canonical manifest bytes differ for equivalent map content:\n%s\n%s", string(b1), string(b2))
	}

	var parsed integrity.Manifest
	if err := json.Unmarshal(b1, &parsed); err != nil {
		t.Fatalf("canonical bytes are not valid JSON: %v", err)
	}
}
