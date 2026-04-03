package eval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

// ---------------------------------------------------------------------------
// NewPlan
// ---------------------------------------------------------------------------

type stubHasher struct {
	failDir  bool
	failFile bool
}

func (h *stubHasher) HashDir(dir string, exts ...string) (string, error) {
	if h.failDir {
		return "", os.ErrNotExist
	}
	return "sha256:dirtest", nil
}

func (h *stubHasher) HashFile(path string) (string, error) {
	if h.failFile {
		return "", os.ErrNotExist
	}
	return "sha256:filetest", nil
}

func TestNewPlan_WithHasher(t *testing.T) {
	dir := t.TempDir()
	ctlDir := filepath.Join(dir, "controls")
	obsDir := filepath.Join(dir, "observations")
	cfgPath := filepath.Join(dir, "stave.yaml")
	os.Mkdir(ctlDir, 0o755)
	os.Mkdir(obsDir, 0o755)
	os.WriteFile(cfgPath, []byte("test: true"), 0o600)

	opts := Options{
		ContextName:        "plan-test",
		ProjectRoot:        dir,
		ControlsDir:        ctlDir,
		ConfigPath:         cfgPath,
		MaxUnsafeDuration:  "24h",
		ObservationsSource: ObservationSource(obsDir),
		Hasher:             &stubHasher{},
	}

	plan, err := NewPlan(opts)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	if plan.ContextName != "plan-test" {
		t.Fatalf("ContextName = %q", plan.ContextName)
	}
	if plan.ControlsHash == "" {
		t.Fatal("expected controls hash")
	}
	if plan.ObservationsHash == "" {
		t.Fatal("expected observations hash")
	}
	if plan.ConfigHash == "" {
		t.Fatal("expected config hash")
	}
}

func TestNewPlan_NilHasher(t *testing.T) {
	opts := Options{
		ContextName:       "no-hash",
		MaxUnsafeDuration: "24h",
	}
	plan, err := NewPlan(opts)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	if plan.ControlsHash != "" {
		t.Fatal("expected empty hash without hasher")
	}
}

func TestNewPlan_ControlsDirNotExist(t *testing.T) {
	// When the controls dir doesn't exist (built-in packs), it should skip hashing.
	opts := Options{
		ContextName:       "no-dir",
		ControlsDir:       "/nonexistent/controls",
		MaxUnsafeDuration: "24h",
		Hasher:            &stubHasher{},
	}
	plan, err := NewPlan(opts)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	if plan.ControlsHash != "" {
		t.Fatal("expected empty hash for non-existent dir")
	}
}

func TestNewPlan_WithLockFile(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "stave.lock")
	os.WriteFile(lockPath, []byte("lock"), 0o600)

	opts := Options{
		ContextName:       "lock-test",
		ProjectRoot:       dir,
		MaxUnsafeDuration: "24h",
		Hasher:            &stubHasher{},
	}
	plan, err := NewPlan(opts)
	if err != nil {
		t.Fatalf("NewPlan: %v", err)
	}
	if plan.LockFile == "" {
		t.Fatal("expected lock file path")
	}
	if plan.LockHash == "" {
		t.Fatal("expected lock hash")
	}
}

// ---------------------------------------------------------------------------
// Enrich with sanitizer
// ---------------------------------------------------------------------------

func TestEnrich_WithSanitizer(t *testing.T) {
	s := sanitize.New(sanitize.WithIDSanitization(true))
	enricher := remediation.NewMapper()

	result := evaluation.Result{
		Run: evaluation.RunInfo{
			InputHashes: &evaluation.InputHashes{
				Files: map[evaluation.FilePath]kernel.Digest{
					"/tmp/a.json": "sha256:aaa",
				},
				Overall: "sha256:combined",
			},
		},
		ExemptedAssets: []asset.ExemptedAsset{
			{ID: "bucket-secret", Pattern: "bucket-*", Reason: "temp"},
		},
	}

	enriched, err := Enrich(enricher, s, result)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	// Exempted asset should have been sanitized
	if enriched.ExemptedAssets[0].ID == "bucket-secret" {
		t.Error("expected sanitized asset ID")
	}
	// Input hash keys should be sanitized
	for path := range enriched.Run.InputHashes.Files {
		if strings.Contains(string(path), "/tmp/") {
			t.Error("expected sanitized path")
		}
	}
}

// ---------------------------------------------------------------------------
// ControlFilter combinations (unique test names to avoid collision)
// ---------------------------------------------------------------------------

func TestFilterControls_ExcludeMultipleIDs(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001", Severity: controldef.SeverityCritical},
		{ID: "CTL.B.001", Severity: controldef.SeverityLow},
		{ID: "CTL.C.001", Severity: controldef.SeverityMedium},
	}
	filtered, err := FilterControls(controls, ControlFilter{
		ExcludeControlID: []kernel.ControlID{"CTL.A.001", "CTL.C.001"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].ID != "CTL.B.001" {
		t.Fatalf("expected only CTL.B.001, got %v", filtered)
	}
}

func TestFilterControls_NoMatchByID(t *testing.T) {
	controls := []controldef.ControlDefinition{
		{ID: "CTL.A.001"},
	}
	filtered, err := FilterControls(controls, ControlFilter{ControlID: "CTL.NOPE"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("expected 0, got %d", len(filtered))
	}
}

// ---------------------------------------------------------------------------
// classifySnapshotSourceType (uses Snapshot input)
// ---------------------------------------------------------------------------

func TestClassifySnapshotSourceType_Missing(t *testing.T) {
	s := asset.Snapshot{}
	verdict := classifySnapshotSourceType(s)
	if verdict != sourceTypeMissing {
		t.Fatalf("expected sourceTypeMissing, got %v", verdict)
	}
}

func TestClassifySnapshotSourceType_NilGeneratedBy(t *testing.T) {
	s := asset.Snapshot{GeneratedBy: nil}
	verdict := classifySnapshotSourceType(s)
	if verdict != sourceTypeMissing {
		t.Fatalf("expected sourceTypeMissing, got %v", verdict)
	}
}
