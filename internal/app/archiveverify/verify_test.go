package archiveverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/internal/app/collect"
)

func createTestArchive(t *testing.T, runs []collect.ManifestRun) string {
	t.Helper()
	dir := t.TempDir()

	manifest := collect.Manifest{
		SchemaVersion: "1",
		ArchiveID:     "test",
		CreatedAt:     "2026-01-01T00:00:00Z",
		LastUpdated:   "2026-01-03T00:00:00Z",
		Runs:          runs,
	}

	// Write manifest.
	mdata, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), mdata, 0o644)
	h := sha256.Sum256(mdata)
	hash := "sha256:" + hex.EncodeToString(h[:])
	_ = os.WriteFile(filepath.Join(dir, "manifest.json.sha256"), []byte(hash+"\n"), 0o644)

	// Create run directories with valid checksums.
	for _, r := range runs {
		runDir := filepath.Join(dir, "runs", r.RunID)
		_ = os.MkdirAll(runDir, 0o755)

		content := []byte(`{"test": true}`)
		_ = os.WriteFile(filepath.Join(runDir, "findings.json"), content, 0o644)
		fh := sha256.Sum256(content)
		sumLine := "sha256:" + hex.EncodeToString(fh[:]) + "  findings.json\n"
		_ = os.WriteFile(filepath.Join(runDir, "sha256sums.txt"), []byte(sumLine), 0o644)
	}

	return dir
}

func TestVerify_ValidArchive_Pass(t *testing.T) {
	runs := []collect.ManifestRun{
		{RunID: "run-1", CollectedAt: "2026-01-01T03:00:00Z"},
		{RunID: "run-2", CollectedAt: "2026-01-02T03:00:00Z"},
		{RunID: "run-3", CollectedAt: "2026-01-03T03:00:00Z"},
	}
	dir := createTestArchive(t, runs)

	a, err := Verify(VerifyInput{
		ArchivePath: dir,
		PeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 1, 3, 23, 59, 59, 0, time.UTC),
		PeriodLabel: "2026-01",
		MaxGapHours: 25,
		GeneratedAt: "2026-01-04T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if a.Verdict != "PASS" {
		t.Errorf("verdict = %q, want PASS", a.Verdict)
	}
	if a.Summary.RunsValid != 3 {
		t.Errorf("valid runs = %d, want 3", a.Summary.RunsValid)
	}
}

func TestVerify_TamperedBundle_Fail(t *testing.T) {
	runs := []collect.ManifestRun{
		{RunID: "run-1", CollectedAt: "2026-01-01T03:00:00Z"},
	}
	dir := createTestArchive(t, runs)

	// Tamper with a file.
	_ = os.WriteFile(filepath.Join(dir, "runs", "run-1", "findings.json"), []byte("TAMPERED"), 0o644)

	a, err := Verify(VerifyInput{
		ArchivePath: dir,
		PeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC),
		PeriodLabel: "2026-01-01",
		MaxGapHours: 25,
		GeneratedAt: "2026-01-02T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if a.Verdict != "FAIL" {
		t.Errorf("verdict = %q, want FAIL (tampered bundle)", a.Verdict)
	}
	if a.Summary.RunsInvalid != 1 {
		t.Errorf("invalid runs = %d, want 1", a.Summary.RunsInvalid)
	}
}

func TestVerify_GapExceedingMax_Fail(t *testing.T) {
	runs := []collect.ManifestRun{
		{RunID: "run-1", CollectedAt: "2026-01-01T03:00:00Z"},
		{RunID: "run-2", CollectedAt: "2026-01-04T03:00:00Z"}, // 72h gap
	}
	dir := createTestArchive(t, runs)

	a, err := Verify(VerifyInput{
		ArchivePath: dir,
		PeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 1, 4, 23, 59, 59, 0, time.UTC),
		PeriodLabel: "test",
		MaxGapHours: 25,
		GeneratedAt: "2026-01-05T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if a.Verdict != "FAIL" {
		t.Errorf("verdict = %q, want FAIL (gap exceeding max)", a.Verdict)
	}
	if a.Summary.GapsExceedingMax != 1 {
		t.Errorf("gaps exceeding max = %d, want 1", a.Summary.GapsExceedingMax)
	}
}

func TestVerify_GapWithinMax_Pass(t *testing.T) {
	runs := []collect.ManifestRun{
		{RunID: "run-1", CollectedAt: "2026-01-01T03:00:00Z"},
		{RunID: "run-2", CollectedAt: "2026-01-02T02:00:00Z"}, // 23h gap
	}
	dir := createTestArchive(t, runs)

	a, err := Verify(VerifyInput{
		ArchivePath: dir,
		PeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 1, 2, 23, 59, 59, 0, time.UTC),
		PeriodLabel: "test",
		MaxGapHours: 25,
		GeneratedAt: "2026-01-03T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if a.Verdict != "PASS" {
		t.Errorf("verdict = %q, want PASS (gap within max)", a.Verdict)
	}
}

func TestVerify_Strict_FailsOnAnyGap(t *testing.T) {
	runs := []collect.ManifestRun{
		{RunID: "run-1", CollectedAt: "2026-01-01T03:00:00Z"},
		{RunID: "run-2", CollectedAt: "2026-01-01T05:00:00Z"}, // 2h gap
	}
	dir := createTestArchive(t, runs)

	a, err := Verify(VerifyInput{
		ArchivePath: dir,
		PeriodStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC),
		PeriodLabel: "test",
		MaxGapHours: 25,
		Strict:      true,
		GeneratedAt: "2026-01-02T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if a.Verdict != "FAIL" {
		t.Errorf("verdict = %q, want FAIL (strict mode)", a.Verdict)
	}
}

func TestParsePeriod(t *testing.T) {
	tests := []struct {
		input string
		start string
		end   string
	}{
		{"2026-Q1", "2026-01-01", "2026-03-31"},
		{"2026-Q4", "2026-10-01", "2026-12-31"},
		{"2026-01", "2026-01-01", "2026-01-31"},
		{"2026-02-15", "2026-02-15", "2026-02-15"},
		{"2026-01-01:2026-03-31", "2026-01-01", "2026-03-31"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			start, end, _, err := ParsePeriod(tt.input)
			if err != nil {
				t.Fatalf("parse %q failed: %v", tt.input, err)
			}
			if start.Format("2006-01-02") != tt.start {
				t.Errorf("start = %s, want %s", start.Format("2006-01-02"), tt.start)
			}
			if end.Format("2006-01-02") != tt.end {
				t.Errorf("end = %s, want %s", end.Format("2006-01-02"), tt.end)
			}
		})
	}
}
