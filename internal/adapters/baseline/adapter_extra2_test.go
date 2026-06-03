package baseline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/reporting"
)

func TestEntriesToDomain(t *testing.T) {
	entries := []evaluation.BaselineEntry{
		{
			ControlID:   kernel.ControlID("CTL.A.001"),
			ControlName: "Test",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
		},
	}
	domain := entriesToDomain(entries)
	if len(domain) != 1 {
		t.Fatalf("len = %d", len(domain))
	}
	if domain[0].ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %q", domain[0].ControlID)
	}
	if domain[0].AssetID != "bucket-1" {
		t.Fatalf("AssetID = %q", domain[0].AssetID)
	}
}

func TestEntriesToDomain_Empty(t *testing.T) {
	domain := entriesToDomain(nil)
	if len(domain) != 0 {
		t.Fatalf("len = %d", len(domain))
	}
}

func TestDomainToEntries(t *testing.T) {
	findings := []reporting.BaselineFinding{
		{
			ControlID:   "CTL.S3.PUBLIC.001",
			ControlName: "Test",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
		},
	}
	entries, err := domainToEntries(findings)
	if err != nil {
		t.Fatalf("domainToEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len = %d", len(entries))
	}
	if entries[0].ControlID != "CTL.S3.PUBLIC.001" {
		t.Fatalf("ControlID = %v", entries[0].ControlID)
	}
}

func TestDomainToEntries_Empty(t *testing.T) {
	entries, err := domainToEntries(nil)
	if err != nil {
		t.Fatalf("domainToEntries: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("len = %d", len(entries))
	}
}

func TestDomainToEntries_InvalidControlID(t *testing.T) {
	findings := []reporting.BaselineFinding{
		{ControlID: "INVALID", ControlName: "Bad", AssetID: "x", AssetType: "s3_bucket"},
	}
	_, err := domainToEntries(findings)
	if err == nil {
		t.Fatal("expected error for invalid control ID")
	}
}

func TestRoundTrip(t *testing.T) {
	original := []evaluation.BaselineEntry{
		{
			ControlID:   "CTL.S3.PUBLIC.001",
			ControlName: "Test Control",
			AssetID:     "bucket-1",
			AssetType:   "s3_bucket",
		},
	}
	domain := entriesToDomain(original)
	roundTrip, err := domainToEntries(domain)
	if err != nil {
		t.Fatalf("domainToEntries: %v", err)
	}
	if len(roundTrip) != 1 {
		t.Fatalf("len = %d", len(roundTrip))
	}
	if roundTrip[0].ControlID != original[0].ControlID {
		t.Fatalf("ControlID mismatch")
	}
	if roundTrip[0].AssetID != original[0].AssetID {
		t.Fatalf("AssetID mismatch")
	}
}

// TestWriteBaseline_CloseErrorPropagated drives WriteBaseline through
// a custom FileOpener whose returned *os.File has already been closed
// — the second Close from the writer's defer becomes an error. We
// assert the error reaches the caller, since a silent close-error
// swallow could leave the on-disk file flushed but unsynced or
// partially written, with WriteBaseline reporting success.
func TestWriteBaseline_CloseErrorPropagated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	// Open the file, then close it before handing it to the writer.
	// jsonutil.WriteIndented will fail on the closed FD, and the
	// fix path returns that error rather than dropping it.
	w := &Writer{
		openFile: func(p string) (*os.File, error) {
			f, err := os.Create(p)
			if err != nil {
				return nil, fmt.Errorf("create test file: %w", err)
			}
			_ = f.Close()
			return f, nil
		},
	}

	err := w.WriteBaseline(context.Background(), path,
		[]reporting.BaselineFinding{{ControlID: "CTL.AWS.S3.001", AssetID: "x"}},
		time.Now(), "src.json")
	if err == nil {
		t.Fatal("expected an error from a closed underlying file, got nil")
	}
	if !strings.Contains(err.Error(), "write") && !strings.Contains(err.Error(), "close") {
		t.Errorf("error %q should mention write or close", err.Error())
	}
}
