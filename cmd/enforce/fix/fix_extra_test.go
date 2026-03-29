package fix

import (
	"testing"
)

func TestFixOptions_ValidateFindingRef_Valid(t *testing.T) {
	opts := &fixOptions{FindingRef: "CTL.S3.PUBLIC.001@bucket-a"}
	if err := opts.validateFindingRef(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFixOptions_ValidateFindingRef_NoAt(t *testing.T) {
	opts := &fixOptions{FindingRef: "CTL.S3.PUBLIC.001"}
	if err := opts.validateFindingRef(); err == nil {
		t.Fatal("expected error for missing @")
	}
}

func TestFixOptions_ValidateFindingRef_EmptyControlID(t *testing.T) {
	opts := &fixOptions{FindingRef: "@bucket-a"}
	if err := opts.validateFindingRef(); err == nil {
		t.Fatal("expected error for empty control ID")
	}
}

func TestFixOptions_ValidateFindingRef_EmptyAssetID(t *testing.T) {
	opts := &fixOptions{FindingRef: "CTL.S3.PUBLIC.001@"}
	if err := opts.validateFindingRef(); err == nil {
		t.Fatal("expected error for empty asset ID")
	}
}

func TestLoopOptions_Normalize_CreatesOutDir(t *testing.T) {
	dir := t.TempDir()
	opts := &loopOptions{
		BeforeDir:   "/some/before",
		AfterDir:    "/some/after",
		ControlsDir: "controls",
		OutDir:      dir + "/subdir",
	}
	if err := opts.normalize(); err != nil {
		t.Fatalf("normalize error: %v", err)
	}
}

func TestLoopOptions_ResolveConfigDefaults_NilDefaults(t *testing.T) {
	opts := &loopOptions{MaxUnsafeRaw: "24h"}
	// Should not panic with nil defaults.
	opts.resolveConfigDefaults(nil, nil)
	if opts.MaxUnsafeRaw != "24h" {
		t.Fatalf("MaxUnsafeRaw changed: %q", opts.MaxUnsafeRaw)
	}
}

func TestBuildLoopInfra_NilCtlRepo(t *testing.T) {
	runner := newTestRunner(t)
	runner.NewCtlRepo = nil
	_, err := runner.buildLoopInfra(LoopRequest{})
	if err == nil {
		t.Fatal("expected error for nil NewCtlRepo")
	}
}

func TestBuildLoopInfra_NilObsRepo(t *testing.T) {
	runner := newTestRunner(t)
	runner.NewObsRepo = nil
	_, err := runner.buildLoopInfra(LoopRequest{})
	if err == nil {
		t.Fatal("expected error for nil NewObsRepo")
	}
}
