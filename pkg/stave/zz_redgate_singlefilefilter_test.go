package stave

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test_RedGate_SingleFileFilter asserts the documented single-file
// contract of RunControlTests: when cfg.ControlPath names one control
// YAML file, ONLY that file's embedded test cases run. The doc comments
// (controltest.go:30-33 and 60-62) say single-file mode "narrows via
// filter to the single file's basename" and the cmd/test --control flag
// help is "test a single control YAML file".
//
// Bug controltest.go:59 RunControlTests: the single-file block only
// reassigns `dir` to the parent directory; it never derives `filter`
// from the control path. So `filter` stays cfg.Filter (empty), and
// controltest.Run skips filtering entirely (runner.go:68), executing the
// embedded test cases for EVERY control YAML in the parent directory.
//
// Construction: a temp directory holds two real controls that ship with
// embedded test cases. The REQUESTED control (NOREFERRER) is copied
// verbatim — all its cases pass. The OTHER control (NOHSTS) is copied
// with one embedded case's expected verdict flipped VIOLATION -> PASS,
// so that case fails at runtime (the predicate still fires VIOLATION).
// We point ControlPath at the requested control.
//
// Correct behavior: only NOREFERRER runs -> no failing cases -> err is
// nil and summary reports exactly one control tested. Buggy behavior:
// both controls run -> the corrupted NOHSTS case fails -> RunControlTests
// returns ErrFailingTests and summary.Failed > 0, which this test asserts
// against, so it goes RED against current code.
func Test_RedGate_SingleFileFilter(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in Test_RedGate_SingleFileFilter: %v", r)
		}
	}()

	const (
		srcReferrer = "../../controls/cloudfront/headers/CTL.CLOUDFRONT.HEADERS.NOREFERRER.001.yaml"
		srcHSTS     = "../../controls/cloudfront/headers/CTL.CLOUDFRONT.HEADERS.NOHSTS.001.yaml"
	)

	dir := t.TempDir()

	// Requested control: copy verbatim. Its embedded cases all pass.
	requestedPath := filepath.Join(dir, "CTL.CLOUDFRONT.HEADERS.NOREFERRER.001.yaml")
	if err := copyFile(srcReferrer, requestedPath); err != nil {
		t.Fatalf("copy requested control: %v", err)
	}

	// Sibling control: copy with one expected verdict corrupted so that
	// its embedded test case FAILS at runtime. The asset still has
	// headers_has_hsts:false, so the predicate fires VIOLATION; flipping
	// the expectation to PASS makes the case mismatch. The verdict value
	// stays in the schema enum {PASS,VIOLATION,INCONCLUSIVE}, so the
	// control still loads.
	hstsBytes, err := os.ReadFile(srcHSTS)
	if err != nil {
		t.Fatalf("read sibling control: %v", err)
	}
	corrupted := strings.Replace(string(hstsBytes), "verdict: VIOLATION", "verdict: PASS", 1)
	if corrupted == string(hstsBytes) {
		t.Fatalf("setup invariant violated: no 'verdict: VIOLATION' to corrupt in %s", srcHSTS)
	}
	siblingPath := filepath.Join(dir, "CTL.CLOUDFRONT.HEADERS.NOHSTS.001.yaml")
	if err := os.WriteFile(siblingPath, []byte(corrupted), 0o644); err != nil {
		t.Fatalf("write corrupted sibling control: %v", err)
	}

	results, summary, runErr := RunControlTests(context.Background(), TestConfig{
		ControlPath: requestedPath,
	})

	// The requested control's cases all pass; the corrupted sibling must
	// NOT have run. Therefore no failing tests and exactly one control.
	if errors.Is(runErr, ErrFailingTests) {
		t.Fatalf("single-file mode ran the sibling control: got ErrFailingTests, "+
			"want nil (only %s should be tested). summary=%+v results=%+v",
			filepath.Base(requestedPath), summary, results)
	}
	if runErr != nil {
		t.Fatalf("unexpected error from RunControlTests: %v", runErr)
	}
	if summary.Failed != 0 {
		t.Fatalf("expected 0 failed cases for single requested control, got %d (summary=%+v)",
			summary.Failed, summary)
	}
	if summary.ControlsTested != 1 {
		t.Fatalf("expected exactly 1 control tested in single-file mode, got %d (summary=%+v)",
			summary.ControlsTested, summary)
	}
	for _, r := range results {
		if !strings.Contains(r.ControlID, "NOREFERRER") {
			t.Fatalf("single-file mode tested an unrequested control %q (summary=%+v)",
				r.ControlID, summary)
		}
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err //nolint:wrapcheck // test helper
	}
	return os.WriteFile(dst, b, 0o644) //nolint:wrapcheck // test helper
}
