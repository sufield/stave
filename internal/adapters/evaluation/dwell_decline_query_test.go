package evaluation_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/core/sirfacts"
)

// dwellFixtureDoc builds a SIR document with two S3 buckets, each carrying
// one exposure window. reliable's window has a positive dwell; clamped's
// window was resolved to zero duration (Start == End) and flagged
// DurationUnreliable, the shape the SIR builder emits for a clock-skewed /
// reordered observation pair.
func dwellFixtureDoc(reliable, clamped string) *sir.Document {
	t := time.Date(2026, 5, 7, 0, 0, 0, 0, time.UTC)
	return &sir.Document{
		Assets: []sir.AssetFact{
			{ID: reliable, Type: "aws_s3_bucket", Vendor: "aws"},
			{ID: clamped, Type: "aws_s3_bucket", Vendor: "aws"},
		},
		Temporal: sir.TemporalFacts{
			Windows: []sir.ExposureWindow{
				{
					AssetID:                reliable,
					Start:                  t,
					End:                    t.Add(72 * time.Hour),
					UnsafePredicateMatched: true,
					ContributingControls:   []string{"CTL.S3.PUBLIC.001"},
				},
				{
					AssetID:                clamped,
					Start:                  t,
					End:                    t, // zero dwell
					UnsafePredicateMatched: true,
					DurationUnreliable:     true,
					ContributingControls:   []string{"CTL.S3.PUBLIC.001"},
				},
			},
		},
		EvaluatedAt: t.Add(72 * time.Hour),
	}
}

// factsSMT2 projects a document to a closed-world SMT-LIB fact block.
func factsSMT2(t *testing.T, doc *sir.Document) string {
	t.Helper()
	var buf bytes.Buffer
	if err := sirfacts.SerializeSMT2(sirfacts.ExtractFacts(doc), &buf, sirfacts.SMT2Options{ClosedWorld: true}); err != nil {
		t.Fatalf("SerializeSMT2: %v", err)
	}
	return buf.String()
}

// solve appends the dwell-grading query to a fact block and runs an SMT
// solver, returning the verdict ("sat"/"unsat") and the full output.
func solve(t *testing.T, solverBin, facts, query string) (verdict, full string) {
	t.Helper()
	args := []string{"-in"}
	if filepath.Base(solverBin) == "cvc5" {
		args = []string{"--lang", "smt2", "--produce-models"}
	}
	cmd := exec.Command(solverBin, args...)
	cmd.Stdin = strings.NewReader(facts + "\n" + query)
	out, _ := cmd.CombinedOutput() // solver exit code is non-zero for unsat models; read output regardless
	full = string(out)
	for line := range strings.SplitSeq(full, "\n") {
		line = strings.TrimSpace(line)
		if line == "sat" || line == "unsat" {
			return line, full
		}
	}
	return "", full
}

// TestDwellGradingQuery_DeclinesOnClampedWindow is a worked SMT proof that the
// dwell-grading query (testdata/dwell_decline_query.smt2) honors the SIR's
// has_unreliable_exposure_duration signal: it returns the reliable exposure as
// a witness and DECLINES (UNSAT) when the only candidate window is clamped.
//
// This lives in internal/adapters/evaluation (not internal/core) because it
// shells out to a solver — the core-test isolation gate forbids os/exec under
// internal/core (see internal/app/architecture_core_isolation_test.go). It
// skips cleanly when no solver is installed, so it never gates CI on z3/cvc5.
//
// The query selects an asset with a confirmed exposure:
//
//	has_type(a,"aws_s3_bucket") ∧ has_exposure_window(a,"true")
//	  ∧ ¬has_unreliable_exposure_duration(a,"true")
//
// The clamped bucket carries has_unreliable_exposure_duration, so the query's
// negation excludes it; under the closed-world axioms the reliable bucket
// (unflagged) satisfies it. Hence sat with the reliable witness on a mixed
// corpus, and unsat (decline) when only the clamped window exists.
func TestDwellGradingQuery_DeclinesOnClampedWindow(t *testing.T) {
	t.Parallel()

	solverBin, err := exec.LookPath("z3")
	if err != nil {
		if solverBin, err = exec.LookPath("cvc5"); err != nil {
			t.Skip("no SMT solver (z3 or cvc5) on PATH; skipping the solver proof")
		}
	}

	queryBytes, err := os.ReadFile(filepath.Join("testdata", "dwell_decline_query.smt2"))
	if err != nil {
		t.Fatalf("read query fixture: %v", err)
	}
	query := string(queryBytes)

	const reliable = "arn:aws:s3:::bucket-reliable-exposure"
	const clamped = "arn:aws:s3:::bucket-clamped-skew"

	// 1) Mixed corpus: one reliable + one clamped window. The grader must find
	//    the reliable bucket and NOT the clamped one.
	mixed := factsSMT2(t, dwellFixtureDoc(reliable, clamped))
	verdict, full := solve(t, solverBin, mixed, query)
	if verdict != "sat" {
		t.Fatalf("mixed corpus: want sat (a gradeable exposure exists), got %q\n%s", verdict, full)
	}
	if !strings.Contains(full, reliable) {
		t.Errorf("mixed corpus: witness should name the reliable bucket %q\n%s", reliable, full)
	}
	if strings.Contains(full, clamped) {
		t.Errorf("mixed corpus: clamped bucket %q must NOT be a gradeable witness "+
			"(its dwell is unreliable)\n%s", clamped, full)
	}

	// 2) Clamped-only corpus: the sole exposure window is unreliable, so there
	//    is nothing trustworthy to grade — the proof must DECLINE (unsat).
	clampedOnly := factsSMT2(t, &sir.Document{
		Assets: []sir.AssetFact{{ID: clamped, Type: "aws_s3_bucket", Vendor: "aws"}},
		Temporal: sir.TemporalFacts{Windows: []sir.ExposureWindow{{
			AssetID:                clamped,
			UnsafePredicateMatched: true,
			DurationUnreliable:     true,
			ContributingControls:   []string{"CTL.S3.PUBLIC.001"},
		}}},
	})
	verdict, full = solve(t, solverBin, clampedOnly, query)
	if verdict != "unsat" {
		t.Fatalf("clamped-only corpus: want unsat (decline to grade an unreliable dwell), got %q\n%s",
			verdict, full)
	}
}
