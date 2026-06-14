package sirfacts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/sir"
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
	if err := SerializeSMT2(ExtractFacts(doc), &buf, SMT2Options{ClosedWorld: true}); err != nil {
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
// This is the end-to-end consumer check for the DurationUnreliable flag: the
// SIR flags the window, sirfacts projects has_unreliable_exposure_duration,
// and the solver excludes it from the gradeable set — instead of reading a
// clamped Start == End as a trustworthy "0s exposure within any SLA."
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

	// 1) Mixed corpus: one reliable + one clamped window. The grader must
	//    find the reliable bucket and NOT the clamped one.
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
