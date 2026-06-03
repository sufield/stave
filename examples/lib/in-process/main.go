// Command in-process demonstrates using pkg/stave as a Go library.
//
// It runs the full pipeline — validate, evaluate, score — in-process
// without shelling out to the stave binary, parsing JSON, or importing
// Cobra. Every result is a typed Go value.
//
// Usage:
//
//	go run ./examples/lib/in-process ./observations
//	go run ./examples/lib/in-process --controls ./my-controls ./observations
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sufield/stave/pkg/stave"
)

func main() {
	controls := flag.String("controls", "", "control definitions directory (empty = builtin catalog)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [--controls <dir>] <observations-dir>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	obsDir := flag.Arg(0)

	ctx := context.Background()

	// ── Step 1: Validate ─────────────────────────────────────────
	//
	// Structural check: are the snapshots well-formed and do the
	// controls parse? Catches malformed JSON, missing schema_version,
	// and predicate syntax errors before the evaluation spends time
	// loading the full catalog.

	fmt.Println("Step 1: Validate")
	vr, err := stave.Validate(ctx, stave.ValidateConfig{
		SnapshotsDir: obsDir,
		ControlsDir:  *controls,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "validate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  controls checked:    %d\n", vr.ControlsChecked)
	fmt.Printf("  snapshots checked:   %d\n", vr.SnapshotsChecked)
	fmt.Printf("  asset observations:  %d\n", vr.AssetObservations)
	fmt.Printf("  errors: %d  warnings: %d  valid: %v\n",
		vr.ErrorCount, vr.WarningCount, vr.Valid)

	if !vr.Valid {
		fmt.Fprintln(os.Stderr, "\nValidation failed. Fix errors before evaluating.")
		for _, f := range vr.Findings {
			if f.Severity == "error" {
				fmt.Fprintf(os.Stderr, "  [%s] %s: %s\n", f.Severity, f.RuleID, f.Message)
			}
		}
		os.Exit(1)
	}
	fmt.Println()

	// ── Step 2: Evaluate ─────────────────────────────────────────
	//
	// Run the full control catalog against the snapshots. Returns a
	// typed Assessment with Findings, Issues, ChainFindings, Summary,
	// and Status — no JSON parsing needed.

	fmt.Println("Step 2: Evaluate")
	assessment, err := stave.Apply(ctx, stave.Config{
		SnapshotsDir: obsDir,
		ControlsDir:  *controls,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluate: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  status:     %s\n", assessment.Status)
	fmt.Printf("  findings:   %d\n", len(assessment.Findings))
	fmt.Printf("  issues:     %d\n", len(assessment.Issues))
	fmt.Printf("  chains:     %d\n", len(assessment.ChainFindings))
	fmt.Println()

	// ── Step 3: Inspect findings ─────────────────────────────────
	//
	// Every finding is a typed struct. Filter, group, or route them
	// however your application needs — no jq required.

	if len(assessment.Findings) > 0 {
		fmt.Println("Step 3: Findings")
		for i, f := range assessment.Findings {
			fmt.Printf("  %d. [%s] %s on %s\n", i+1, f.Severity, f.ControlID, f.AssetID)
			if i >= 9 {
				remaining := len(assessment.Findings) - 10
				if remaining > 0 {
					fmt.Printf("  ... and %d more\n", remaining)
				}
				break
			}
		}
		fmt.Println()
	}

	// ── Step 4: Score ────────────────────────────────────────────
	//
	// Compute a 0–100 posture score from the assessment. The score
	// weights findings by severity and control classification.

	fmt.Println("Step 4: Score")
	sr, err := stave.Score(ctx, stave.ScoreConfig{Assessment: assessment})
	if err != nil {
		fmt.Fprintf(os.Stderr, "score: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  posture: %.0f/100 (%s)\n", sr.Score, sr.RubricBand)
	fmt.Println()

	// ── Done ─────────────────────────────────────────────────────
	//
	// From here the caller owns the data. Send findings to Slack,
	// write a Confluence page, update a dashboard, gate a deploy —
	// whatever your workflow needs. Stave's job is done.

	fmt.Println("Done. The Assessment, Findings, and Score are typed Go values.")
	fmt.Println("Route them to your own side effects — no CLI or JSON involved.")

	if assessment.Status != stave.StatusCompliant {
		os.Exit(3)
	}
}
