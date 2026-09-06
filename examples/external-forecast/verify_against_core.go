//go:build ignore

// Command verify_against_core reads the same input.json the
// Python script consumes, runs the same internal/app/forecast.Compute
// the Stave binary uses, and writes core.json. The example's run.sh
// then diffs external.json vs core.json to prove the Python port
// is byte-identical to core (modulo float-formatting tolerance).
//
// Build-ignored so this file never participates in normal `go build`.
// Run with `go run verify_against_core.go input.json output.json`.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sufield/stave/internal/app/forecast"
	policy "github.com/sufield/stave/internal/core/controldef"
)

type inputShape struct {
	ScoreHistory      []float64            `json:"score_history"`
	HorizonDays       int                  `json:"horizon_days"`
	SLADeadlinesHours map[string]float64   `json:"sla_deadlines_hours"`
	MTTRHistoryHours  map[string][]float64 `json:"mttr_history_hours"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <input.json> <output.json>\n", os.Args[0])
		os.Exit(2)
	}
	inData, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input: %v\n", err)
		os.Exit(1)
	}
	var in inputShape
	if err := json.Unmarshal(inData, &in); err != nil {
		fmt.Fprintf(os.Stderr, "parse input: %v\n", err)
		os.Exit(1)
	}

	slaDeadlines := map[policy.Severity]float64{}
	for k, v := range in.SLADeadlinesHours {
		sev, _ := policy.ParseSeverity(k)
		slaDeadlines[sev] = v
	}
	mttrHistory := map[policy.Severity][]float64{}
	for k, v := range in.MTTRHistoryHours {
		sev, _ := policy.ParseSeverity(k)
		mttrHistory[sev] = v
	}

	result, err := forecast.Compute(forecast.Input{
		ScoreHistory: in.ScoreHistory,
		HorizonDays:  in.HorizonDays,
		SLADeadlines: slaDeadlines,
		MTTRHistory:  mttrHistory,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "forecast.Compute: %v\n", err)
		os.Exit(1)
	}
	outBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(os.Args[2], append(outBytes, '\n'), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write output: %v\n", err)
		os.Exit(1)
	}
}
