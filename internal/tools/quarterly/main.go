// Command quarterly runs all gap discovery engines and produces
// a consolidated report with cross-engine deduplication and
// quarter-over-quarter diff.
//
// Usage:
//
//	go run ./internal/tools/quarterly
//	go run ./internal/tools/quarterly --engine botocore,deprecation
//	go run ./internal/tools/quarterly --json
//	go run ./internal/tools/quarterly --save
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/awsmeta"
)

func main() {
	engineFlag := flag.String("engine", "", "comma-separated engines to run (default: all)")
	jsonOut := flag.Bool("json", false, "output as JSON")
	save := flag.Bool("save", false, "save results as this quarter's baseline")
	diffOnly := flag.Bool("diff-only", false, "only show quarter-over-quarter diff")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	initBotocoreDataDir()

	engines := allEngines()
	if *engineFlag != "" {
		engines = filterEngines(engines, strings.Split(*engineFlag, ","))
	}

	if len(engines) == 0 {
		fmt.Fprintln(os.Stderr, "error: no matching engines")
		os.Exit(2)
	}

	var results []*EngineResult
	for _, eng := range engines {
		fmt.Fprintf(os.Stderr, "Running %s...\n", eng.Name())
		result, err := eng.Run(ctx)
		if err != nil {
			result = &EngineResult{
				Engine: eng.Name(),
				Error:  err.Error(),
			}
		}
		results = append(results, result)
	}

	multi, single := deduplicateGaps(results)

	totalRaw := 0
	for _, r := range results {
		totalRaw += len(r.GapsFound)
	}

	report := &AuditReport{
		Quarter:      currentQuarter(),
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Engines:      make([]EngineResult, len(results)),
		MultiEngine:  multi,
		SingleEngine: single,
		TotalRaw:     totalRaw,
		TotalDeduped: len(multi) + len(single),
	}
	for i, r := range results {
		report.Engines[i] = *r
	}

	previous := loadPreviousReport()
	report.Diff = computeDiff(report, previous)

	if *diffOnly {
		if report.Diff == nil {
			fmt.Println("No previous quarter data.")
		} else {
			fmt.Print(formatQuarterDiff(report.Diff))
		}
		return
	}

	if *jsonOut {
		writeJSONReport(report)
	} else {
		writeTextReport(report)
	}

	if *save {
		if err := saveReport(report); err != nil {
			fmt.Fprintf(os.Stderr, "error saving report: %v\n", err)
			os.Exit(1)
		}
	}
}

func initBotocoreDataDir() {
	if os.Getenv("BOTOCORE_DATA") != "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "python3", "-c", //nolint:gosec // fixed command, not user input
		"import botocore; print(botocore.__path__[0]+'/data')").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot locate botocore: %v\n", err)
		return
	}
	awsmeta.SetDataDir(strings.TrimSpace(string(out)))
}
