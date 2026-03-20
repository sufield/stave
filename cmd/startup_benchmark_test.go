package cmd

import (
	"testing"
	"time"
)

// StartupTarget is the aspirational startup budget for light-weight commands.
// This benchmark is informational (not a hard CI gate).
const StartupTarget = 500 * time.Millisecond

func BenchmarkCLIStartupHelp(b *testing.B) {
	for i := 0; i < b.N; i++ {
		root := getRootCmd()
		root.SetArgs([]string{"--help"})
		start := time.Now()
		if _, err := root.ExecuteC(); err != nil {
			b.Fatalf("execute --help: %v", err)
		}
		elapsed := time.Since(start)
		b.ReportMetric(float64(elapsed.Microseconds()), "startup-us")
	}
}
