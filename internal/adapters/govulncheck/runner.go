// Package govulncheck provides a concrete VulnerabilityScanner that executes
// the govulncheck binary via os/exec.
package govulncheck

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
)

// Run executes "govulncheck -json ./..." in cwd and returns its combined
// output. The function returns the captured output ALONGSIDE any error,
// rather than discarding it on a non-zero exit. govulncheck signals
// "vulnerabilities found" via a non-zero exit code while still emitting
// the full JSON report on stdout — the earlier shape silently dropped
// every finding because the error path returned (nil, err). Callers
// that received an `*exec.ExitError` should still parse the output as
// a valid vulnerability report; non-ExitError failures (binary
// missing, ctx cancellation, IO failure) indicate a tool/execution
// problem and the output is undefined.
func Run(ctx context.Context, cwd string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = cwd
	output, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			// Findings reported via non-zero exit. Output is the
			// JSON vulnerability report; surface both so callers
			// can parse the report and still know there were
			// findings (or that govulncheck itself failed if the
			// JSON is malformed).
			return output, fmt.Errorf("govulncheck reported issues: %w", err)
		}
		return output, fmt.Errorf("govulncheck: %w", err)
	}
	// Subprocess-boundary contract (bug-1 class): exit 0 from
	// govulncheck means "no vulnerabilities found" — but the JSON
	// report is still expected on stdout (header + scan metadata
	// even when findings are empty). Empty output under exit 0 is
	// a contract violation by the binary; surface it as an error
	// rather than letting the caller's JSON parse silently fail
	// later or, worse, record an empty report as "clean."
	if len(output) == 0 {
		return nil, errors.New("govulncheck exited 0 but produced no output (expected JSON report)")
	}
	return output, nil
}
