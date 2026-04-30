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
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Findings reported via non-zero exit. Output is the
			// JSON vulnerability report; surface both so callers
			// can parse the report and still know there were
			// findings (or that govulncheck itself failed if the
			// JSON is malformed).
			return output, fmt.Errorf("govulncheck reported issues: %w", err)
		}
		return output, fmt.Errorf("govulncheck: %w", err)
	}
	return output, nil
}
