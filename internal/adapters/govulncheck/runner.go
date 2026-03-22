// Package govulncheck provides a concrete VulnerabilityScanner that executes
// the govulncheck binary via os/exec.
package govulncheck

import (
	"context"
	"fmt"
	"os/exec"
)

// Run executes "govulncheck -json ./..." in cwd and returns its combined output.
func Run(ctx context.Context, cwd string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = cwd
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("govulncheck: %w", err)
	}
	return output, nil
}
