package securityaudit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

type defaultCrosswalkResolver struct {
	readFile func(path string) ([]byte, error)
	resolve  func(raw []byte, frameworks, checkIDs []string, now time.Time) (CrosswalkResult, error)
}

func (d defaultCrosswalkResolver) Resolve(
	_ context.Context,
	req SecurityAuditRequest,
	checkIDs []string,
) (crosswalkSnapshot, error) {
	root, err := findRepoRoot(req.Cwd)
	if err != nil {
		return crosswalkSnapshot{}, err
	}
	path := filepath.Join(root, "internal", "contracts", "security", "control_crosswalk.v1.yaml")
	raw, err := d.readFile(path)
	if err != nil {
		return crosswalkSnapshot{}, fmt.Errorf("read crosswalk file: %w", err)
	}
	result, err := d.resolve(raw, req.ComplianceFrameworks, checkIDs, req.Now.UTC())
	if err != nil {
		return crosswalkSnapshot{}, err
	}
	return crosswalkSnapshot{
		ByCheck:        result.ByCheck,
		MissingChecks:  result.MissingChecks,
		ResolutionJSON: result.ResolutionJSON,
	}, nil
}
