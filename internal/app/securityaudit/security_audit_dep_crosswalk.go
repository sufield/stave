package securityaudit

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

type defaultCrosswalkResolver struct {
	readFile func(path string) ([]byte, error)
	resolve  func(raw []byte, frameworks, checkIDs []string, now time.Time) (CrosswalkResult, error)
	statFile func(string) (fs.FileInfo, error)
}

func (d defaultCrosswalkResolver) Resolve(
	_ context.Context,
	req SecurityAuditRequest,
	checkIDs []string,
) (crosswalkSnapshot, error) {
	root, err := findRepoRootWith(req.Cwd, func() (string, error) { return req.Cwd, nil }, d.statFile)
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
	return crosswalkSnapshot(result), nil
}
