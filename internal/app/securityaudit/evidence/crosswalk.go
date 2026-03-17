package evidence

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"time"
)

type DefaultCrosswalkResolver struct {
	ReadFile  func(path string) ([]byte, error)
	ResolveFn func(raw []byte, frameworks, checkIDs []string, now time.Time) (CrosswalkResult, error)
	StatFile  func(string) (fs.FileInfo, error)
}

func (d DefaultCrosswalkResolver) Resolve(
	_ context.Context,
	req Params,
	checkIDs []string,
) (CrosswalkSnapshot, error) {
	root, err := findRepoRootWith(req.Cwd, func() (string, error) { return req.Cwd, nil }, d.StatFile)
	if err != nil {
		return CrosswalkSnapshot{}, err
	}
	path := filepath.Join(root, "internal", "contracts", "security", "control_crosswalk.v1.yaml")
	raw, err := d.ReadFile(path)
	if err != nil {
		return CrosswalkSnapshot{}, fmt.Errorf("read crosswalk file: %w", err)
	}
	result, err := d.ResolveFn(raw, req.ComplianceFrameworks, checkIDs, req.Now.UTC())
	if err != nil {
		return CrosswalkSnapshot{}, err
	}
	return CrosswalkSnapshot(result), nil
}
