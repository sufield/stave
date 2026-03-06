package securityaudit

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type defaultCrosswalkResolver struct{}

func (defaultCrosswalkResolver) Resolve(
	_ context.Context,
	req SecurityAuditRequest,
	checkIDs []string,
) (crosswalkSnapshot, error) {
	root, err := findRepoRoot(req.Cwd)
	if err != nil {
		return crosswalkSnapshot{}, err
	}
	path := filepath.Join(root, "internal", "contracts", "security", "control_crosswalk.v1.yaml")
	raw, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return crosswalkSnapshot{}, fmt.Errorf("read crosswalk file: %w", err)
	}
	resolved, err := compliance.ResolveControlCrosswalk(
		raw,
		req.ComplianceFrameworks,
		checkIDs,
		req.Now.UTC(),
	)
	if err != nil {
		return crosswalkSnapshot{}, err
	}

	return crosswalkSnapshot{
		ByCheck:        resolved.ByCheck,
		MissingChecks:  resolved.MissingChecks,
		ResolutionJSON: resolved.ResolutionJSON,
	}, nil
}
