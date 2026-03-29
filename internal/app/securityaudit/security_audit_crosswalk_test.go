package securityaudit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/internal/app/securityaudit/evidence"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/core/securityaudit"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func TestSecurityAuditCrosswalk_Completeness(t *testing.T) {
	root := repoRootForTest(t)
	resolver := evidence.DefaultCrosswalkResolver{
		ReadFile: fsutil.ReadFileLimited,
		ResolveFn: func(raw []byte, frameworks, checkIDs []string, now time.Time) (evidence.CrosswalkResult, error) {
			resolved, err := compliance.ResolveControlCrosswalk(raw, frameworks, checkIDs, now)
			if err != nil {
				return evidence.CrosswalkResult{}, err
			}
			return evidence.CrosswalkResult{
				ByCheck:        resolved.ByCheck,
				MissingChecks:  resolved.MissingChecks,
				ResolutionJSON: resolved.ResolutionJSON,
			}, nil
		},
		StatFile: os.Stat,
	}
	allIDs := securityaudit.AllCheckIDs()
	checkIDStrings := make([]string, len(allIDs))
	for i, id := range allIDs {
		checkIDStrings[i] = string(id)
	}

	resolved, err := resolver.Resolve(context.Background(), evidence.Params{
		Cwd:                  root,
		ComplianceFrameworks: compliance.FrameworkStrings(compliance.SupportedFrameworks()),
	}, checkIDStrings)
	if err != nil {
		t.Fatalf("resolve crosswalk: %v", err)
	}
	if len(resolved.MissingChecks) > 0 {
		t.Fatalf("crosswalk missing check mappings: %v", resolved.MissingChecks)
	}
	for _, checkID := range allIDs {
		refs := resolved.ByCheck[string(checkID)]
		if len(refs) == 0 {
			t.Fatalf("check %s resolved to zero control refs", checkID)
		}
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found while resolving repo root")
		}
		dir = parent
	}
}
