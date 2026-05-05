package apply

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/app/reachability"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// reachabilityBundleName is the conventional bundle-file name the
// apply pipeline looks for inside an observations directory.
// Mirrors the fixture-tree convention seen in
// testdata/e2e/*/observations.json.
const reachabilityBundleName = "observations.json"

// annotateReachability enriches findings with IAM reachability context.
//
// Two-stage migration: the function previously called LoadBundle on
// the observations DIRECTORY, which always errored (LoadBundle
// expects a FILE) and the failure was silently swallowed — every
// reachability annotation became a no-op. This shape derives the
// bundle file from the directory and distinguishes "bundle missing"
// (legitimate no-op for legacy fixtures) from "bundle malformed"
// (real failure that surfaces as an error).
//
// FOLLOW-UP: once every test fixture that hits the missing-file
// branch has been updated to ship an observations.json, drop the
// errors.Is(err, os.ErrNotExist) branch so a missing bundle hard-
// fails the apply pipeline instead of silently no-oping.
func annotateReachability(result *evaluation.ComplianceReport, obsDir string) error {
	if obsDir == "" || len(result.Findings) == 0 {
		return nil
	}
	// Stdin mode (`-o -`) carries no observation file on disk, so
	// joining "observations.json" against `-` and probing the
	// filesystem is meaningless — the path-join below would produce
	// `-/observations.json` and rely on the os.ErrNotExist branch
	// further down to silently skip. Bail out explicitly so the
	// stdin contract is visible in this file rather than depending
	// on the implicit not-found fall-through.
	if obsDir == "-" {
		slog.Debug("annotate reachability: stdin observation mode; skipping bundle lookup",
			"obs_dir", obsDir)
		return nil
	}

	bundlePath := filepath.Join(obsDir, reachabilityBundleName)

	snapshots, err := observations.LoadBundle(bundlePath)
	if err != nil {
		// Missing bundle is the legacy fixture path — log so the
		// untracked fixtures surface in -v mode and can be
		// migrated incrementally, but don't break the pipeline.
		// Anything else is a real load failure (malformed JSON,
		// permission, IO) that the caller must see.
		if errors.Is(err, os.ErrNotExist) {
			slog.Debug("annotate reachability: no bundle file in observations dir; skipping",
				"obs_dir", obsDir, "bundle_name", reachabilityBundleName)
			return nil
		}
		return fmt.Errorf("annotate reachability: malformed bundle at %q: %w", bundlePath, err)
	}
	if len(snapshots) == 0 {
		return nil
	}
	snap := &snapshots[len(snapshots)-1]

	idx := iam.BuildResourceAccessIndex(snap)
	if idx == nil {
		return nil
	}

	// Wrap evaluation findings for the annotation API.
	remFindings := make([]remediation.Finding, len(result.Findings))
	for i := range result.Findings {
		remFindings[i] = remediation.Finding{Finding: result.Findings[i]}
	}

	reachability.AnnotateFindings(remFindings, idx)

	// Copy reachability back.
	for i := range remFindings {
		result.Findings[i].Reachability = remFindings[i].Reachability
	}
	return nil
}
