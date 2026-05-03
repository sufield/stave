package apply

import (
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/app/reachability"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// annotateReachability enriches findings with IAM reachability context.
// Runs automatically when the snapshot contains IAM resource policy data.
// No-ops when no IAM data is present or when the observations path is empty.
func annotateReachability(result *evaluation.ComplianceReport, obsDir string) {
	if obsDir == "" || len(result.Findings) == 0 {
		return
	}

	snapshots, err := observations.LoadBundle(obsDir)
	if err != nil || len(snapshots) == 0 {
		return
	}
	snap := &snapshots[len(snapshots)-1]

	idx := iam.BuildResourceAccessIndex(snap)
	if idx == nil {
		return
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
}
