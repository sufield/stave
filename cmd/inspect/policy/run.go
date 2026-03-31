package policy

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	s3policy "github.com/sufield/stave/internal/core/s3/policy"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// PolicyReport is the output of the policy inspector.
type PolicyReport struct {
	Assessment  s3policy.Assessment          `json:"assessment"`
	PrefixScope s3policy.PrefixScopeAnalysis `json:"prefix_scope"`
	Risk        risk.Report                  `json:"risk"`
	RequiredIAM []string                     `json:"required_iam_actions"`
}

// Analyze parses a policy document and produces a comprehensive report.
func Analyze(input []byte, resolver risk.PermissionResolver) (PolicyReport, error) {
	doc, err := s3policy.Parse(string(input))
	if err != nil {
		return PolicyReport{}, fmt.Errorf("parse policy: %w", err)
	}

	return PolicyReport{
		Assessment:  doc.Assess(),
		PrefixScope: doc.AnalyzeScopes(),
		Risk:        s3policy.NewEvaluator(nil, resolver).Evaluate(doc),
		RequiredIAM: s3policy.MinimumS3IngestIAMActions(),
	}, nil
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		return fsutil.ReadFileLimited(file)
	}
	return io.ReadAll(stdin)
}
