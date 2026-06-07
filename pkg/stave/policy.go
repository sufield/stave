package stave

import (
	"bytes"
	"fmt"

	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	s3policy "github.com/sufield/stave/internal/platform/providers/aws/s3/policy"
	"github.com/sufield/stave/internal/util/jsonutil"
)

type policyReport struct {
	Assessment  s3policy.Assessment          `json:"assessment"`
	PrefixScope s3policy.PrefixScopeAnalysis `json:"prefix_scope"`
	Risk        risk.Report                  `json:"risk"`
	RequiredIAM []string                     `json:"required_iam_actions"`
}

// InspectPolicy parses a raw S3 bucket-policy JSON document and returns a
// comprehensive security analysis — access assessment, prefix-scope
// analysis, risk score, and required IAM actions — as indented JSON
// bytes (no HTML escaping, one trailing newline, matching the prior
// jsonutil output). It builds the default S3 permission resolver
// internally, so it is the library entry point behind
// `stave inspect policy`.
func InspectPolicy(input []byte) ([]byte, error) {
	doc, err := s3policy.Parse(string(input))
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	report := policyReport{
		Assessment:  doc.Assess(),
		PrefixScope: doc.AnalyzeScopes(),
		Risk:        s3policy.NewEvaluator(nil, s3resolver.NewResolver()).Evaluate(doc),
		RequiredIAM: s3policy.MinimumS3IngestIAMActions(),
	}

	var buf bytes.Buffer
	if err := jsonutil.WriteIndented(&buf, report); err != nil {
		return nil, fmt.Errorf("encode policy report: %w", err)
	}
	return buf.Bytes(), nil
}
