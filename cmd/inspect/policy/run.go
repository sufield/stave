package policy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	s3resolver "github.com/sufield/stave/internal/adapters/aws/s3"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	s3policy "github.com/sufield/stave/pkg/alpha/domain/s3/policy"
)

// PolicyReport is the output of the policy inspector.
type PolicyReport struct {
	Assessment  s3policy.Assessment          `json:"assessment"`
	PrefixScope s3policy.PrefixScopeAnalysis `json:"prefix_scope"`
	Risk        risk.Report                  `json:"risk"`
	RequiredIAM []string                     `json:"required_iam_actions"`
}

func run(cmd *cobra.Command, file string) error {
	input, err := readInput(file, cmd.InOrStdin())
	if err != nil {
		return err
	}

	doc, err := s3policy.Parse(string(input))
	if err != nil {
		return fmt.Errorf("parse policy: %w", err)
	}

	report := PolicyReport{
		Assessment:  doc.Assess(),
		PrefixScope: doc.PrefixScopeAnalysis(),
		Risk:        s3policy.NewEvaluator(nil, s3resolver.NewResolver()).Evaluate(doc),
		RequiredIAM: s3policy.MinimumS3IngestIAMActions(),
	}

	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		return fsutil.ReadFileLimited(file)
	}
	return io.ReadAll(stdin)
}
