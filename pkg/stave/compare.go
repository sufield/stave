package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appcompare "github.com/sufield/stave/internal/app/compare"
	"github.com/sufield/stave/internal/app/remediationimpact"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// CompareFrameworks analyzes the compliance gap between a baseline and a
// target framework given a `stave apply` assessment (JSON with findings)
// and renders the result in the requested format ("json", "markdown", or
// "table"/""). generatedAt stamps the report. Parse failures and
// unsupported formats wrap [ErrInvalidInput]. It is the library entry
// point behind `stave compare`.
func CompareFrameworks(generatedAt time.Time, from, to string, assessmentData []byte, format string) ([]byte, error) {
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if err := json.Unmarshal(assessmentData, &assessment); err != nil {
		return nil, fmt.Errorf("parse assessment: %w: %w", err, ErrInvalidInput)
	}

	result := appcompare.Analyze(appcompare.Input{
		GeneratedAt:  generatedAt.Format(time.RFC3339),
		BaselineName: from,
		TargetName:   to,
		BaselineKey:  from,
		TargetKey:    to,
		Findings:     assessment.Findings,
	})

	var buf bytes.Buffer
	switch format {
	case "json":
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return nil, fmt.Errorf("render output: %w", err)
		}
	case "markdown":
		appcompare.WriteMarkdown(&buf, result)
	case "table", "":
		appcompare.WriteTable(&buf, result)
	default:
		return nil, fmt.Errorf("unsupported format %q (expected: table | json | markdown): %w", format, ErrInvalidInput)
	}
	return buf.Bytes(), nil
}

// CompareRemediationImpact loads a before and an after assessment
// artifact and renders the remediation-impact analysis as indented JSON.
// Load and analysis failures wrap [ErrInvalidInput]. It is the library
// entry point behind `stave compare --mode remediation`.
func CompareRemediationImpact(ctx context.Context, beforePath, afterPath string) ([]byte, error) {
	loader := artifact.NewLoader()

	before, err := loader.Evaluation(ctx, beforePath)
	if err != nil {
		return nil, fmt.Errorf("load before assessment: %w: %w", err, ErrInvalidInput)
	}

	after, err := loader.Evaluation(ctx, afterPath)
	if err != nil {
		return nil, fmt.Errorf("load after assessment: %w: %w", err, ErrInvalidInput)
	}

	result, err := remediationimpact.Analyze(remediationimpact.Input{
		Before: before,
		After:  after,
	})
	if err != nil {
		return nil, fmt.Errorf("analyze remediation impact: %w: %w", err, ErrInvalidInput)
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return nil, fmt.Errorf("encode remediation impact: %w", err)
	}
	return buf.Bytes(), nil
}
