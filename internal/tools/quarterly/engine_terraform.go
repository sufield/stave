package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

type terraformEngine struct{}

func (e *terraformEngine) Name() string { return "terraform" }

func (e *terraformEngine) Run(ctx context.Context) (*EngineResult, error) {
	start := time.Now()

	script := "tools/tf-schema-diff/diff.py"
	if _, err := os.Stat(script); err != nil {
		return &EngineResult{
			Engine:   "terraform",
			Duration: time.Since(start),
			Error:    "tools/tf-schema-diff/diff.py not found",
		}, nil
	}

	schemaPath := os.Getenv("TF_SCHEMA_PATH")
	if schemaPath == "" {
		schemaPath = "/tmp/tf-aws-schema.json"
	}

	if _, err := os.Stat(schemaPath); err != nil {
		return &EngineResult{
			Engine:   "terraform",
			Duration: time.Since(start),
			Error:    fmt.Sprintf("terraform schema not found at %s — run: terraform providers schema -json > %s", schemaPath, schemaPath),
		}, nil
	}

	out, err := exec.CommandContext(ctx, "python3", script, schemaPath, "--json").Output() //nolint:gosec // script path is hardcoded
	if err != nil {
		return &EngineResult{
			Engine:   "terraform",
			Duration: time.Since(start),
			Error:    fmt.Sprintf("tf-schema-diff failed: %v", err),
		}, nil
	}

	gaps, total, covered, parseErr := parseTerraformOutput(out)
	if parseErr != nil {
		return &EngineResult{
			Engine:   "terraform",
			Duration: time.Since(start),
			Error:    fmt.Sprintf("parse tf-schema-diff output: %v", parseErr),
		}, nil
	}

	return &EngineResult{
		Engine:       "terraform",
		GapsFound:    gaps,
		Covered:      covered,
		TotalChecked: total,
		Duration:     time.Since(start),
		DataSource:   "terraform aws provider schema",
	}, nil
}

type tfDiffOutput struct {
	Total   int `json:"total_security_args"`
	Covered int `json:"covered"`
	Gaps    []struct {
		Resource string `json:"resource"`
		Arg      string `json:"argument"`
		Type     string `json:"type"`
	} `json:"uncovered"`
}

func parseTerraformOutput(data []byte) (gaps []Gap, total, covered int, err error) {
	var out tfDiffOutput
	if err = json.Unmarshal(data, &out); err != nil {
		return nil, 0, 0, err
	}

	for _, g := range out.Gaps {
		gaps = append(gaps, Gap{
			Service:    g.Resource,
			Property:   g.Arg,
			Severity:   "Medium",
			Source:     "terraform",
			Confidence: "Medium",
		})
	}
	return gaps, out.Total, out.Covered, nil
}
