package asff

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// TestMarshalASFF_NilAssessment covers the empty-input shortcut.
func TestMarshalASFF_NilAssessment(t *testing.T) {
	got, err := MarshalASFF(nil)
	if err != nil {
		t.Fatalf("MarshalASFF(nil) err = %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("nil assessment output = %q, want []", string(got))
	}
}

// TestMarshalASFF_ChainFindings exercises the chain-mapping branch
// rewritten when the asff package's risk dependency was dropped.
// Asserts:
//   - chain entries appear in the output
//   - Description prefers Narrative when present
//   - Description falls back to chain.Description when Narrative empty
//   - Severity label + normalized value derived from cf.Severity
//   - ChainId / CompoundScore appear in ProductFields
//
// risk.CompoundFinding is named here in test setup to populate
// report.Assessment fixtures — production code no longer names it.
func TestMarshalASFF_ChainFindings(t *testing.T) {
	assessment := &report.Assessment{
		ChainFindings: []risk.CompoundFinding{
			{
				ChainID:       kernel.ChainID("chain.capital-one"),
				AssetID:       asset.ID("arn:aws:s3:::data-bucket"),
				Severity:      policy.SeverityCritical,
				CompoundScore: 95.5,
				Narrative:     "Public bucket policy + role assumption path + logging disabled",
				Description:   "Falls back when Narrative empty",
			},
			{
				ChainID:       kernel.ChainID("chain.fallback"),
				AssetID:       asset.ID("arn:aws:s3:::other-bucket"),
				Severity:      policy.SeverityHigh,
				CompoundScore: 70.0,
				Narrative:     "", // empty — exercise Description fallback
				Description:   "Static chain definition text",
			},
		},
	}

	data, err := MarshalASFF(assessment)
	if err != nil {
		t.Fatalf("MarshalASFF err = %v", err)
	}

	var got []ASFFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, string(data))
	}
	if len(got) != 2 {
		t.Fatalf("findings = %d, want 2 (chain entries only — no Findings supplied)", len(got))
	}

	byID := map[string]ASFFinding{}
	for _, f := range got {
		byID[f.ID] = f
	}

	// Narrative-preferred branch.
	cap1 := byID["stave/chain/chain.capital-one"]
	if !strings.Contains(cap1.Description, "Public bucket policy") {
		t.Errorf("capital-one Description = %q, want Narrative text", cap1.Description)
	}
	if cap1.Severity.Label != "critical" || cap1.Severity.Normalized != 90 {
		t.Errorf("capital-one severity = %+v, want critical/90", cap1.Severity)
	}
	if cap1.ProductFields["ChainId"] != "chain.capital-one" {
		t.Errorf("capital-one ChainId field = %q", cap1.ProductFields["ChainId"])
	}
	if cap1.ProductFields["CompoundScore"] != "95.5" {
		t.Errorf("capital-one CompoundScore field = %q, want 95.5", cap1.ProductFields["CompoundScore"])
	}

	// Description-fallback branch.
	fb := byID["stave/chain/chain.fallback"]
	if fb.Description != "Static chain definition text" {
		t.Errorf("fallback Description = %q, want Description-text fallback", fb.Description)
	}
	if fb.Severity.Label != "high" || fb.Severity.Normalized != 70 {
		t.Errorf("fallback severity = %+v, want high/70", fb.Severity)
	}
}
