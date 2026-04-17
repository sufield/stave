package validator

import (
	"testing"
)

const ccmBaseControl = `dsl_version: ctrl.v1
id: CTL.TEST.CCM.001
name: Test Control
description: Test control with CCM mapping
type: unsafe_state
unsafe_predicate:
  any:
    - field: properties.x
      op: eq
      value: true
`

func ccmControlWith(complianceBlock string) []byte {
	return []byte(ccmBaseControl + "compliance:\n" + complianceBlock)
}

func TestCCMv4_ValidMappings(t *testing.T) {
	v := New()
	cases := []struct {
		name  string
		block string
	}{
		{
			name:  "single valid IAM mapping",
			block: "  ccm_v4:\n    - IAM-05\n",
		},
		{
			name:  "multiple valid mappings across domains",
			block: "  ccm_v4:\n    - IAM-05\n    - CCC-07\n    - DSP-17\n    - CEK-03\n    - LOG-12\n",
		},
		{
			name:  "A&A domain prefix",
			block: "  ccm_v4:\n    - A&A-01\n",
		},
		{
			name:  "empty list is accepted",
			block: "  ccm_v4: []\n",
		},
		{
			name:  "mixed with existing framework mappings",
			block: "  hipaa: \"164.312(a)(1)\"\n  ccm_v4:\n    - IAM-05\n",
		},
		{
			name:  "all allowed prefixes",
			block: "  ccm_v4:\n    - AIS-01\n    - A&A-01\n    - BCR-01\n    - CCC-01\n    - CEK-01\n    - DCS-01\n    - DSP-01\n    - GRC-01\n    - HRS-01\n    - IAM-01\n    - IPY-01\n    - IVS-01\n    - LOG-01\n    - SEF-01\n    - STA-01\n    - TVM-01\n    - UEM-01\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := v.ValidateControlYAML(ccmControlWith(tc.block))
			if err != nil {
				t.Fatalf("validate error: %v", err)
			}
			if result.Failed() {
				t.Errorf("valid mapping %q rejected:\n%s", tc.name, result)
			}
		})
	}
}

func TestCCMv4_AbsentFieldAccepted(t *testing.T) {
	v := New()
	// No compliance block at all.
	result, err := v.ValidateControlYAML([]byte(ccmBaseControl))
	if err != nil {
		t.Fatalf("validate error: %v", err)
	}
	if result.Failed() {
		t.Errorf("control without compliance block rejected:\n%s", result)
	}
}

func TestCCMv4_InvalidMappings(t *testing.T) {
	v := New()
	cases := []struct {
		name  string
		block string
	}{
		{
			name:  "unknown prefix XXX",
			block: "  ccm_v4:\n    - XXX-05\n",
		},
		{
			name:  "lowercase prefix",
			block: "  ccm_v4:\n    - iam-05\n",
		},
		{
			name:  "underscore separator",
			block: "  ccm_v4:\n    - IAM_05\n",
		},
		{
			name:  "missing zero-padding single digit",
			block: "  ccm_v4:\n    - IAM-5\n",
		},
		{
			name:  "three-digit number",
			block: "  ccm_v4:\n    - IAM-005\n",
		},
		{
			name:  "string not list",
			block: "  ccm_v4: IAM-05\n",
		},
		{
			name:  "number not list",
			block: "  ccm_v4: 5\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := v.ValidateControlYAML(ccmControlWith(tc.block))
			if err != nil {
				t.Fatalf("validate error: %v", err)
			}
			if !result.Failed() {
				t.Errorf("invalid mapping %q accepted:\n%s", tc.name, result)
			}
		})
	}
}

func TestCCMv4_AllAllowedPrefixesRoundTrip(t *testing.T) {
	prefixes := []string{"AIS", "A&A", "BCR", "CCC", "CEK", "DCS", "DSP", "GRC", "HRS", "IAM", "IPY", "IVS", "LOG", "SEF", "STA", "TVM", "UEM"}
	v := New()
	for _, p := range prefixes {
		id := p + "-09"
		t.Run(id, func(t *testing.T) {
			block := "  ccm_v4:\n    - " + id + "\n"
			result, err := v.ValidateControlYAML(ccmControlWith(block))
			if err != nil {
				t.Fatalf("validate error: %v", err)
			}
			if result.Failed() {
				t.Errorf("prefix %q rejected:\n%s", p, result)
			}
		})
	}
}
