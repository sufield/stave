package stave

import (
	"bytes"
	"testing"
)

// TestContractRenderers_HandleBothPayloadTypes covers the contract
// writers that moved here from cmd/contract: the JSON writer accepts both
// report shapes, and each text writer renders its own report shape
// non-empty.
func TestContractRenderers_HandleBothPayloadTypes(t *testing.T) {
	typeRep := contractTypeReport{AssetType: "aws_s3_bucket"}
	listRep := contractListReport{TotalTypes: 0}

	cases := []struct {
		name string
		fn   func(w *bytes.Buffer) error
	}{
		{"json+type", func(w *bytes.Buffer) error { return writeContractJSON(w, typeRep) }},
		{"json+list", func(w *bytes.Buffer) error { return writeContractJSON(w, listRep) }},
		{"text+type", func(w *bytes.Buffer) error { return writeContractTypeText(w, typeRep) }},
		{"text+list", func(w *bytes.Buffer) error { return writeContractListText(w, listRep) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.fn(&buf); err != nil {
				t.Fatalf("render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("render produced empty output")
			}
		})
	}
}
