package kernel

import (
	"encoding/json"
	"testing"
)

func TestNewControlID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "valid CTL prefix", input: "CTL.S3.PUBLIC.001"},
		{name: "multi-segment CTL", input: "CTL.S3.PUBLIC.LIST.001"},
		{name: "invalid format", input: "invalid", wantErr: true},
		{name: "wrong prefix", input: "FOO.S3.PUBLIC.001", wantErr: true},
		{name: "INV prefix rejected", input: "INV.S3.PUBLIC.001", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewControlID(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewControlID(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestControlIDSegments(t *testing.T) {
	tests := []struct {
		name         string
		id           ControlID
		wantProvider string
		wantCategory string
		wantSequence string
	}{
		{
			name:         "standard three-segment",
			id:           ControlID("CTL.S3.PUBLIC.001"),
			wantProvider: "S3",
			wantCategory: "PUBLIC",
			wantSequence: "001",
		},
		{
			name:         "multi-segment category",
			id:           ControlID("CTL.S3.PUBLIC.READ.001"),
			wantProvider: "S3",
			wantCategory: "PUBLIC.READ",
			wantSequence: "001",
		},
		{
			name:         "deep category",
			id:           ControlID("CTL.NETWORK.FIREWALL.INGRESS.005"),
			wantProvider: "NETWORK",
			wantCategory: "FIREWALL.INGRESS",
			wantSequence: "005",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.Provider(); got != tt.wantProvider {
				t.Errorf("Provider() = %q, want %q", got, tt.wantProvider)
			}
			if got := tt.id.Category(); got != tt.wantCategory {
				t.Errorf("Category() = %q, want %q", got, tt.wantCategory)
			}
			if got := tt.id.Sequence(); got != tt.wantSequence {
				t.Errorf("Sequence() = %q, want %q", got, tt.wantSequence)
			}
		})
	}
}

func TestControlIDUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    string
		wantErr bool
	}{
		{name: "CTL prefix", json: `"CTL.S3.PUBLIC.001"`, want: "CTL.S3.PUBLIC.001"},
		{name: "INV prefix rejected", json: `"INV.S3.PUBLIC.001"`, wantErr: true},
		{name: "invalid", json: `"not-an-id"`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id ControlID
			err := json.Unmarshal([]byte(tt.json), &id)
			if (err != nil) != tt.wantErr {
				t.Fatalf("unmarshal error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && id.String() != tt.want {
				t.Fatalf("id = %q, want %q", id.String(), tt.want)
			}
		})
	}
}

func TestControlIDMarshalJSON(t *testing.T) {
	id := ControlID("CTL.S3.PUBLIC.001")
	b, err := json.Marshal(id)
	if err != nil {
		t.Fatalf("marshal error = %v", err)
	}
	if string(b) != `"CTL.S3.PUBLIC.001"` {
		t.Fatalf("got %s, want %q", b, "CTL.S3.PUBLIC.001")
	}
}
