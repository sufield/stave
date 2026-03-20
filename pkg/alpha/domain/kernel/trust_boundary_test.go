package kernel

import (
	"encoding/json"
	"testing"
)

func TestParseTrustBoundary(t *testing.T) {
	tests := []struct {
		in      string
		want    TrustBoundary
		wantErr bool
	}{
		{in: "external", want: BoundaryExternal},
		{in: "cross_account", want: BoundaryCrossAccount},
		{in: "internal", want: BoundaryInternal},
		{in: "unknown", want: BoundaryUnknown},
		{in: "", want: BoundaryUnknown},
		{in: "  External  ", want: BoundaryExternal},
		{in: "INTERNAL", want: BoundaryInternal},
		{in: "public", wantErr: true},
		{in: "bad_value", wantErr: true},
	}

	for _, tt := range tests {
		got, err := ParseTrustBoundary(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("ParseTrustBoundary(%q) error = nil, want error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseTrustBoundary(%q) error = %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseTrustBoundary(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestTrustBoundaryJSON(t *testing.T) {
	var boundary TrustBoundary
	if err := json.Unmarshal([]byte(`"external"`), &boundary); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if boundary != BoundaryExternal {
		t.Fatalf("boundary = %v, want %v", boundary, BoundaryExternal)
	}

	data, err := json.Marshal(BoundaryCrossAccount)
	if err != nil {
		t.Fatalf("json.Marshal error = %v", err)
	}
	if string(data) != `"cross_account"` {
		t.Fatalf("json.Marshal = %s, want %q", data, `"cross_account"`)
	}
}

func TestTrustBoundaryString(t *testing.T) {
	tests := []struct {
		boundary TrustBoundary
		want     string
	}{
		{BoundaryUnknown, "unknown"},
		{BoundaryExternal, "external"},
		{BoundaryCrossAccount, "cross_account"},
		{BoundaryInternal, "internal"},
		{TrustBoundary(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.boundary.String(); got != tt.want {
			t.Errorf("TrustBoundary(%d).String() = %q, want %q", tt.boundary, got, tt.want)
		}
	}
}

func TestTrustBoundaryJSONRoundTrip(t *testing.T) {
	for _, b := range []TrustBoundary{BoundaryUnknown, BoundaryExternal, BoundaryCrossAccount, BoundaryInternal} {
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("Marshal(%v) error = %v", b, err)
		}
		var got TrustBoundary
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal(%s) error = %v", data, err)
		}
		if got != b {
			t.Errorf("round-trip: got %v, want %v", got, b)
		}
	}
}
