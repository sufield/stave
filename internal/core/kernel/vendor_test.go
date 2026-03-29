package kernel

import (
	"encoding/json"
	"testing"
)

func TestVendor_String(t *testing.T) {
	tests := []struct {
		v    Vendor
		want string
	}{
		{Vendor("aws"), "aws"},
		{Vendor("gcp"), "gcp"},
		{Vendor(""), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("Vendor(%q).String() = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestNewVendor(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Vendor
		wantErr bool
	}{
		{"lowercase", "aws", Vendor("aws"), false},
		{"uppercase normalized", "AWS", Vendor("aws"), false},
		{"trimmed", "  gcp  ", Vendor("gcp"), false},
		{"empty rejected", "", Vendor(""), true},
		{"whitespace-only rejected", "   ", Vendor(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewVendor(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("NewVendor(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestVendor_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Vendor
		wantErr bool
	}{
		{"lowercase", `"aws"`, Vendor("aws"), false},
		{"uppercase", `"AWS"`, Vendor("aws"), false},
		{"empty", `""`, Vendor(""), true},
		{"invalid json", `123`, Vendor(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v Vendor
			err := json.Unmarshal([]byte(tt.input), &v)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v != tt.want {
				t.Errorf("got %q, want %q", v, tt.want)
			}
		})
	}
}

func TestVendor_MarshalJSON(t *testing.T) {
	v := Vendor("aws")
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != `"aws"` {
		t.Errorf("MarshalJSON = %s, want %q", data, "aws")
	}

	// Empty vendor marshals as "unknown".
	empty := Vendor("")
	data, err = json.Marshal(empty)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if string(data) != `"unknown"` {
		t.Errorf("MarshalJSON(empty) = %s, want %q", data, "unknown")
	}
}

func TestVendor_JSONRoundTrip(t *testing.T) {
	v := Vendor("azure")
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var got Vendor
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if got != v {
		t.Errorf("round-trip: got %q, want %q", got, v)
	}
}
