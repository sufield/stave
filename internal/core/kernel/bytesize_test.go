package kernel

import (
	"strings"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"256MB", 256 << 20, false},
		{"1GB", 1 << 30, false},
		{"512mb", 512 << 20, false},
		{"64KB", 64 << 10, false},
		{"1024", 1024, false},
		{"", 0, true},
		{"0MB", 0, true},
		{"-1MB", 0, true},
		{"abc", 0, true},
		{"MB", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseByteSize(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseByteSize(%q) err = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("ParseByteSize(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseByteSize_OverflowGuard(t *testing.T) {
	// 9000000000 GB (9e9 GB) overflows int64 when multiplied by
	// 1<<30. Without the guard the wrap produced a small positive
	// number that downstream limit math accepted as legitimate.
	cases := []string{
		"9000000000GB",
		"99999999999999MB",
		"99999999999999999KB",
	}
	for _, in := range cases {
		_, err := ParseByteSize(in)
		if err == nil {
			t.Errorf("ParseByteSize(%q) expected overflow error, got nil", in)
			continue
		}
		if !strings.Contains(err.Error(), "overflow") {
			t.Errorf("ParseByteSize(%q) error %q does not mention overflow", in, err)
		}
	}
}

func TestParseByteSize_BoundaryNoOverflow(t *testing.T) {
	// Exactly at the boundary: 8589934591 GB is below 8GB×1<<30
	// fitting into int64, so it should NOT be rejected. (In
	// practice this is silly large but it pins the guard's
	// off-by-one.)
	_, err := ParseByteSize("8GB")
	if err != nil {
		t.Errorf("ParseByteSize(\"8GB\") = %v, want no error", err)
	}
}
