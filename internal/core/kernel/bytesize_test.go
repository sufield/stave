package kernel

import "testing"

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
