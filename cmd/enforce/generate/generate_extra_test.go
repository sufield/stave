package generate

import (
	"testing"

	"github.com/sufield/stave/internal/platform/fileout"
)

func TestParseMode_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  Mode
	}{
		{"pab", ModePAB},
		{"scp", ModeSCP},
		{"PAB", ModePAB},
		{"SCP", ModeSCP},
		{" pab ", ModePAB},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.input)
		if err != nil {
			t.Errorf("ParseMode(%q) error = %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseMode(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestParseMode_Invalid(t *testing.T) {
	_, err := ParseMode("terraform")
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestModeString(t *testing.T) {
	if ModePAB.String() != "pab" {
		t.Fatalf("String() = %q", ModePAB.String())
	}
	if ModeSCP.String() != "scp" {
		t.Fatalf("String() = %q", ModeSCP.String())
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := defaultOptions()
	if opts.OutDir != "output" {
		t.Fatalf("OutDir = %q", opts.OutDir)
	}
	if opts.ModeRaw != "pab" {
		t.Fatalf("ModeRaw = %q", opts.ModeRaw)
	}
}

func TestTargetNames(t *testing.T) {
	names := targetNames(nil)
	if len(names) != 0 {
		t.Fatalf("expected 0 targets, got %d", len(names))
	}
}

func TestNewRunner(t *testing.T) {
	r := NewRunner(fileout.FileOptions{
		Overwrite: false,
		DirPerms:  0o700,
	})
	if r == nil {
		t.Fatal("expected non-nil runner")
	}
}

func TestValidateInputPath_Missing(t *testing.T) {
	err := validateInputPath("/nonexistent/path/file.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidateInputPath_Dir(t *testing.T) {
	err := validateInputPath(t.TempDir())
	if err == nil {
		t.Fatal("expected error for directory input")
	}
}
