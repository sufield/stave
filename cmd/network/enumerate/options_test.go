package enumerate

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

func TestAddFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &options{}
	addFlags(cmd, opts)

	flags := []string{"observations", "port", "format"}
	for _, f := range flags {
		if cmd.Flags().Lookup(f) == nil {
			t.Errorf("expected flag %q to be registered", f)
		}
	}

	obsFlag := cmd.Flags().Lookup("observations")
	if obsFlag == nil || obsFlag.Shorthand != "o" {
		t.Errorf("observations shorthand = %q, want 'o'", obsFlag.Shorthand)
	}

	formatFlag := cmd.Flags().Lookup("format")
	if formatFlag == nil || formatFlag.Shorthand != "f" {
		t.Errorf("format shorthand = %q, want 'f'", formatFlag.Shorthand)
	}
	for _, fmtName := range ValidFormats {
		if !strings.Contains(formatFlag.Usage, fmtName) {
			t.Errorf("format flag usage %q does not contain format %q", formatFlag.Usage, fmtName)
		}
	}
	if formatFlag.DefValue != DefaultFormat {
		t.Errorf("format default = %q, want %q", formatFlag.DefValue, DefaultFormat)
	}

	portFlag := cmd.Flags().Lookup("port")
	if portFlag == nil || portFlag.DefValue != "22" {
		t.Errorf("port default = %v, want '22'", portFlag)
	}
}

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		opts    options
		wantErr bool
	}{
		{
			name: "valid text",
			opts: options{
				observations: "testdata",
				port:         22,
				format:       "text",
			},
			wantErr: false,
		},
		{
			name: "valid json",
			opts: options{
				observations: "testdata",
				port:         22,
				format:       "json",
			},
			wantErr: false,
		},
		{
			name: "valid empty format defaults",
			opts: options{
				observations: "testdata",
				port:         22,
				format:       "",
			},
			wantErr: false,
		},
		{
			name: "invalid format",
			opts: options{
				observations: "testdata",
				port:         22,
				format:       "xml",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var uerr *ui.UserError
				if !errors.As(err, &uerr) {
					t.Errorf("expected *ui.UserError, got %T", err)
				}
			}
		})
	}
}

func TestOptions_ToConfig(t *testing.T) {
	opts := &options{
		observations: "/path/to/obs",
		port:         2222,
		format:       "json",
	}

	cfg := opts.ToConfig()
	if cfg.SnapshotsDir != "/path/to/obs" {
		t.Errorf("SnapshotsDir = %q, want %q", cfg.SnapshotsDir, "/path/to/obs")
	}
	if cfg.Port != 2222 {
		t.Errorf("Port = %d, want 2222", cfg.Port)
	}
}
