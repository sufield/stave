package prove

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

	flags := []string{"observations", "property", "port", "format"}
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

	propFlag := cmd.Flags().Lookup("property")
	if propFlag == nil {
		t.Fatal("property flag not registered")
	}
	for _, p := range ValidProperties {
		if !strings.Contains(propFlag.Usage, p) {
			t.Errorf("property flag usage %q does not contain property %q", propFlag.Usage, p)
		}
	}
	if propFlag.DefValue != DefaultProperty {
		t.Errorf("property default = %q, want %q", propFlag.DefValue, DefaultProperty)
	}
	if formatFlag.DefValue != DefaultFormat {
		t.Errorf("format default = %q, want %q", formatFlag.DefValue, DefaultFormat)
	}
	portFlag := cmd.Flags().Lookup("port")
	if portFlag == nil || portFlag.DefValue != "22" {
		t.Errorf("port default = %v, want '22'", portFlag)
	}
}

func TestValidProperties(t *testing.T) {
	expected := []string{
		"bastion-ssh",
		"prod-dev-isolation",
		"database-isolation",
		"firewall-mandatory",
		"transitive-ssh",
		"transitive-egress",
	}
	if len(ValidProperties) != len(expected) {
		t.Fatalf("len(ValidProperties) = %d, want %d", len(ValidProperties), len(expected))
	}
	for i, p := range expected {
		if ValidProperties[i] != p {
			t.Errorf("ValidProperties[%d] = %q, want %q", i, ValidProperties[i], p)
		}
	}
}

func TestIsValidProperty(t *testing.T) {
	for _, p := range ValidProperties {
		if !IsValidProperty(p) {
			t.Errorf("IsValidProperty(%q) = false, want true", p)
		}
	}

	invalid := []string{"", "unknown", "ssh", "bastion", "prod"}
	for _, p := range invalid {
		if IsValidProperty(p) {
			t.Errorf("IsValidProperty(%q) = true, want false", p)
		}
	}
}

func TestValidFormats(t *testing.T) {
	expected := []string{"json", "text"}
	if len(ValidFormats) != len(expected) {
		t.Fatalf("len(ValidFormats) = %d, want %d", len(ValidFormats), len(expected))
	}
	for i, f := range expected {
		if ValidFormats[i] != f {
			t.Errorf("ValidFormats[%d] = %q, want %q", i, ValidFormats[i], f)
		}
	}
}

func TestIsValidFormat(t *testing.T) {
	t.Run("empty format is valid default", func(t *testing.T) {
		if !IsValidFormat("") {
			t.Error("IsValidFormat(\"\") = false, want true")
		}
	})

	t.Run("valid format names", func(t *testing.T) {
		for _, f := range ValidFormats {
			if !IsValidFormat(f) {
				t.Errorf("IsValidFormat(%q) = false, want true", f)
			}
		}
	})

	t.Run("invalid format names", func(t *testing.T) {
		invalid := []string{"yaml", "xml", "csv", "html"}
		for _, f := range invalid {
			if IsValidFormat(f) {
				t.Errorf("IsValidFormat(%q) = true, want false", f)
			}
		}
	})
}

func TestDefaultConstants(t *testing.T) {
	if DefaultProperty != "bastion-ssh" {
		t.Errorf("DefaultProperty = %q, want bastion-ssh", DefaultProperty)
	}
	if DefaultPort != 22 {
		t.Errorf("DefaultPort = %d, want 22", DefaultPort)
	}
	if DefaultFormat != "text" {
		t.Errorf("DefaultFormat = %q, want text", DefaultFormat)
	}
}

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name        string
		opts        options
		wantErr     bool
		errContains string
	}{
		{
			name: "valid bastion-ssh text",
			opts: options{
				property: "bastion-ssh",
				format:   "text",
			},
			wantErr: false,
		},
		{
			name: "valid prod-dev-isolation json",
			opts: options{
				property: "prod-dev-isolation",
				format:   "json",
			},
			wantErr: false,
		},
		{
			name: "valid database-isolation default format",
			opts: options{
				property: "database-isolation",
				format:   "",
			},
			wantErr: false,
		},
		{
			name: "valid firewall-mandatory",
			opts: options{
				property: "firewall-mandatory",
				format:   "text",
			},
			wantErr: false,
		},
		{
			name: "valid transitive-ssh",
			opts: options{
				property: "transitive-ssh",
				format:   "json",
			},
			wantErr: false,
		},
		{
			name: "valid transitive-egress",
			opts: options{
				property: "transitive-egress",
				format:   "text",
			},
			wantErr: false,
		},
		{
			name: "unknown property",
			opts: options{
				property: "invalid-property",
				format:   "text",
			},
			wantErr:     true,
			errContains: "unknown --property \"invalid-property\"",
		},
		{
			name: "invalid format",
			opts: options{
				property: "bastion-ssh",
				format:   "yaml",
			},
			wantErr:     true,
			errContains: "unknown format \"yaml\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				var userErr *ui.UserError
				if !errors.As(err, &userErr) {
					t.Errorf("expected *ui.UserError, got %T (%v)", err, err)
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("err = %q, want to contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestOptions_Prepare(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &options{
		observations: "./testdata/../testdata",
		property:     "bastion-ssh",
		format:       "text",
	}

	if err := opts.Prepare(cmd); err != nil {
		t.Fatalf("Prepare() error: %v", err)
	}

	if strings.Contains(opts.observations, "..") {
		t.Errorf("expected cleaned observations path, got %q", opts.observations)
	}
}

func TestOptions_ToConfig(t *testing.T) {
	opts := &options{
		observations: "/path/to/obs",
		property:     "bastion-ssh",
		port:         22,
		format:       "json",
	}

	cfg := opts.ToConfig()
	if cfg.SnapshotsDir != "/path/to/obs" {
		t.Errorf("SnapshotsDir = %q, want %q", cfg.SnapshotsDir, "/path/to/obs")
	}
	if cfg.Property != "bastion-ssh" {
		t.Errorf("Property = %q, want %q", cfg.Property, "bastion-ssh")
	}
	if cfg.Port != 22 {
		t.Errorf("Port = %d, want 22", cfg.Port)
	}
}
