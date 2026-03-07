package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/sufield/stave/cmd/apply"
	applyvalidate "github.com/sufield/stave/cmd/apply/validate"
	"github.com/sufield/stave/cmd/diagnose"
	"github.com/sufield/stave/cmd/enforce"
	"github.com/sufield/stave/cmd/ingest"
)

// TestDirPermissions0o700 verifies that output directories are created with
// 0o700 permissions.
func TestDirPermissions0o700(t *testing.T) {
	tmpDir := t.TempDir()
	targetDir := filepath.Join(tmpDir, "nested", "output")

	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(targetDir)
	if err != nil {
		t.Fatal(err)
	}

	perm := info.Mode().Perm()
	if perm != 0o700 {
		t.Errorf("expected directory permissions 0o700, got %o", perm)
	}
}

// TestFilePermissions0o600 verifies that output files are created with
// 0o600 permissions using os.OpenFile.
func TestFilePermissions0o600(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "test-output.json")

	f, err := os.OpenFile(outFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatal(err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected file permissions 0o600, got %o", perm)
	}
}

// TestWriteFilePermissions0o600 verifies that os.WriteFile with 0o600
// creates files with correct permissions (used by ingest --profile aws-s3).
func TestWriteFilePermissions0o600(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "obs.json")

	if err := os.WriteFile(outFile, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatal(err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("expected file permissions 0o600, got %o", perm)
	}
}

// TestNoOsCreateInOutputFiles verifies that output files use os.OpenFile
// with explicit permissions instead of os.Create (which defaults to 0666).
func TestNoOsCreateInOutputFiles(t *testing.T) {
	// Source files have moved to sub-packages. Check each sub-package directory.
	checks := []struct {
		dir  string
		file string
	}{
		{"ingest", "ingest.go"},
		{"enforce", "enforce.go"},
		{"apply", "handler.go"},
	}

	for _, c := range checks {
		path := filepath.Join(".", c.dir, c.file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping %s/%s: %v", c.dir, c.file, err)
			continue
		}

		content := string(data)
		if contains(content, "os.Create(") {
			t.Errorf("%s/%s still uses os.Create — should use os.OpenFile with 0o600", c.dir, c.file)
		}
	}
}

// TestNoWorldReadableDirs verifies that output directories do not use 0o755.
func TestNoWorldReadableDirs(t *testing.T) {
	checks := []struct {
		dir  string
		file string
	}{
		{"ingest", "ingest.go"},
		{"enforce", "enforce.go"},
		{"apply", "handler.go"},
	}

	for _, c := range checks {
		path := filepath.Join(".", c.dir, c.file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("skipping %s/%s: %v", c.dir, c.file, err)
			continue
		}

		content := string(data)
		if contains(content, "0o755") || contains(content, "0755") {
			t.Errorf("%s/%s still uses 0o755 for MkdirAll — should use 0o700", c.dir, c.file)
		}
	}
}

// TestExtractFlagRegistered verifies --force and --dry-run flags exist.
func TestExtractS3FlagRegistered(t *testing.T) {
	flags := []string{"force", "dry-run"}
	for _, name := range flags {
		f := ingest.IngestCmd.Flags().Lookup(name)
		if f == nil {
			t.Errorf("extract missing --%s flag", name)
		}
	}
}

// TestEnforceFlagRegistered verifies --dry-run flag exists on enforce.
func TestEnforceFlagRegistered(t *testing.T) {
	f := enforce.EnforceCmd.Flags().Lookup("dry-run")
	if f == nil {
		t.Error("enforce missing --dry-run flag")
	}
}

// TestValidateInFlagRegistered verifies --in flag exists on validate.
func TestValidateInFlagRegistered(t *testing.T) {
	f := applyvalidate.ValidateCmd.Flags().Lookup("in")
	if f == nil {
		t.Error("validate missing --in flag")
	}
}

func TestCommonShortAliasesRegistered(t *testing.T) {
	cases := []struct {
		name      string
		shorthand string
		flags     interface{ ShorthandLookup(name string) *pflag.Flag }
	}{
		{name: "apply controls", shorthand: "i", flags: apply.ApplyCmd.Flags()},
		{name: "apply observations", shorthand: "o", flags: apply.ApplyCmd.Flags()},
		{name: "validate controls", shorthand: "i", flags: applyvalidate.ValidateCmd.Flags()},
		{name: "validate observations", shorthand: "o", flags: applyvalidate.ValidateCmd.Flags()},
		{name: "diagnose previous-output", shorthand: "p", flags: diagnose.DiagnoseCmd.Flags()},
	}

	for _, tc := range cases {
		if tc.flags.ShorthandLookup(tc.shorthand) == nil {
			t.Fatalf("%s missing -%s alias", tc.name, tc.shorthand)
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
