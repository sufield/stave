package forgecmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// ValidateGenerated finds <controlID>.yaml under outDir and validates it the
// same way `stave validate` parses controls (unmarshal + Prepare). It returns
// the status output and a non-nil error when the expected YAML is absent
// (generation produced nothing) or fails to parse/prepare. It is the library
// entry point behind the validation step of `stave forge new`.
func ValidateGenerated(controlID, outDir string) ([]byte, error) {
	if outDir == "" {
		outDir = "testdata/e2e"
	}

	var buf bytes.Buffer

	wantName := controlID + ".yaml"
	var yamlPath string
	walkErr := filepath.Walk(outDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == wantName {
			yamlPath = path
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil {
		fmt.Fprintf(&buf, "\nValidating generated control...  WARNING\n  walk error: %v\n", walkErr)
	}

	if yamlPath == "" {
		fmt.Fprintf(&buf, "\nValidating generated control...  FAILED\n  expected %s under %s but it was not generated\n", wantName, outDir)
		if walkErr != nil {
			return buf.Bytes(), fmt.Errorf("generated control %s not found under %s (walk error: %w)", wantName, outDir, walkErr)
		}
		return buf.Bytes(), fmt.Errorf("generated control %s not found under %s — generation produced no output", wantName, outDir)
	}

	data, err := fsutil.ReadFileLimited(yamlPath)
	if err != nil {
		fmt.Fprintf(&buf, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		return buf.Bytes(), fmt.Errorf("read generated control %s: %w", yamlPath, err)
	}

	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		fmt.Fprintf(&buf, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		fmt.Fprintf(&buf, "\nThe generated control has a schema error. Edit the file and\nrun 'stave validate %s' to verify.\n", yamlPath)
		return buf.Bytes(), fmt.Errorf("parse generated control %s: %w", yamlPath, err)
	}

	if err := ctl.Prepare(); err != nil {
		fmt.Fprintf(&buf, "\nValidating generated control...  FAILED\n  error: %v\n", err)
		fmt.Fprintf(&buf, "\nThe generated control has a preparation error. Edit the file and\nrun 'stave validate %s' to verify.\n", yamlPath)
		return buf.Bytes(), fmt.Errorf("prepare generated control %s: %w", yamlPath, err)
	}

	fmt.Fprintln(&buf, "\nValidating generated control...  OK")
	return buf.Bytes(), nil
}
