package initcmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// GenerateRequest holds the parameters for template generation.
type GenerateRequest struct {
	Name string
	Out  string
}

// GenerateRunner orchestrates the creation of starter observation templates.
type GenerateRunner struct {
	Out          io.Writer
	Force        bool
	Quiet        bool
	AllowSymlink bool
}

// RefusesOverwrite reports whether writeFile should refuse to clobber
// an existing target. The previous shape inverted Force at the call
// site (`if !r.Force`); the named accessor keeps the policy intent
// (--force flips refusal off) on the type that owns the flag.
func (r *GenerateRunner) RefusesOverwrite() bool {
	return r != nil && !r.Force
}

// ShouldEmitText reports whether the runner should write its
// human-readable "Generated <path>" line. Mirrors Runtime.ShouldOutput
// for the subset of state this runner carries.
func (r *GenerateRunner) ShouldEmitText() bool {
	return r != nil && !r.Quiet
}

// RunObservation generates an observation JSON template.
func (r *GenerateRunner) RunObservation(req GenerateRequest) error {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return errors.New("observation name cannot be empty")
	}
	slug := sanitizeSlug(name)
	content := strings.ReplaceAll(strings.TrimLeft(templateObservation, "\n"), "aws:s3:::example-phi-bucket", "asset:"+slug)
	out := strings.TrimSpace(req.Out)
	if out == "" {
		out = filepath.Join("observations", slug+".json")
	}
	return r.writeFile(out, []byte(content))
}

func (r *GenerateRunner) writeFile(path string, content []byte) error {
	path = fsutil.CleanUserPath(path)
	if strings.TrimSpace(path) == "" {
		return errors.New("output path cannot be empty")
	}
	if r.RefusesOverwrite() {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("file already exists: %s (use --force to overwrite)", path)
		}
	}
	if err := fsutil.SafeMkdirAll(filepath.Dir(path), fsutil.WriteOptions{Perm: 0o700, AllowSymlink: r.AllowSymlink}); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	opts := fsutil.ConfigWriteOpts()
	opts.Overwrite = r.Force
	opts.AllowSymlink = r.AllowSymlink
	if err := fsutil.SafeWriteFile(path, content, opts); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	if r.ShouldEmitText() {
		fmt.Fprintf(r.Out, "Generated %s\n", path)
	}
	return nil
}
