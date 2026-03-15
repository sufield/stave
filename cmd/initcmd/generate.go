package initcmd

import (
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

// GenerateRunner orchestrates the creation of starter control and observation templates.
type GenerateRunner struct {
	Out          io.Writer
	Force        bool
	Quiet        bool
	AllowSymlink bool
}

// RunControl generates a canonical control YAML template.
func (r *GenerateRunner) RunControl(req GenerateRequest) error {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return fmt.Errorf("control name cannot be empty")
	}
	id := controlIDFromName(name)
	content := strings.ReplaceAll(strings.TrimLeft(templateControlCanonical, "\n"), "CTL.S3.PUBLIC.901", id)
	out := strings.TrimSpace(req.Out)
	if out == "" {
		out = filepath.Join("controls", id+".yaml")
	}
	return r.writeFile(out, []byte(content))
}

// RunObservation generates an observation JSON template.
func (r *GenerateRunner) RunObservation(req GenerateRequest) error {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return fmt.Errorf("observation name cannot be empty")
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
		return fmt.Errorf("output path cannot be empty")
	}
	if !r.Force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("file already exists: %s (use --force to overwrite)", path)
		}
	}
	if err := fsutil.SafeMkdirAll(filepath.Dir(path), fsutil.WriteOptions{Perm: 0o700, AllowSymlink: r.AllowSymlink}); err != nil {
		return err
	}
	opts := fsutil.ConfigWriteOpts()
	opts.Overwrite = r.Force
	opts.AllowSymlink = r.AllowSymlink
	if err := fsutil.SafeWriteFile(path, content, opts); err != nil {
		return err
	}
	if !r.Quiet {
		fmt.Fprintf(r.Out, "Generated %s\n", path)
	}
	return nil
}
