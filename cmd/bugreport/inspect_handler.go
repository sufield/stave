//go:build stavedev

package bugreport

import (
	"archive/zip"
	"fmt"
	"io"
	"sort"
	"strings"
)

// DefaultMaxInspectSize is the safety limit for decompressing files during inspection (10 MB).
const DefaultMaxInspectSize int64 = 10 << 20

// InspectConfig defines how the bundle should be dumped.
type InspectConfig struct {
	Stdout  io.Writer
	Stderr  io.Writer
	MaxSize int64
}

// Inspector handles the extraction and display of diagnostic bundles.
type Inspector struct {
	cfg InspectConfig
}

// NewInspector creates an inspector with the provided configuration.
func NewInspector(cfg InspectConfig) *Inspector {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxInspectSize
	}
	return &Inspector{cfg: cfg}
}

// Inspect reads a zip archive and writes its contents to the configured Stdout.
func (ins *Inspector) Inspect(zr *zip.Reader) error {
	entries := make([]*zip.File, len(zr.File))
	copy(entries, zr.File)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	for _, f := range entries {
		if err := ins.inspectFile(f); err != nil {
			return err
		}
	}
	return nil
}

func (ins *Inspector) inspectFile(f *zip.File) error {
	if strings.Contains(f.Name, "..") {
		_, _ = fmt.Fprintf(ins.cfg.Stderr, "warning: skipping suspicious entry %q\n", f.Name)
		return nil
	}
	if ins.cfg.MaxSize > 0 && f.UncompressedSize64 > uint64(ins.cfg.MaxSize) { //nolint:gosec // MaxSize is validated positive by NewInspector
		_, _ = fmt.Fprintf(ins.cfg.Stderr, "warning: skipping %s (%d bytes exceeds %dMB limit)\n",
			f.Name, f.UncompressedSize64, ins.cfg.MaxSize>>20)
		return nil
	}
	if _, err := fmt.Fprintf(ins.cfg.Stdout, "=== %s ===\n", f.Name); err != nil {
		return fmt.Errorf("%s: %w", f.Name, err)
	}
	if err := ins.copyEntry(f); err != nil {
		return fmt.Errorf("%s: %w", f.Name, err)
	}
	if _, err := fmt.Fprintln(ins.cfg.Stdout); err != nil {
		return fmt.Errorf("%s: %w", f.Name, err)
	}
	return nil
}

func (ins *Inspector) copyEntry(f *zip.File) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	_, err = io.Copy(ins.cfg.Stdout, io.LimitReader(rc, ins.cfg.MaxSize+1))
	return err
}
