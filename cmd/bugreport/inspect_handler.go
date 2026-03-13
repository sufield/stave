package bugreport

import (
	"archive/zip"
	"fmt"
	"io"
	"sort"
	"strings"
)

const inspectMaxFileSize int64 = 10 << 20 // 10 MB

func dumpBundle(out io.Writer, errOut io.Writer, path string, maxSize int64) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("open bundle: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// Sort entries by name for deterministic output.
	entries := make([]*zip.File, len(zr.File))
	copy(entries, zr.File)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	if maxSize < 0 {
		return fmt.Errorf("maxSize cannot be negative")
	}

	for _, f := range entries {
		if strings.Contains(f.Name, "..") {
			_, _ = fmt.Fprintf(errOut, "warning: skipping suspicious entry %q\n", f.Name)
			continue
		}
		if f.UncompressedSize64 > uint64(maxSize) {
			_, _ = fmt.Fprintf(errOut, "warning: skipping %s (%d bytes exceeds %dMB limit)\n", f.Name, f.UncompressedSize64, maxSize>>20)
			continue
		}
		if _, err := fmt.Fprintf(out, "=== %s ===\n", f.Name); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if err := copyZipEntry(out, f, maxSize); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	return nil
}

func copyZipEntry(w io.Writer, f *zip.File, maxSize int64) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer func() { _ = rc.Close() }()

	// Cap read to maxSize+1 to guard against decompression bombs
	// (entry size is pre-checked, but LimitReader provides defense in depth).
	_, err = io.Copy(w, io.LimitReader(rc, maxSize+1))
	return err
}
