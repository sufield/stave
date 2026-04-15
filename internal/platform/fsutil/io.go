// Package fsutil provides filesystem safety primitives for Stave CLI.
//
// All file writes in Stave pass through this package to enforce:
//   - Symlink protection (refuse to write through symlinks by default)
//   - Overwrite protection (refuse to clobber existing files without --force)
//   - Path traversal prevention (JoinWithinRoot)
//   - Path normalization (CleanUserPath)
//   - Bucket name validation for read-path safety
package fsutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMaxInputFileBytes is the conservative default safety limit for input
// files (256 MB). Override via SetMaxInputFileBytes for environments that
// process larger snapshots (e.g., enterprise CI with thousands of assets).
const DefaultMaxInputFileBytes int64 = 256 << 20

// maxInputFileBytes is the active safety limit. Starts at the default and can
// be overridden once at startup via SetMaxInputFileBytes.
var maxInputFileBytes = DefaultMaxInputFileBytes

// SetMaxInputFileBytes overrides the input file safety limit. Call this once
// during CLI bootstrap, before any file reads. Values <= 0 are ignored.
func SetMaxInputFileBytes(n int64) {
	if n > 0 {
		maxInputFileBytes = n
	}
}

var (
	// ErrFileTooLarge indicates input exceeded the internal safety size limit.
	ErrFileTooLarge = errors.New("input exceeds internal safety limit")
	// ErrPathTraversal indicates a relative path escaped the allowed root.
	ErrPathTraversal = errors.New("path traversal detected")
	// ErrSymlinkForbidden indicates a write target is a symlink and symlinks are disallowed.
	ErrSymlinkForbidden = errors.New("refusing to write through symlink")
	// ErrFileExists indicates overwrite-protected output already exists.
	ErrFileExists = errors.New("output file already exists")
)

// --- READ SAFETY ---

// ReadFileLimited reads a file after verifying it does not exceed the active
// safety limit (default 256 MB). Returns a descriptive error if the file is
// too large. Override the limit with SetMaxInputFileBytes.
func ReadFileLimited(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxInputFileBytes {
		return nil, fmt.Errorf(
			"%w: file %q exceeds the internal safety limit of %dMB; "+
				"to prevent resource exhaustion, Stave does not process files larger than this — "+
				"please check if this file was generated correctly",
			ErrFileTooLarge,
			filepath.Base(path), maxInputFileBytes>>20)
	}
	// #nosec G304 -- this helper intentionally reads caller-supplied paths after size checks.
	return os.ReadFile(path)
}

// ReadFileOrStdin reads from a file path if non-empty, otherwise from stdin.
// Both paths enforce the active safety limit to prevent resource exhaustion.
func ReadFileOrStdin(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		return ReadFileLimited(file)
	}
	return LimitedReadAll(stdin, "stdin")
}

// LimitedReadAll reads from r up to the active safety limit (default 256 MB).
// Returns ErrFileTooLarge if the stream exceeds the limit.
//
// Uses a two-phase approach to prevent resource exhaustion:
//  1. Read up to the limit via io.LimitReader, which caps io.ReadAll's
//     internal buffer at exactly the limit — preventing the capacity
//     doubling that occurs when reading limit+1 bytes.
//  2. Probe one additional byte from the original reader to detect
//     overflow without allocating beyond the limit.
func LimitedReadAll(r io.Reader, sourceName string) ([]byte, error) {
	// Phase 1: read up to the limit. The LimitReader ensures io.ReadAll
	// never grows its buffer past maxInputFileBytes.
	data, err := io.ReadAll(io.LimitReader(r, maxInputFileBytes))
	if err != nil {
		return nil, err
	}

	// Phase 2: probe for overflow. If even one more byte is available,
	// the stream exceeds the limit — reject without further allocation.
	var probe [1]byte
	n, _ := r.Read(probe[:])
	if n > 0 {
		return nil, fmt.Errorf(
			"%w: input from %s exceeds the internal safety limit of %dMB; "+
				"to prevent resource exhaustion, Stave does not process input larger than this — "+
				"please check if this input was generated correctly",
			ErrFileTooLarge,
			sourceName, maxInputFileBytes>>20)
	}

	return data, nil
}

// CleanUserPath performs lexical path cleanup via filepath.Clean.
// It does NOT expand ~ (tilde), does NOT resolve symlinks, and does NOT
// make paths absolute. Use filepath.Abs() when absolute paths are needed.
// Returns the input unchanged for empty strings and "-" (stdin sentinel).
func CleanUserPath(p string) string {
	if p == "" || p == "-" {
		return p
	}
	return filepath.Clean(p)
}

// JoinWithinRoot joins a root directory and a relative path, then verifies
// the result does not escape root. Returns an error if:
//   - relPath is absolute
//   - the joined path resolves outside root after cleaning
func JoinWithinRoot(root, relPath string) (string, error) {
	relPath = filepath.Clean(relPath)
	if filepath.IsAbs(relPath) || strings.HasPrefix(relPath, string(filepath.Separator)) {
		return "", fmt.Errorf("path must be relative: %s", relPath)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}

	joined := filepath.Join(absRoot, relPath)
	rel, err := filepath.Rel(absRoot, joined)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s", ErrPathTraversal, relPath)
	}

	return joined, nil
}

// --- WRITE SAFETY ---

// SafeCreateFile creates a file using provided write options, enforcing:
//   - Symlink protection: refuses if target is a symlink (unless AllowSymlink),
//     with post-open handle verification to close the TOCTOU window
//   - Overwrite protection: atomic O_EXCL prevents clobbering (unless Overwrite)
//
// Returns an open file handle. Caller must close it.
func SafeCreateFile(path string, opts WriteOptions) (*os.File, error) {
	if !opts.AllowSymlink {
		if err := CheckSymlinkSafety(path); err != nil {
			return nil, err
		}
	}

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !opts.Overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}

	// #nosec G304 -- intentionally opens caller-supplied output paths after safety checks.
	f, err := os.OpenFile(path, flags, opts.Perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s (use --force to overwrite)", ErrFileExists, path)
		}
		return nil, err
	}

	if !opts.AllowSymlink {
		if err := verifyHandle(f, path); err != nil {
			_ = f.Close()
			return nil, err
		}
	}

	return f, nil
}

// SafeWriteFile writes data using provided write options, enforcing:
//   - Symlink protection: refuses if target is a symlink (unless AllowSymlink)
//   - Overwrite protection: atomic O_EXCL prevents clobbering (unless Overwrite)
func SafeWriteFile(path string, data []byte, opts WriteOptions) error {
	f, err := SafeCreateFile(path, opts)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// SafeMkdirAll creates a directory tree, checking every path component for
// symlinks during creation (unless AllowSymlink). This prevents TOCTOU races
// that could occur between a pre-check and os.MkdirAll.
func SafeMkdirAll(path string, opts WriteOptions) error {
	if opts.AllowSymlink {
		return os.MkdirAll(path, opts.Perm)
	}

	cleanPath := filepath.Clean(path)
	components := strings.Split(cleanPath, string(filepath.Separator))

	current := ""
	if filepath.IsAbs(cleanPath) {
		current = string(filepath.Separator)
	}

	for _, part := range components {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)

		fi, err := os.Lstat(current)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s (use --allow-symlink-output to override)", ErrSymlinkForbidden, current)
			}
			if !fi.IsDir() {
				return fmt.Errorf("path component is not a directory: %s", current)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("security check failed for %q: %w", current, err)
		}
		if mkErr := os.Mkdir(current, opts.Perm); mkErr != nil && !os.IsExist(mkErr) {
			return mkErr
		}
	}
	return nil
}

// SafeOpenAppend opens a file for appending, enforcing symlink protection
// with post-open handle verification. Used for log files which are append-only.
func SafeOpenAppend(path string, opts WriteOptions) (*os.File, error) {
	if !opts.AllowSymlink {
		if err := CheckSymlinkSafety(path); err != nil {
			return nil, err
		}
	}

	// #nosec G304 -- intentionally appends to caller-supplied output paths after safety checks.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, opts.Perm)
	if err != nil {
		return nil, fmt.Errorf("failed to open %q for appending: %w", path, err)
	}

	if !opts.AllowSymlink {
		if err := verifyHandle(f, path); err != nil {
			_ = f.Close()
			return nil, err
		}
	}

	return f, nil
}

// maxPathDepth is a safety cap to prevent infinite loops on malformed paths.
// It is not a policy limit on path depth — 512 is unreachable on any real
// filesystem (Linux PATH_MAX is 4096 bytes).
const maxPathDepth = 512

// CheckSymlinkSafety checks the target and its first existing ancestor for symlinks.
// Callers that obtain a file handle should also use verifyHandle for TOCTOU-safe
// confirmation.
func CheckSymlinkSafety(path string) error {
	cur := filepath.Clean(path)

	for range maxPathDepth {
		fi, err := os.Lstat(cur)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s (use --allow-symlink-output to override)", ErrSymlinkForbidden, cur)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("security check failed for %q: %w", cur, err)
		}

		parent := filepath.Dir(cur)
		if parent == cur {
			return nil // reached filesystem root
		}
		cur = parent
	}

	return fmt.Errorf("security check failed for %q: path depth exceeds safety limit of %d components", path, maxPathDepth)
}

// verifyHandle confirms the opened file handle points to the same inode as the
// path's Lstat, detecting symlink swaps between pre-check and open (TOCTOU).
func verifyHandle(f *os.File, path string) error {
	handleInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("security check failed: %w", err)
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("security check failed: %w", err)
	}
	if !os.SameFile(handleInfo, pathInfo) {
		return fmt.Errorf("%w: %s (path changed between check and open)", ErrSymlinkForbidden, path)
	}
	return nil
}

// --- ATOMIC WRITES ---

// WriteFileAtomic writes data to a temporary file and renames it to the
// destination path. This ensures that the destination file is either fully
// written or not changed at all, preventing partial writes on crash.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := CheckSymlinkSafety(path); err != nil {
		return fmt.Errorf("atomic write safety check: %w", err)
	}

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	// Create parent directory if it does not exist.
	if dir != "" && dir != "." {
		if mkErr := SafeMkdirAll(dir, WriteOptions{Perm: 0o700}); mkErr != nil {
			return fmt.Errorf("create parent directory for atomic write %q: %w", dir, mkErr)
		}
	}

	tmpFile, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for atomic write: %w", err)
	}
	tmpPath := tmpFile.Name()

	committed := false
	closed := false
	defer func() {
		if !closed {
			_ = tmpFile.Close()
		}
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	err = tmpFile.Chmod(perm)
	if err != nil {
		return fmt.Errorf("set permissions on temp file: %w", err)
	}
	_, err = tmpFile.Write(data)
	if err != nil {
		return fmt.Errorf("write data to temp file: %w", err)
	}
	err = tmpFile.Sync()
	if err != nil {
		return fmt.Errorf("sync temp file: %w", err)
	}
	closed = true
	err = tmpFile.Close()
	if err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Attempt atomic rename — works when src and dst are on the same fs.
	if renameErr := os.Rename(tmpPath, path); renameErr == nil {
		committed = true
		return nil
	}

	// Fallback: copy-then-delete for cross-filesystem case.
	if cpErr := crossFSCopy(tmpPath, path, perm); cpErr != nil {
		return fmt.Errorf("cross-filesystem fallback: %w", cpErr)
	}
	committed = true
	_ = os.Remove(tmpPath)
	return nil
}

// crossFSCopy copies a file when os.Rename fails across filesystems.
func crossFSCopy(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // temp file we just created
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm) //nolint:gosec // caller checked path
	if err != nil {
		return err
	}

	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
