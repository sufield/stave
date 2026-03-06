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
	"regexp"
	"strings"
)

// maxInputFileBytes is the hardcoded safety limit for input files (256 MB).
// Any file or stream larger than this is rejected to prevent resource exhaustion.
const maxInputFileBytes int64 = 256 << 20

var (
	// ErrFileTooLarge indicates input exceeded the internal safety size limit.
	ErrFileTooLarge = errors.New("input exceeds internal safety limit")
	// ErrPathTraversal indicates a relative path escaped the allowed root.
	ErrPathTraversal = errors.New("path traversal detected")
	// ErrSymlinkForbidden indicates a write target is a symlink and symlinks are disallowed.
	ErrSymlinkForbidden = errors.New("refusing to write through symlink")
	// ErrFileExists indicates overwrite-protected output already exists.
	ErrFileExists = errors.New("output file already exists")
	// ErrInvalidBucket indicates the supplied bucket name is invalid.
	ErrInvalidBucket = errors.New("invalid bucket name")

	// RFC 1123-style bucket regex used by common object stores.
	bucketNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$`)
)

// --- READ SAFETY ---

// ReadFileLimited reads a file after verifying it does not exceed the internal
// safety limit of 256 MB. Returns a descriptive error if the file is too large.
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

// LimitedReadAll reads from r up to the internal safety limit of 256 MB.
// Returns a descriptive error if the stream exceeds the limit.
func LimitedReadAll(r io.Reader, sourceName string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxInputFileBytes {
		return nil, fmt.Errorf(
			"%w: input from %s exceeds the internal safety limit of %dMB; "+
				"to prevent resource exhaustion, Stave does not process input larger than this — "+
				"please check if this input was generated correctly",
			ErrFileTooLarge,
			sourceName, maxInputFileBytes>>20)
	}
	return data, nil
}

// CleanUserPath normalizes a user-supplied path by cleaning . and ..
// segments and duplicate separators. It does NOT resolve symlinks.
// Empty strings are returned as-is.
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
	if filepath.IsAbs(relPath) {
		return "", fmt.Errorf("path must be relative: %s", relPath)
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}

	joined := filepath.Join(absRoot, filepath.Clean(relPath))
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("resolve destination: %w", err)
	}

	// Verify the joined path is within root
	rel, err := filepath.Rel(absRoot, absJoined)
	if err != nil {
		return "", fmt.Errorf("path outside root: %s", relPath)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s", ErrPathTraversal, relPath)
	}

	return absJoined, nil
}

// --- WRITE SAFETY ---

// IsSymlink returns true if path exists and is a symbolic link.
// Returns (false, nil) if the path does not exist.
func IsSymlink(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return fi.Mode()&os.ModeSymlink != 0, nil
}

// SafeCreateFile creates a file using provided write options, enforcing:
//   - Symlink protection: refuses if target is a symlink (unless AllowSymlink),
//     with post-open handle verification to close the TOCTOU window
//   - Overwrite protection: atomic O_EXCL prevents clobbering (unless Overwrite)
//
// Returns an open file handle. Caller must close it.
func SafeCreateFile(path string, opts WriteOptions) (*os.File, error) {
	if !opts.AllowSymlink {
		if err := checkSymlinkSafety(path); err != nil {
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

// SafeMkdirAll creates a directory tree with the given permissions.
// It refuses if the final directory path is a symlink (unless AllowSymlink).
func SafeMkdirAll(path string, opts WriteOptions) error {
	if !opts.AllowSymlink {
		if err := checkSymlinkSafety(path); err != nil {
			return err
		}
	}
	return os.MkdirAll(path, opts.Perm)
}

// SafeOpenAppend opens a file for appending, enforcing symlink protection
// with post-open handle verification. Used for log files which are append-only.
func SafeOpenAppend(path string, opts WriteOptions) (*os.File, error) {
	if !opts.AllowSymlink {
		if err := checkSymlinkSafety(path); err != nil {
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

// maxParentWalk is a safety cap to prevent infinite loops on malformed paths.
const maxParentWalk = 16

// checkSymlinkSafety checks the target and its first existing ancestor for symlinks.
// Callers that obtain a file handle should also use verifyHandle for TOCTOU-safe
// confirmation.
func checkSymlinkSafety(path string) error {
	cur := filepath.Clean(path)

	for range maxParentWalk {
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
			break
		}
		cur = parent
	}

	return nil
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

// --- VALIDATION ---

// ValidateBucket checks that a bucket name is safe for use in file paths and URLs.
func ValidateBucket(name string) error {
	if strings.Contains(name, "..") || !bucketNameRe.MatchString(name) {
		return fmt.Errorf("%w: %q", ErrInvalidBucket, name)
	}
	return nil
}
