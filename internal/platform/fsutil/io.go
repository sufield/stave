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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// mbShift is the log2(bytes-per-megabyte) bit-shift exponent
// (2^20 = 1 MiB). Used as `limit << mbShift` to convert MB → bytes
// and `bytes >> mbShift` for the reverse — NOT a raw byte count.
// Centralised so error messages and limit calculations refer to
// the same exponent rather than each open-coding `>> 20` / `<< 20`.
const mbShift = 20

// DefaultMaxInputFileBytes is the conservative default safety limit for input
// files (256 MB). Override via SetMaxInputFileBytes for environments that
// process larger snapshots (e.g., enterprise CI with thousands of assets).
const DefaultMaxInputFileBytes int64 = 256 << mbShift

// maxInputFileBytes is the active safety limit. Stored atomically so
// the bootstrap-time SetMaxInputFileBytes write does not race with
// concurrent reads from worker goroutines that may have already
// reached ReadFileLimited / LimitedReadAll.
var maxInputFileBytes atomic.Int64

func init() {
	maxInputFileBytes.Store(DefaultMaxInputFileBytes)
}

// SetMaxInputFileBytes overrides the input file safety limit. Call this once
// during CLI bootstrap, before any file reads. Values <= 0 are ignored.
func SetMaxInputFileBytes(n int64) {
	if n > 0 {
		maxInputFileBytes.Store(n)
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

// ReadFileLimited reads a file after verifying it does not exceed the
// active safety limit (default 256 MB). Returns a descriptive error
// if the file is too large. Override the limit with
// SetMaxInputFileBytes.
//
// The earlier shape used an os.Stat-then-os.ReadFile pair; that
// pattern has a TOCTOU window between the size check and the read,
// so a racing writer could grow the file past the limit and the
// read would still succeed at the new larger size. Switching to
// os.Open + io.LimitReader (the same pattern as LimitedReadAll)
// closes the window: the read itself is bounded, and a one-byte
// probe afterwards tells us whether the limit was exceeded.
func ReadFileLimited(path string) ([]byte, error) {
	// #nosec G304 -- this helper intentionally reads caller-supplied paths after size checks.
	f, err := os.Open(path)
	if err != nil {
		return nil, err //nolint:wrapcheck // os.Open returns *PathError with full context; wrapping breaks os.IsNotExist callers
	}
	defer f.Close()

	limit := maxInputFileBytes.Load()
	data, err := io.ReadAll(io.LimitReader(f, limit))
	if err != nil {
		return nil, err //nolint:wrapcheck // io.ReadAll context is sufficient
	}

	// Probe for overflow: if any byte remains beyond the limit,
	// reject. Mirrors LimitedReadAll's overflow handling.
	var probe [1]byte
	n, probeErr := f.Read(probe[:])
	if n > 0 {
		return nil, fmt.Errorf(
			"%w: file %q exceeds the internal safety limit of %dMB; "+
				"to prevent resource exhaustion, Stave does not process files larger than this — "+
				"please check if this file was generated correctly",
			ErrFileTooLarge,
			filepath.Base(path), limit>>mbShift)
	}
	if probeErr != nil && !errors.Is(probeErr, io.EOF) {
		return nil, probeErr //nolint:wrapcheck // low-level IO; caller wraps
	}
	return data, nil
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
	data, err := io.ReadAll(io.LimitReader(r, maxInputFileBytes.Load()))
	if err != nil {
		return nil, fmt.Errorf("read all: %w", err)
	}

	// Phase 2: probe for overflow. If even one more byte is available,
	// the stream exceeds the limit — reject without further allocation.
	// Capture the probe error: a reader that returns (0, someError)
	// rather than (0, io.EOF) used to be silently treated as
	// "no overflow" because the error was discarded. That hid genuine
	// I/O failures (a torn network stream, a closed file) behind what
	// looked like a successful bounded read.
	var probe [1]byte
	n, probeErr := r.Read(probe[:])
	if n > 0 {
		return nil, fmt.Errorf(
			"%w: input from %s exceeds the internal safety limit of %dMB; "+
				"to prevent resource exhaustion, Stave does not process input larger than this — "+
				"please check if this input was generated correctly",
			ErrFileTooLarge,
			sourceName, maxInputFileBytes.Load()>>mbShift)
	}
	if probeErr != nil && !errors.Is(probeErr, io.EOF) {
		return nil, fmt.Errorf("read %s: %w", sourceName, probeErr)
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
//   - the joined path resolves outside root after cleaning (lexical)
//   - the joined path, after symlink resolution, resolves outside root
//
// The symlink-resolution pass (evalWithinRoot) is essential for the
// control-loading path: registry entries are relative paths trusted to
// stay within root, but a lexically-in-root entry that is (or descends
// through) a symlink to outside root would otherwise be accepted and
// the out-of-root file read as a control. Lexical Rel cannot see this;
// only resolving the link does.
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

	if err := evalWithinRoot(absRoot, joined); err != nil {
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

	// Test hook: inject a path swap between the symlink check and the open to
	// exercise the TOCTOU window. Nil in production.
	testHookAfterLstatMu.Lock()
	beforeOpen := testHookBeforeOpen
	testHookAfterLstatMu.Unlock()
	if beforeOpen != nil {
		beforeOpen(path)
	}

	// No O_TRUNC: truncation happens AFTER verifyHandle (below), never before,
	// so a symlink swapped in after CheckSymlinkSafety cannot cause O_TRUNC to
	// clear an attacker-chosen target. openNoFollow makes the open itself fail
	// (ELOOP) if the final component is a symlink — atomic on unix; on platforms
	// without it, verifyHandle + truncate-after-verify are the backstop.
	flags := os.O_WRONLY | os.O_CREATE
	if !opts.AllowSymlink {
		// openNoFollow only when symlinks are disallowed; AllowSymlink callers
		// explicitly opt into following the link.
		flags |= openNoFollow
	}
	if !opts.Overwrite {
		flags |= os.O_EXCL
	}

	// #nosec G304 -- intentionally opens caller-supplied output paths after safety checks.
	f, err := os.OpenFile(path, flags, opts.Perm)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s (use --force to overwrite)", ErrFileExists, path)
		}
		return nil, fmt.Errorf("open file: %w", err)
	}

	if !opts.AllowSymlink {
		if err := verifyHandle(f, path); err != nil {
			// Best-effort close; returning the security error takes priority.
			_ = f.Close()
			return nil, err
		}
	}

	// Truncate only after the handle is verified as the intended (non-symlink)
	// target, so an overwrite can never clear a file we haven't confirmed.
	if opts.Overwrite {
		if truncErr := f.Truncate(0); truncErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("truncate: %w", truncErr)
		}
		if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("seek: %w", seekErr)
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
		if closeErr != nil {
			return errors.Join(fmt.Errorf("write: %w", writeErr), fmt.Errorf("close: %w", closeErr))
		}
		return fmt.Errorf("write: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close: %w", closeErr)
	}
	return nil
}

// SafeMkdirAll creates a directory tree, checking every path component for
// symlinks during creation (unless AllowSymlink). This prevents TOCTOU races
// that could occur between a pre-check and os.MkdirAll.
// testHookAfterLstat is called between the Lstat check and Mkdir call
// in SafeMkdirAll. Nil in production. Set in tests to inject TOCTOU
// race conditions for symlink swap testing.
//
// testHookAfterLstatMu guards both the read in SafeMkdirAll and any
// test code that writes the hook. -race flagged the unsynchronised
// read whenever a parallel test set the hook on a sibling goroutine;
// the hook is rare enough that the lock overhead is negligible.
// testHookBeforeOpen is called in SafeCreateFile between CheckSymlinkSafety and
// the os.OpenFile, to inject a TOCTOU path swap in tests. Nil in production.
// Guarded by testHookAfterLstatMu (same rationale as testHookAfterLstat).
var (
	testHookAfterLstat   func(component string)
	testHookBeforeOpen   func(path string)
	testHookAfterLstatMu sync.Mutex
)

func SafeMkdirAll(path string, opts WriteOptions) error {
	if opts.AllowSymlink {
		if err := os.MkdirAll(path, opts.Perm); err != nil {
			return fmt.Errorf("mkdir all: %w", err)
		}
		return nil
	}

	cleanPath := filepath.Clean(path)

	// 1. Find the deepest existing ancestor
	ancestor := cleanPath
	for range maxPathDepth {
		fi, err := os.Lstat(ancestor)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: %s (use --allow-symlink-output to override)", ErrSymlinkForbidden, ancestor)
			}
			if !fi.IsDir() {
				return fmt.Errorf("path component is not a directory: %s", ancestor)
			}
			break
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("security check failed for %q: %w", ancestor, err)
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			break
		}
		ancestor = parent
	}

	// 2. Get relative path from ancestor to cleanPath
	rel, err := filepath.Rel(ancestor, cleanPath)
	if err != nil {
		return fmt.Errorf("failed to get relative path from %q to %q: %w", ancestor, cleanPath, err)
	}
	if rel == "." {
		return nil // Target already exists and is valid
	}

	// 3. Create components from ancestor down
	components := strings.Split(rel, string(filepath.Separator))
	current := ancestor
	var createdByUs []string

	for _, part := range components {
		if part == "" || part == "." {
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
		testHookAfterLstatMu.Lock()
		hook := testHookAfterLstat
		testHookAfterLstatMu.Unlock()
		if hook != nil {
			hook(current)
		}
		if mkErr := os.Mkdir(current, opts.Perm); mkErr != nil && !os.IsExist(mkErr) {
			return fmt.Errorf("mkdir: %w", mkErr)
		}
		createdByUs = append(createdByUs, current)

		for _, p := range createdByUs {
			pfi, plstatErr := os.Lstat(p)
			if plstatErr != nil {
				return fmt.Errorf("post-mkdir verification failed for %q: %w", p, plstatErr)
			}
			if pfi.Mode()&os.ModeSymlink != 0 {
				_ = os.Remove(current)
				_ = os.Remove(p)
				return fmt.Errorf("%w: %s became a symlink during creation", ErrSymlinkForbidden, p)
			}
		}
	}
	return nil
}

// SafeOpenAppend opens a file for appending, enforcing symlink protection
// with post-open handle verification. Used for log files which are append-only.
//
// Caller must close the returned file to avoid leaking file descriptors.
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
			// Best-effort close; returning the security error takes priority.
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
			// Best-effort close in cleanup path.
			_ = tmpFile.Close()
		}
		if !committed {
			// Best-effort removal of incomplete temp file.
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
	// Close FIRST, then mark closed. The previous order set
	// closed=true ahead of the Close call — when Close returned an
	// error, the deferred cleanup skipped the second Close attempt
	// and the descriptor leaked alongside the error path.
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	closed = true

	// Attempt atomic rename — works when src and dst are on the same fs.
	if renameErr := os.Rename(tmpPath, path); renameErr == nil {
		// Mark committed BEFORE the post-rename safety check. The
		// rename has already moved our content into place; if the
		// defense-in-depth check below fails we want to surface the
		// failure to the caller WITHOUT having the deferred cleanup
		// path unlink the just-renamed destination. The earlier
		// order (check first, then committed = true) silently
		// deleted the operator's freshly-written file on a check
		// failure.
		const persistenceGuaranteed = true
		committed = persistenceGuaranteed

		// Post-rename TOCTOU verification: an attacker who swapped
		// the destination (or one of its parents) to a symlink
		// between the initial CheckSymlinkSafety and the rename
		// above would have had our temp file end up at the symlink
		// target. This is defense-in-depth, not a primitive — Go
		// does not expose openat-style atomic operations that would
		// close the race entirely; the post-check catches the swap
		// after the fact so the caller sees the breach instead of
		// trusting a corrupted destination.
		isDestinationHijacked := CheckSymlinkSafety(path) != nil
		if isDestinationHijacked {
			return errors.New("post-rename symlink check (defense-in-depth): destination swapped during write")
		}
		return nil
	}

	// Fallback: copy-then-delete for cross-filesystem case.
	if cpErr := crossFSCopy(tmpPath, path, perm); cpErr != nil {
		return fmt.Errorf("cross-filesystem fallback: %w", cpErr)
	}
	committed = true
	// Best-effort cleanup; data is already at dst via cross-fs copy.
	_ = os.Remove(tmpPath)
	return nil
}

// crossFSCopy copies a file when os.Rename fails across filesystems.
// Uses temp-then-rename in the destination directory to prevent
// truncation of the destination on a mid-copy crash.
func crossFSCopy(src, dst string, perm os.FileMode) error {
	data, err := os.ReadFile(src) //nolint:gosec // temp file we just created
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".stave-xfscopy-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// renamed flips to true after a successful os.Rename so the
	// defer skips the cleanup. The earlier defer ran unconditionally,
	// which on a successful path issued an os.Remove against the
	// new destination's path (since rename moves the inode under
	// the new name) — harmless on POSIX but visible in audit
	// instrumentation (extra syscall, ENOENT noise) and a foot-gun
	// if a future filesystem treats the path-after-rename specially.
	// Mirrors the `committed` sentinel pattern in WriteFileAtomic.
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	_, err = tmp.Write(data)
	if err != nil {
		// Surface a Close error alongside the original Write failure
		// instead of dropping it silently. Disk-full / NFS / quota
		// failures often surface only at Close (deferred metadata
		// writeback), and silencing them masks the real cause when
		// triaging a partial copy. Defer handles temp file removal.
		return errors.Join(err, tmp.Close())
	}
	err = tmp.Chmod(perm)
	if err != nil {
		return errors.Join(err, tmp.Close())
	}
	err = tmp.Sync()
	if err != nil {
		return errors.Join(err, tmp.Close())
	}
	// Capture the close error explicitly: even after a successful
	// Sync, Close can still return errors for buffered metadata
	// flushes or filesystem-level reservations. The earlier shape
	// dropped the close error and proceeded to rename; if the close
	// failed (a stale NFS handle, a quota bump after Sync, etc.) we
	// could rename a partially flushed temp into the destination
	// while reporting success. Surface it instead — defer cleans up
	// the abandoned temp.
	if closeErr := tmp.Close(); closeErr != nil {
		return fmt.Errorf("close temp before rename: %w", closeErr)
	}

	// Pre-rename TOCTOU check on the destination: between the
	// initial caller-side CheckSymlinkSafety and now, an attacker
	// could have swapped dst (or a parent) to a symlink. Catch
	// it here so the upcoming Rename doesn't unwittingly land
	// our temp at the symlink target.
	if symErr := CheckSymlinkSafety(dst); symErr != nil {
		return fmt.Errorf("pre-rename symlink check: %w", symErr)
	}

	if err = os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	renamed = true

	// Fsync the parent directory so the rename itself is durable. Without
	// this, a crash between rename and the OS's next flush can leave the
	// destination's directory entry unpersisted — on some filesystems that
	// manifests as a zero-byte or missing destination after reboot.
	//
	// Treat sync failure as a warning, not a fatal error: by this
	// point the rename has succeeded, the file is durably committed
	// at the inode level, and the only outstanding question is
	// whether the parent directory's metadata is flushed. Some
	// filesystems (tmpfs, virtio-9p, certain network mounts) reject
	// directory fsync with EINVAL or ENOTSUP; the earlier shape
	// turned that into a hard failure for callers who had already
	// successfully written and renamed.
	d, openErr := os.Open(dir) //nolint:gosec // directory path from caller's dst
	if openErr != nil {
		// Intentional discard: rename already succeeded, so the data is
		// durably committed at the inode level. Failing to open the
		// parent directory only means we cannot fsync its metadata —
		// some filesystems (tmpfs, virtio-9p, certain network mounts)
		// reject directory open/sync. Surface the warning via slog so
		// operators can see the degraded durability mode without
		// turning a successful write into a failure.
		slog.Warn("crossFSCopy: parent-dir open after rename failed; rename succeeded but durability not enforced",
			"dir", dir, "error", openErr)
		return nil
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		slog.Warn("crossFSCopy: parent-dir sync after rename failed; rename succeeded but durability not enforced",
			"dir", dir, "error", syncErr)
		// Fall through — close error (if any) still surfaces below.
	}
	if closeErr != nil {
		return fmt.Errorf("close parent dir: %w", closeErr)
	}
	return nil
}
