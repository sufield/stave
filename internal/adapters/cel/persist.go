package cel

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"

	"github.com/google/cel-go/cel"
	"google.golang.org/protobuf/proto"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// Disk cache wire format
// ----------------------
// A single binary file holds every cached predicate. Layout:
//
//   [4-byte magic 'STVC'][4-byte format version (LE uint32)]
//   [4-byte cel-go-version-length (LE uint32)][cel-go-version bytes]
//   [8-byte entry count (LE uint64)]
//   for each entry:
//     [32-byte SHA-256 of expression string]
//     [4-byte expression length (LE uint32)][expression bytes]
//     [4-byte CheckedExpr length (LE uint32)][CheckedExpr proto bytes]
//
// The header carries cel-go's build version so a cel-go upgrade
// triggers a full reload (CheckedExpr semantics could shift between
// minor versions, even if rare). Format version is bumped if this
// layout ever changes.
//
// The per-entry SHA is the foundational correctness check: every
// load recomputes the SHA from the live expression string and
// compares it against the on-disk header before handing the
// CheckedExpr to env.Program. A mismatch means the cache file was
// edited, corrupted, or collided — that entry is dropped, a warning
// is logged, and the predicate recompiles from source.

const (
	cacheMagic         = "STVC"
	cacheFormatVersion = 1
	cacheFileName      = "cache.pb"
	// disableCacheEnv toggles the on-disk CEL compile cache off
	// entirely. Set to any non-empty value to short-circuit both
	// load and persist. The flag exists so an operator can roll
	// back the optimisation without redeploying.
	disableCacheEnv = "STAVE_DISABLE_CEL_CACHE"
)

// cachedEntry is the in-memory representation of one persisted
// predicate. It deliberately holds the raw CheckedExpr proto rather
// than a cel.Program: env.Program(ast) must run against the *live*
// environment, so program reconstruction is the consumer's job.
type cachedEntry struct {
	ExpressionSHA [32]byte
	Expression    string
	CheckedExpr   *exprpb.CheckedExpr
}

// celGoVersion is detected once at process start from the build
// info. Stored as a package-level so the cache header writer and the
// reader compare the same value without re-walking module deps on
// every load.
var (
	celGoVersionOnce sync.Once
	celGoVersionVal  string
)

func celGoVersion() string {
	celGoVersionOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			celGoVersionVal = "unknown"
			return
		}
		for _, dep := range info.Deps {
			if dep.Path == "github.com/google/cel-go" {
				celGoVersionVal = dep.Version
				return
			}
		}
		celGoVersionVal = "unknown"
	})
	return celGoVersionVal
}

// IsCacheDisabled reports whether the persist layer should
// short-circuit. Checked by Compiler.LoadCache / PersistCache so the
// kill-switch covers both directions.
func IsCacheDisabled() bool {
	return os.Getenv(disableCacheEnv) != ""
}

// DefaultCacheDir returns the conventional location for the cache
// file under XDG_CACHE_HOME (or os.UserCacheDir as the fallback).
// Returns an empty string and a nil error if the OS could not
// resolve a cache dir — callers should treat that as "do not
// cache" rather than as a hard failure.
func DefaultCacheDir() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", nil //nolint:nilerr // intentional: missing cache dir is not an error, just no caching
	}
	return filepath.Join(root, "stave", "cel", "v1"), nil
}

// cacheFilePath returns the cache file path inside dir. Centralised
// so the load and persist sides cannot drift.
func cacheFilePath(dir string) string { return filepath.Join(dir, cacheFileName) }

// loadCacheFile reads and decodes the on-disk cache file. A missing
// file is not an error (returns (nil, nil)) — it just means cold
// start. Any other decode failure surfaces so the caller can warn
// and fall back to recompilation.
func loadCacheFile(path string) ([]cachedEntry, error) {
	// gosec G304: the path is derived from the operator-controlled
	// cache directory option (WithCacheDir) or the OS user-cache
	// dir; both are trusted inputs. The contents are validated by
	// magic, format-version, cel-go-version, and per-entry SHA
	// before any cached AST is trusted — see decodeCache + the
	// loadDiskCache poisoning defense in compiler.go.
	data, err := os.ReadFile(path) //nolint:gosec // see comment above
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache file: %w", err)
	}
	return decodeCache(data)
}

// decodeCache parses the binary cache wire format. Defensive against
// truncation at every length-prefix step: a half-written file
// surfaces as a decode error here, the caller drops the cache, and
// the next persist rewrites it.
func decodeCache(data []byte) ([]cachedEntry, error) {
	r := byteReader{buf: data}
	if !r.consumeMagic() {
		return nil, errors.New("cache: bad magic")
	}
	formatVer, ok := r.readUint32()
	if !ok {
		return nil, errors.New("cache: truncated header")
	}
	if formatVer != cacheFormatVersion {
		return nil, fmt.Errorf("cache: format version %d, want %d", formatVer, cacheFormatVersion)
	}
	celVer, ok := r.readLengthPrefixed()
	if !ok {
		return nil, errors.New("cache: truncated cel-go version")
	}
	if string(celVer) != celGoVersion() {
		return nil, fmt.Errorf("cache: cel-go version mismatch (%s != %s)", string(celVer), celGoVersion())
	}
	count, ok := r.readUint64()
	if !ok {
		return nil, errors.New("cache: truncated entry count")
	}
	entries := make([]cachedEntry, 0, count)
	for i := range count {
		var sha [32]byte
		if !r.readInto(sha[:]) {
			return nil, fmt.Errorf("cache: truncated SHA at entry %d", i)
		}
		expr, ok := r.readLengthPrefixed()
		if !ok {
			return nil, fmt.Errorf("cache: truncated expression at entry %d", i)
		}
		exprBytes, ok := r.readLengthPrefixed()
		if !ok {
			return nil, fmt.Errorf("cache: truncated checked-expr at entry %d", i)
		}
		ce := &exprpb.CheckedExpr{}
		if err := proto.Unmarshal(exprBytes, ce); err != nil {
			return nil, fmt.Errorf("cache: unmarshal checked-expr at entry %d: %w", i, err)
		}
		entries = append(entries, cachedEntry{
			ExpressionSHA: sha,
			Expression:    string(expr),
			CheckedExpr:   ce,
		})
	}
	return entries, nil
}

// persistCacheFile encodes entries and atomically writes them to
// path. Atomicity comes from writing a sibling .tmp file and
// renaming — POSIX guarantees rename-within-directory is atomic, so
// no reader ever sees a half-written file.
//
// Concurrent writers race to the rename: last-rename-wins. The cache
// is content-equivalent (every writer is deriving the same
// CheckedExprs from the same source), so a lost write costs at most
// one extra warm-up.
func persistCacheFile(path string, entries []cachedEntry) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".cache-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(encodeCache(entries)); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write cache temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync cache temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close cache temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

// encodeCache produces the binary blob written to disk. The wire
// format uses uint32 length prefixes, so any field exceeding ~4 GB
// would silently truncate. Real CEL expressions and CheckedExpr
// protos are kilobyte-scale, so the bound is a sanity check rather
// than a feature: an entry that hits it indicates upstream corruption
// and is dropped (logged at write time would be wrong since this
// helper is also called from tests; the drop is silent and the next
// cold start regenerates).
func encodeCache(entries []cachedEntry) []byte {
	var buf []byte
	buf = append(buf, []byte(cacheMagic)...)
	buf = appendUint32(buf, cacheFormatVersion)
	cv := []byte(celGoVersion())
	if !fitsUint32(len(cv)) {
		return nil
	}
	buf = appendUint32(buf, uint32(len(cv))) //nolint:gosec // guarded by fitsUint32
	buf = append(buf, cv...)
	buf = appendUint64(buf, uint64(len(entries)))
	for _, e := range entries {
		buf = append(buf, e.ExpressionSHA[:]...)
		if !fitsUint32(len(e.Expression)) {
			continue
		}
		buf = appendUint32(buf, uint32(len(e.Expression))) //nolint:gosec // guarded by fitsUint32
		buf = append(buf, e.Expression...)
		// proto.Marshal on a CheckedExpr is deterministic enough for
		// cache stability across runs of the same cel-go version; we
		// don't enforce stable byte equality because the cache is
		// keyed by SHA-of-expression, not SHA-of-program-bytes.
		ceBytes, _ := proto.Marshal(e.CheckedExpr)
		if !fitsUint32(len(ceBytes)) {
			continue
		}
		buf = appendUint32(buf, uint32(len(ceBytes))) //nolint:gosec // guarded by fitsUint32
		buf = append(buf, ceBytes...)
	}
	return buf
}

// fitsUint32 guards length-prefix conversions against the int → uint32
// narrowing that gosec G115 flags. Centralised so the bound is named
// once and the per-field check sites are uniform.
func fitsUint32(n int) bool {
	const uint32Max = int(^uint32(0))
	return n >= 0 && n <= uint32Max
}

// hashExpression computes the SHA-256 used as the cache key for a
// CEL expression string. Stable across runs by construction; the
// hash space is wide enough that a collision is impossible in
// practice, so equality of hashes is treated as equality of
// expressions.
func hashExpression(expr string) [32]byte {
	return sha256.Sum256([]byte(expr))
}

// hashExpressionHex returns the lowercase hex form, used in log
// lines so the operator can grep cache hits/misses by ID.
func hashExpressionHex(expr string) string {
	h := hashExpression(expr)
	return hex.EncodeToString(h[:])
}

// astToCheckedExpr / checkedExprToAst are thin wrappers over the
// cel-go round-trip API. Centralised here so the type imports leak
// only across this file and so the persist layer can switch to a
// different round-trip format (e.g. cached Program bytes if cel-go
// ever ships one) by changing only these two helpers.
func astToCheckedExpr(a *cel.Ast) (*exprpb.CheckedExpr, error) {
	ce, err := cel.AstToCheckedExpr(a)
	if err != nil {
		return nil, fmt.Errorf("ast to checked-expr: %w", err)
	}
	return ce, nil
}

func checkedExprToAst(ce *exprpb.CheckedExpr) *cel.Ast {
	return cel.CheckedExprToAst(ce)
}

// --- binary helpers -------------------------------------------------------

func appendUint32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendUint64(b []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(b, tmp[:]...)
}

// byteReader is a minimal forward-only decoder so the cache parser
// does not pull in encoding/gob, encoding/json, or a third-party
// codec. Every "read" advances the cursor and returns a bool so the
// caller can attribute truncation errors precisely.
type byteReader struct {
	buf []byte
	pos int
}

func (r *byteReader) consumeMagic() bool {
	if len(r.buf) < len(cacheMagic) {
		return false
	}
	if string(r.buf[:len(cacheMagic)]) != cacheMagic {
		return false
	}
	r.pos = len(cacheMagic)
	return true
}

func (r *byteReader) readUint32() (uint32, bool) {
	if r.pos+4 > len(r.buf) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *byteReader) readUint64() (uint64, bool) {
	if r.pos+8 > len(r.buf) {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, true
}

func (r *byteReader) readLengthPrefixed() ([]byte, bool) {
	n, ok := r.readUint32()
	if !ok {
		return nil, false
	}
	if r.pos+int(n) > len(r.buf) {
		return nil, false
	}
	out := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, true
}

func (r *byteReader) readInto(dst []byte) bool {
	if r.pos+len(dst) > len(r.buf) {
		return false
	}
	copy(dst, r.buf[r.pos:r.pos+len(dst)])
	r.pos += len(dst)
	return true
}

// unused but exported so test helpers can build a corrupted reader
// without copying the type.
var _ io.Reader = (*byteReader)(nil)

func (r *byteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}
