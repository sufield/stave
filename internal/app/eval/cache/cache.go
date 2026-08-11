// Package assessmentcache stores compiled ComplianceReports keyed
// by (StaveVersion, controls-digest, input-hashes-overall) so a
// stave-apply run with unchanged inputs short-circuits the engine
// and returns the previously-computed report.
//
// The cache is content-addressed: the key is a deterministic hash
// of everything that affects the report. A change to any control
// YAML, any observation snapshot, or the stave binary version
// rotates the key and triggers a fresh evaluation; an unchanged
// run hits the cache and skips compilation + evaluation + risk
// reasoning entirely.
//
// Wire format mirrors internal/adapters/cel/persist.go's atomic-
// rename + magic-header + format-version pattern so a reader who
// learned that one reads this one without re-learning.
package cache

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

const (
	cacheMagic = "STVA" // STaVe Assessment
	// cacheFormatVersion is bumped to 2: the body JSON drops
	// ComplianceReport.Metadata (it is json:"-", excluded from the
	// report's own wire contract) so the cache now carries Metadata as
	// its own JSON segment and re-attaches it on load. Without this a
	// cache HIT replayed a report with empty Metadata, which silently
	// dropped the output extensions block (Metadata feeds
	// ToExtensions()). Bumping the version invalidates v1 entries,
	// which the decoder treats as a clean miss.
	cacheFormatVersion = 2
	disableEnv         = "STAVE_DISABLE_ASSESSMENT_CACHE"
)

// IsDisabled reports whether the cache is short-circuited by the
// kill-switch env var. Operators set STAVE_DISABLE_ASSESSMENT_CACHE
// to any non-empty value to bypass both load and persist — useful
// when debugging a suspected stale-cache issue or proving the
// engine still works without the cache.
func IsDisabled() bool {
	return os.Getenv(disableEnv) != ""
}

// DefaultCacheDir returns $XDG_CACHE_HOME/stave/assessments/v1 (or
// the platform equivalent). Empty string + nil error means the OS
// could not resolve a cache dir; callers treat that as "no cache,
// run normally" rather than as a hard failure.
func DefaultCacheDir() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", nil //nolint:nilerr // missing cache dir is "no cache", not an error
	}
	return filepath.Join(root, "stave", "assessments", "v1"), nil
}

// Key is the cache key carried alongside a cached report. Stored
// in the file so a corrupted cache surfaces as a mismatch rather
// than a wrong-report substitution.
//
// Every field that AFFECTS the cached report shape must flow into
// the key. The current set covers: the stave binary version
// (catches a binary upgrade that changes report fields), the
// controls catalog (any YAML edit), the observations
// (InputHashes.Overall), the chain definitions (any change
// rotates the risk-reasoning output), and the assessment config
// (SLA rules, exemptions, exceptions, acknowledgments — all of
// which mutate findings in-place during the engine pass).
//
// Excluded from the key:
//   - Clock now-value: cached reports may have stale SLA deadlines
//     when replayed later; the caller should re-run SLA annotation
//     after a cache hit if it wants fresh deadlines.
//
// SourcePaths is foundational for correctness: the report embeds
// the controls / observations directory paths in Run.ResolvedPaths.
// Two assessment runs with structurally identical inputs at
// different on-disk locations (e.g. two e2e fixtures with the
// same YAML at different testdata/e2e/<name>/ dirs) would
// otherwise share a cache key, and the second run would
// short-circuit and serve the first run's report with the wrong
// embedded paths.
type Key struct {
	StaveVersion    string
	EvalVersion     string // engine evaluation semantics version (stave-cel/1.x)
	ControlsDigest  string
	InputHashesHash string
	ChainsDigest    string
	ConfigDigest    string
	SourcePaths     string // SHA-256 of controls-dir|observations-dir
}

// Hex returns the hex-encoded composite key. Used as the cache
// file basename and as the integrity check on load.
func (k Key) Hex() string {
	h := sha256.New()
	for _, field := range []string{
		k.StaveVersion,
		k.EvalVersion,
		k.ControlsDigest,
		k.InputHashesHash,
		k.ChainsDigest,
		k.ConfigDigest,
		k.SourcePaths,
	} {
		h.Write([]byte(field))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeControlsDigest produces a stable SHA-256 over the
// canonical JSON encoding of the controls slice, sorted by ID so
// the digest doesn't drift if the loader changes its enumeration
// order.
//
// Stable JSON: we sort the controls by ID and marshal each one with
// encoding/json (which already sorts map keys), then concatenate.
// Anything that mutates a control's predicate, severity, parameters,
// or applicable types flows into the bytes and rotates the digest.
func ComputeControlsDigest(controls []policy.ControlDefinition) string {
	idx := make([]int, len(controls))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		return cmp.Compare(controls[a].ID, controls[b].ID)
	})
	h := sha256.New()
	for _, i := range idx {
		// Marshal each control independently so a re-ordering
		// within the slice (without ID change) doesn't affect the
		// digest, but ANY field mutation does.
		b, err := json.Marshal(controls[i])
		if err != nil {
			// Marshal of a typed struct with JSON-tagged fields
			// should not fail; if it does, fall back to the ID
			// alone so the digest still completes (the cache
			// just won't catch the mutation). Surface a separator
			// so an unmarshalable control doesn't silently collide
			// with a different one.
			h.Write([]byte(controls[i].ID))
			h.Write([]byte{0xFF})
			continue
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeChainsDigest hashes the chain-definition slice in stable
// order. Any chain edit (controls list, threshold, severity)
// flows into the hash and rotates the cache key, so a chain-
// definition change cannot serve a stale risk-reasoning result.
func ComputeChainsDigest(chains []policy.ChainDefinition) string {
	if len(chains) == 0 {
		return "no-chains"
	}
	idx := make([]int, len(chains))
	for i := range idx {
		idx[i] = i
	}
	slices.SortStableFunc(idx, func(a, b int) int {
		return cmp.Compare(chains[a].ID, chains[b].ID)
	})
	h := sha256.New()
	for _, i := range idx {
		b, err := json.Marshal(chains[i])
		if err != nil {
			h.Write([]byte(chains[i].ID))
			h.Write([]byte{0xFF})
			continue
		}
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeConfigDigest hashes the assessment-configuration values
// that mutate the final report — SLA threshold, exemption rules,
// exception rules, acknowledgment rules. Each is JSON-marshalled
// independently so a nil pointer hashes distinguishably from an
// empty struct.
//
// Inputs intentionally NOT in this digest:
//   - Clock: cached reports tolerate stale "now" values; callers
//     should re-run any clock-dependent annotation after a cache
//     hit (e.g. SLA deadline computation).
//   - Output writer, Hasher, Tracer: pure side-effect channels,
//     they don't shape the report.
//   - PredicateParser, PredicateEval: their behaviour is
//     transitively captured by ControlsDigest (a change to a
//     parser/eval implementation that produces different verdicts
//     would also require a controls-catalog rebuild that rotates
//     ControlsDigest). When that assumption breaks, bump
//     cacheFormatVersion.
type ConfigForDigest struct {
	SLAThreshold        string                       `json:"sla_threshold,omitempty"`
	ExemptionRules      *policy.ExemptionConfig      `json:"exemption_rules,omitempty"`
	ExceptionRules      *policy.ExceptionConfig      `json:"exception_rules,omitempty"`
	AcknowledgmentRules *policy.AcknowledgmentConfig `json:"acknowledgment_rules,omitempty"`
	BuildVersion        string                       `json:"build_version,omitempty"`
}

func ComputeConfigDigest(c ConfigForDigest) string {
	b, err := json.Marshal(c)
	if err != nil {
		// json.Marshal of typed structs with JSON tags should not
		// fail; the fallback hashes the SLA + build-version
		// strings alone so the digest still completes.
		h := sha256.New()
		h.Write([]byte(c.SLAThreshold))
		h.Write([]byte{0})
		h.Write([]byte(c.BuildVersion))
		return hex.EncodeToString(h.Sum(nil))
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ComputeSourcePathsKey hashes the controls and observations source
// paths so two assessment runs with structurally identical inputs
// at different on-disk locations get distinct cache keys. The
// report embeds these paths in Run.ResolvedPaths; serving a cached
// report under a different path produces the wrong output.
//
// Empty input is fine — produces a stable empty-paths digest that
// older callers without this field continue to hash to. Going
// forward, every caller should pass the real values; the empty-
// digest constant is preserved only so an in-flight cache file from
// the previous schema version can be invalidated cleanly when the
// field is added to a key.
func ComputeSourcePathsKey(controlsDir, observationsDir string) string {
	h := sha256.New()
	h.Write([]byte(controlsDir))
	h.Write([]byte{0})
	h.Write([]byte(observationsDir))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeInputHashesKey returns the canonical key derived from an
// InputHashes value. Prefers Overall (the aggregate the loader
// already computes); if absent, hashes the per-file digests.
func ComputeInputHashesKey(h *evaluation.InputHashes) string {
	if h == nil {
		return ""
	}
	if h.Overall != "" {
		return string(h.Overall)
	}
	// Defensive: build a deterministic substitute from per-file
	// entries so we still produce A key (not the empty key) when
	// Overall is missing. Keys sorted so iteration order doesn't
	// affect the hash.
	paths := make([]evaluation.FilePath, 0, len(h.Files))
	for p := range h.Files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	hash := sha256.New()
	for _, p := range paths {
		hash.Write([]byte(p))
		hash.Write([]byte{0})
		hash.Write([]byte(h.Files[p]))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Cache is the load/persist interface. Threadsafe; callers may
// share one Cache across goroutines.
type Cache struct {
	dir string
	mu  sync.Mutex // serialises atomic rename writes per-file
}

// New constructs a Cache rooted at dir. Empty dir disables the
// cache entirely — Load returns (zero, false) and Persist is a
// no-op. This is the shape callers want when the platform has no
// cache directory (DefaultCacheDir returned "") so they don't have
// to wrap every call in a nil-check.
func New(dir string) *Cache {
	return &Cache{dir: dir}
}

// Load returns the cached report for the key, or false if missing /
// corrupted / kill-switched. Never returns an error: a missing or
// corrupted cache must never block evaluation. A corrupted entry
// is logged and treated as a miss; the caller runs the engine and
// the next Persist rewrites the file.
func (c *Cache) Load(k Key) (evaluation.ComplianceReport, bool) {
	if c == nil || c.dir == "" || IsDisabled() {
		return evaluation.ComplianceReport{}, false
	}
	data, err := os.ReadFile(c.path(k)) //nolint:gosec // path derived from operator cache dir
	if err != nil {
		return evaluation.ComplianceReport{}, false
	}
	var report evaluation.ComplianceReport
	storedKey, ok := decode(data, &report)
	if !ok {
		return evaluation.ComplianceReport{}, false
	}
	// Per-entry integrity check: the key embedded in the file must
	// match the key we just computed. A mismatch means the file
	// was edited, corrupted, or the file basename was renamed
	// independently of its contents — never serve the report.
	if storedKey != k.Hex() {
		return evaluation.ComplianceReport{}, false
	}
	return report, true
}

// Persist writes the report under the key. Atomic rename so a
// concurrent reader sees either no file or the full file; never a
// torn write.
func (c *Cache) Persist(k Key, report *evaluation.ComplianceReport) error {
	if c == nil || c.dir == "" || IsDisabled() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.MkdirAll(c.dir, 0o750); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}
	buf, err := encode(k.Hex(), report)
	if err != nil {
		return fmt.Errorf("encode cache entry: %w", err)
	}
	tmp, err := os.CreateTemp(c.dir, ".assess-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write cache: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync cache: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close cache: %w", err)
	}
	if err := os.Rename(tmpPath, c.path(k)); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename cache: %w", err)
	}
	return nil
}

func (c *Cache) path(k Key) string {
	return filepath.Join(c.dir, k.Hex()+".json")
}

// Wire format:
//   [4-byte magic 'STVA'][4-byte format version (LE uint32)]
//   [4-byte key-hex-length (LE uint32)][key-hex bytes]
//   [4-byte report-json-length (LE uint32)][report-json bytes]
//   [4-byte metadata-json-length (LE uint32)][metadata-json bytes]
//
// The key-hex prefix lets the loader fail FAST on a stale or
// tampered cache file before trying to decode the report body.
//
// Metadata is encoded as its own trailing segment because
// ComplianceReport.Metadata is json:"-" — it is excluded from the
// report's own wire contract and would otherwise vanish across the
// cache's JSON round-trip, silently dropping the output extensions
// block on a cache hit.

func encode(keyHex string, report *evaluation.ComplianceReport) ([]byte, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	meta, err := json.Marshal(report.Metadata)
	if err != nil {
		return nil, err
	}
	if !fitsUint32(len(keyHex)) || !fitsUint32(len(body)) || !fitsUint32(len(meta)) {
		return nil, errors.New("cache entry exceeds uint32 length prefix")
	}
	var buf []byte
	buf = append(buf, []byte(cacheMagic)...)
	buf = appendUint32(buf, cacheFormatVersion)
	buf = appendUint32(buf, uint32(len(keyHex))) //nolint:gosec // guarded by fitsUint32
	buf = append(buf, keyHex...)
	buf = appendUint32(buf, uint32(len(body))) //nolint:gosec // guarded by fitsUint32
	buf = append(buf, body...)
	buf = appendUint32(buf, uint32(len(meta))) //nolint:gosec // guarded by fitsUint32
	buf = append(buf, meta...)
	return buf, nil
}

func decode(data []byte, report *evaluation.ComplianceReport) (string, bool) {
	if len(data) < len(cacheMagic)+4 {
		return "", false
	}
	if string(data[:len(cacheMagic)]) != cacheMagic {
		return "", false
	}
	pos := len(cacheMagic)
	formatVer := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	if formatVer != cacheFormatVersion {
		return "", false
	}
	if pos+4 > len(data) {
		return "", false
	}
	keyLen := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	// Bounds checks use uint64 arithmetic so a keyLen/bodyLen >= 2^31
	// (crafted or corrupt cache file) cannot wrap int() negative on
	// 32-bit builds and slip past the guard into a panicking slice. The
	// encode path guards with fitsUint32; this is the symmetric decode
	// guard.
	if uint64(pos)+uint64(keyLen) > uint64(len(data)) { //nolint:gosec // pos and len(data) are non-negative byte offsets; uint64 widening only
		return "", false
	}
	keyHex := string(data[pos : pos+int(keyLen)])
	pos += int(keyLen)
	if pos+4 > len(data) {
		return "", false
	}
	bodyLen := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	if uint64(pos)+uint64(bodyLen) > uint64(len(data)) { //nolint:gosec // pos and len(data) are non-negative byte offsets; uint64 widening only
		return "", false
	}
	if err := json.Unmarshal(data[pos:pos+int(bodyLen)], report); err != nil {
		return "", false
	}
	pos += int(bodyLen)
	// Metadata segment: json:"-" excludes it from the report body, so
	// it is carried separately and re-attached here. A v2 entry always
	// has it; the format-version guard above rejects v1 files before
	// reaching this point.
	if pos+4 > len(data) {
		return "", false
	}
	metaLen := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	if uint64(pos)+uint64(metaLen) > uint64(len(data)) { //nolint:gosec // pos and len(data) are non-negative byte offsets; uint64 widening only
		return "", false
	}
	if err := json.Unmarshal(data[pos:pos+int(metaLen)], &report.Metadata); err != nil {
		return "", false
	}
	return keyHex, true
}

// Suppress unused warnings — the type is part of the public package
// API but the standard test fixtures don't currently reach for it
// from outside this file.
var _ kernel.Digest = kernel.Digest("")

func appendUint32(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

func fitsUint32(n int) bool {
	return n >= 0 && uint64(n) <= 0xffffffff
}
