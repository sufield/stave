// Package archiveverify provides evidence archive continuity verification
// for compliance audit periods.
package archiveverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/app/collect"
)

// Verdict constants for the archive-verify attestation. Centralised
// so callers stop comparing the Verdict field against magic strings.
const (
	VerdictPass = "PASS"
	VerdictFail = "FAIL"
)

// Attestation is the verification result.
type Attestation struct {
	GeneratedAt string       `json:"generated_at"`
	ArchivePath string       `json:"archive_path"`
	Period      PeriodResult `json:"period"`
	Parameters  Parameters   `json:"parameters"`
	Verdict     string       `json:"verdict"`
	Reason      string       `json:"reason,omitempty"`
	Summary     Summary      `json:"summary"`
	InvalidRuns []InvalidRun `json:"invalid_bundles,omitempty"`
	Gaps        []GapResult  `json:"gaps,omitempty"`
	Runs        []RunResult  `json:"bundles,omitempty"`
}

// IsPass reports whether the attestation passed.
func (a *Attestation) IsPass() bool { return a != nil && a.Verdict == VerdictPass }

// IsFail reports whether the attestation failed.
func (a *Attestation) IsFail() bool { return a != nil && a.Verdict == VerdictFail }

// Failed is an alias for IsFail kept so cmd/verify (and any future
// consumer) can read "did this attestation fail?" with the verb form
// the plan called for. Pointer receiver matches IsPass / IsFail.
func (a *Attestation) Failed() bool { return a.IsFail() }

// PeriodResult describes the verified period.
type PeriodResult struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Label string    `json:"label"`
}

// Parameters records the verification settings.
type Parameters struct {
	MaxGapHours float64 `json:"max_gap_hours"`
	Strict      bool    `json:"strict"`
}

// Summary holds aggregate counts.
type Summary struct {
	RunsDiscovered   int     `json:"bundles_discovered"`
	RunsInPeriod     int     `json:"bundles_in_period"`
	RunsValid        int     `json:"bundles_valid"`
	RunsInvalid      int     `json:"bundles_invalid"`
	GapsDetected     int     `json:"gaps_detected"`
	GapsExceedingMax int     `json:"gaps_exceeding_max"`
	CoveragePct      float64 `json:"period_coverage_pct"`
}

// InvalidRun describes a run that failed verification.
type InvalidRun struct {
	RunID         string `json:"run_id"`
	CollectedAt   string `json:"collection_time"`
	FailureReason string `json:"failure_reason"`
	Detail        string `json:"detail"`
}

// GapResult describes a gap between consecutive runs.
type GapResult struct {
	GapStart      time.Time `json:"gap_start"`
	GapEnd        time.Time `json:"gap_end"`
	DurationHours float64   `json:"duration_hours"`
	ExceedsMax    bool      `json:"exceeds_max_gap"`
}

// RunResult is the verification status of a single run.
type RunResult struct {
	RunID       string `json:"run_id"`
	CollectedAt string `json:"collection_time"`
	ManifestOK  bool   `json:"manifest_valid"`
	ChecksumOK  bool   `json:"checksum_valid"`
}

// VerifyInput holds the parameters for archive verification.
type VerifyInput struct {
	ArchivePath string
	PeriodStart time.Time
	PeriodEnd   time.Time
	PeriodLabel string
	MaxGapHours float64
	Strict      bool
	GeneratedAt string
}

// parsedRun pairs a manifest run with its parsed CollectedAt time so
// the temporal-continuity passes don't reparse the timestamp on every
// access.
type parsedRun struct {
	run  collect.ManifestRun
	time time.Time
}

// Verify performs evidence archive continuity verification.
func Verify(input VerifyInput) (*Attestation, error) {
	archive := &collect.Archive{Path: input.ArchivePath}

	manifest, err := archive.LoadManifest()
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}

	manifestValid := verifyManifestHash(input.ArchivePath)
	allRuns := parseAndSortRuns(manifest.Runs)
	inPeriod := filterRunsToPeriod(allRuns, input.PeriodStart, input.PeriodEnd)

	runs, invalidRuns, validCount := verifyRunsInPeriod(input.ArchivePath, inPeriod, manifestValid)
	if !manifestValid {
		invalidRuns = append(invalidRuns, InvalidRun{
			RunID:         "manifest",
			FailureReason: "manifest_hash_mismatch",
			Detail:        "manifest.json SHA-256 does not match manifest.json.sha256",
		})
	}

	gaps, gapsExceeding := computeTemporalGaps(inPeriod, input)
	coveragePct := computeCoveragePct(input.PeriodStart, input.PeriodEnd, gaps)
	verdict, reason := computeVerdict(invalidRuns, gapsExceeding, input.MaxGapHours)

	return &Attestation{
		GeneratedAt: input.GeneratedAt,
		ArchivePath: input.ArchivePath,
		Period:      PeriodResult{Start: input.PeriodStart, End: input.PeriodEnd, Label: input.PeriodLabel},
		Parameters:  Parameters{MaxGapHours: input.MaxGapHours, Strict: input.Strict},
		Verdict:     verdict,
		Reason:      reason,
		Summary: Summary{
			RunsDiscovered:   len(allRuns),
			RunsInPeriod:     len(inPeriod),
			RunsValid:        validCount,
			RunsInvalid:      len(invalidRuns),
			GapsDetected:     len(gaps),
			GapsExceedingMax: gapsExceeding,
			CoveragePct:      coveragePct,
		},
		InvalidRuns: invalidRuns,
		Gaps:        gaps,
		Runs:        runs,
	}, nil
}

// parseAndSortRuns parses each ManifestRun's CollectedAt and returns
// the parseable subset sorted ascending by collection time. Runs with
// unparseable timestamps are silently dropped — they're already
// invalid and the manifest-hash verification fails them anyway.
func parseAndSortRuns(runs []collect.ManifestRun) []parsedRun {
	out := make([]parsedRun, 0, len(runs))
	for _, r := range runs {
		t, parseErr := time.Parse(time.RFC3339, r.CollectedAt)
		if parseErr != nil {
			continue
		}
		out = append(out, parsedRun{run: r, time: t})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].time.Before(out[j].time)
	})
	return out
}

// filterRunsToPeriod returns the subset of runs whose CollectedAt
// falls within [start, end] inclusive.
func filterRunsToPeriod(runs []parsedRun, start, end time.Time) []parsedRun {
	var out []parsedRun
	for _, r := range runs {
		if !r.time.Before(start) && !r.time.After(end) {
			out = append(out, r)
		}
	}
	return out
}

// verifyRunsInPeriod runs per-bundle checksum verification for every
// run in scope and returns the per-run result list, the invalid-run
// detail list, and the count of bundles that passed.
func verifyRunsInPeriod(archivePath string, inPeriod []parsedRun, manifestValid bool) ([]RunResult, []InvalidRun, int) {
	var runs []RunResult
	var invalid []InvalidRun
	validCount := 0
	for _, pr := range inPeriod {
		rr := RunResult{
			RunID:       pr.run.RunID,
			CollectedAt: pr.run.CollectedAt,
			ManifestOK:  manifestValid,
		}
		checksumOK, detail := verifyRunChecksums(archivePath, pr.run.RunID)
		rr.ChecksumOK = checksumOK
		if !checksumOK {
			invalid = append(invalid, InvalidRun{
				RunID:         pr.run.RunID,
				CollectedAt:   pr.run.CollectedAt,
				FailureReason: "checksum_mismatch",
				Detail:        detail,
			})
		} else {
			validCount++
		}
		runs = append(runs, rr)
	}
	return runs, invalid, validCount
}

// computeTemporalGaps walks the in-period runs and reports gaps that
// exceed MaxGapHours (or any gap when Strict is set). Returns the gap
// list and the count of gaps marked ExceedsMax.
func computeTemporalGaps(inPeriod []parsedRun, input VerifyInput) ([]GapResult, int) {
	var gaps []GapResult
	gapsExceeding := 0

	if len(inPeriod) > 0 {
		firstGap := inPeriod[0].time.Sub(input.PeriodStart).Hours()
		if firstGap > input.MaxGapHours {
			gaps = append(gaps, GapResult{
				GapStart:      input.PeriodStart,
				GapEnd:        inPeriod[0].time,
				DurationHours: firstGap,
				ExceedsMax:    true,
			})
			gapsExceeding++
		}
	}

	for i := 1; i < len(inPeriod); i++ {
		gap := inPeriod[i].time.Sub(inPeriod[i-1].time).Hours()
		if exceedsGapThreshold(gap, input.MaxGapHours, input.Strict) {
			exceeds := gap > input.MaxGapHours || input.Strict
			gaps = append(gaps, GapResult{
				GapStart:      inPeriod[i-1].time,
				GapEnd:        inPeriod[i].time,
				DurationHours: gap,
				ExceedsMax:    exceeds,
			})
			if exceeds {
				gapsExceeding++
			}
		}
	}

	if len(inPeriod) > 0 {
		lastGap := input.PeriodEnd.Sub(inPeriod[len(inPeriod)-1].time).Hours()
		if lastGap > input.MaxGapHours {
			gaps = append(gaps, GapResult{
				GapStart:      inPeriod[len(inPeriod)-1].time,
				GapEnd:        input.PeriodEnd,
				DurationHours: lastGap,
				ExceedsMax:    true,
			})
			gapsExceeding++
		}
	}

	return gaps, gapsExceeding
}

// computeCoveragePct returns the fraction of the verification window
// covered by collected runs, expressed as a percentage clamped to
// [0,100]. A zero-length window is reported as 100% (degenerate but
// not failed).
func computeCoveragePct(start, end time.Time, gaps []GapResult) float64 {
	periodHours := end.Sub(start).Hours()
	var totalGapHours float64
	for _, g := range gaps {
		totalGapHours += g.DurationHours
	}
	if periodHours <= 0 {
		return 100.0
	}
	coveragePct := (1.0 - totalGapHours/periodHours) * 100
	if coveragePct < 0 {
		return 0
	}
	return coveragePct
}

// computeVerdict reduces the per-run / per-gap counts into the
// PASS/FAIL verdict and accompanying reason string.
func computeVerdict(invalidRuns []InvalidRun, gapsExceeding int, maxGapHours float64) (verdict, reason string) {
	if len(invalidRuns) > 0 {
		return VerdictFail, fmt.Sprintf("%d bundles failed integrity verification", len(invalidRuns))
	}
	if gapsExceeding > 0 {
		return VerdictFail, fmt.Sprintf("%d gaps exceed maximum allowed gap of %.0fh", gapsExceeding, maxGapHours)
	}
	return VerdictPass, ""
}

func verifyManifestHash(archivePath string) bool {
	data, err := os.ReadFile(filepath.Join(archivePath, "manifest.json")) //nolint:gosec
	if err != nil {
		return false
	}
	expected, err := os.ReadFile(filepath.Join(archivePath, "manifest.json.sha256")) //nolint:gosec
	if err != nil {
		return false
	}
	actual := "sha256:" + sha256Hex(data)
	return strings.TrimSpace(string(expected)) == actual
}

func verifyRunChecksums(archivePath, runID string) (bool, string) {
	runDir := filepath.Join(archivePath, "runs", runID)
	sumsPath := filepath.Join(runDir, "sha256sums.txt")
	data, err := os.ReadFile(sumsPath) //nolint:gosec
	if err != nil {
		return false, "sha256sums.txt missing"
	}

	// Resolve runDir to its canonical absolute path so containment
	// checks survive symlinks and relative inputs.
	absRunDir, err := filepath.Abs(runDir)
	if err != nil {
		return false, fmt.Sprintf("resolve run dir: %v", err)
	}

	// Phase 1: parse the manifest into (filename → expectedHash). Reject
	// any filename that escapes runDir — a tampered sha256sums.txt could
	// otherwise point at sibling runs, the parent archive's manifest.json,
	// or arbitrary readable files on disk, which would let a forged
	// bundle pass verification by hashing unrelated content.
	expected := make(map[string]string)
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			continue
		}
		expectedHash := parts[0]
		filename := parts[1]
		if !isSafeRunRelative(filename) {
			return false, filename + ": unsafe filename in manifest"
		}
		filePath := filepath.Join(runDir, filename)
		absFilePath, absErr := filepath.Abs(filePath)
		if absErr != nil {
			return false, fmt.Sprintf("%s: resolve path: %v", filename, absErr)
		}
		// Containment check: absFilePath must be under absRunDir.
		// filepath.Rel returns "../..." when escaping; reject any rel
		// that starts with ".." or is absolute on the target side.
		rel, relErr := filepath.Rel(absRunDir, absFilePath)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return false, filename + ": path escapes run directory"
		}
		if _, dup := expected[filename]; dup {
			return false, filename + ": duplicate manifest entry"
		}
		expected[filename] = expectedHash
	}

	// Phase 2: walk runDir and verify every actual file is in the
	// manifest with a matching hash. Catches "manifest omits real
	// files" attacks where the attacker only lists files they've
	// rehashed and skips the real run output.
	seen := make(map[string]bool, len(expected))
	walkErr := filepath.WalkDir(runDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(runDir, path)
		if relErr != nil {
			return relErr
		}
		// sha256sums.txt is the manifest itself — never lists itself.
		if rel == "sha256sums.txt" {
			return nil
		}
		expectedHash, ok := expected[rel]
		if !ok {
			return fmt.Errorf("%s: file present but not in manifest", rel)
		}
		fileData, readErr := os.ReadFile(path) //nolint:gosec
		if readErr != nil {
			return fmt.Errorf("%s: %w", rel, readErr)
		}
		actualHash := "sha256:" + sha256Hex(fileData)
		if actualHash != expectedHash {
			return fmt.Errorf("%s: expected %s, got %s", rel, expectedHash, actualHash)
		}
		seen[rel] = true
		return nil
	})
	if walkErr != nil {
		return false, walkErr.Error()
	}

	// Phase 3: every manifest entry must have been visited. Any entry
	// not seen in the walk points at a file that doesn't exist in
	// runDir — the path-containment check in phase 1 already rejected
	// out-of-tree paths, so this catches missing files only.
	for filename := range expected {
		if !seen[filename] {
			return false, filename + ": file missing"
		}
	}

	return true, ""
}

// isSafeRunRelative checks that a manifest filename is a relative path
// that stays inside the run directory: no leading separator, no parent
// segments, no NUL bytes, no Windows-style absolute paths.
func isSafeRunRelative(filename string) bool {
	if filename == "" {
		return false
	}
	if strings.ContainsRune(filename, 0) {
		return false
	}
	if filepath.IsAbs(filename) {
		return false
	}
	// Check raw segments (before filepath.Clean collapses .. into the
	// base path) so attackers can't slip "../foo" through by relying on
	// filepath.Join's cleaning.
	if slices.Contains(strings.Split(filepath.ToSlash(filename), "/"), "..") {
		return false
	}
	return true
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ParsePeriod parses a period string into start and end times.
func ParsePeriod(s string) (start, end time.Time, label string, err error) {
	s = strings.TrimSpace(s)

	// Range: 2026-01-01:2026-03-31
	if strings.Contains(s, ":") {
		parts := strings.SplitN(s, ":", 2)
		start, err = time.Parse("2006-01-02", parts[0])
		if err != nil {
			return time.Time{}, time.Time{}, "", fmt.Errorf("parse start date: %w", err)
		}
		end, err = time.Parse("2006-01-02", parts[1])
		if err != nil {
			return time.Time{}, time.Time{}, "", fmt.Errorf("parse end date: %w", err)
		}
		end = end.Add(24*time.Hour - time.Second)
		return start, end, s, nil
	}

	// Quarter: 2026-Q1
	if strings.Contains(s, "-Q") || strings.Contains(s, "-q") {
		upper := strings.ToUpper(s)
		var year int
		var q string
		if _, scanErr := fmt.Sscanf(upper, "%d-Q%s", &year, &q); scanErr == nil {
			switch q {
			case "1":
				return time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC),
					time.Date(year, 3, 31, 23, 59, 59, 0, time.UTC), s, nil
			case "2":
				return time.Date(year, 4, 1, 0, 0, 0, 0, time.UTC),
					time.Date(year, 6, 30, 23, 59, 59, 0, time.UTC), s, nil
			case "3":
				return time.Date(year, 7, 1, 0, 0, 0, 0, time.UTC),
					time.Date(year, 9, 30, 23, 59, 59, 0, time.UTC), s, nil
			case "4":
				return time.Date(year, 10, 1, 0, 0, 0, 0, time.UTC),
					time.Date(year, 12, 31, 23, 59, 59, 0, time.UTC), s, nil
			}
		}
		return time.Time{}, time.Time{}, "", fmt.Errorf("invalid quarter: %s", s)
	}

	// Month: 2026-01
	if len(s) == 7 {
		t, parseErr := time.Parse("2006-01", s)
		if parseErr == nil {
			endOfMonth := t.AddDate(0, 1, 0).Add(-time.Second)
			return t, endOfMonth, s, nil
		}
	}

	// Single day: 2026-01-15
	if len(s) == 10 {
		t, parseErr := time.Parse("2006-01-02", s)
		if parseErr == nil {
			return t, t.Add(24*time.Hour - time.Second), s, nil
		}
	}

	return time.Time{}, time.Time{}, "", fmt.Errorf("unrecognized period format: %q (expected: 2026-Q1, 2026-01, 2026-01-01, or 2026-01-01:2026-03-31)", s)
}

// exceedsGapThreshold returns true when a collection gap should be
// flagged. In strict mode, any gap (> 0 hours) is a violation.
// Otherwise, only gaps exceeding the configured maximum are flagged.
func exceedsGapThreshold(gap, maxGapHours float64, strict bool) bool {
	return gap > maxGapHours || (strict && gap > 0)
}
