// Package archiveverify provides evidence archive continuity verification
// for compliance audit periods.
package archiveverify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sufield/stave/internal/app/collect"
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

// Verify performs evidence archive continuity verification.
func Verify(input VerifyInput) (*Attestation, error) {
	archive := &collect.Archive{Path: input.ArchivePath}

	manifest, err := archive.LoadManifest()
	if err != nil {
		return nil, fmt.Errorf("load manifest: %w", err)
	}

	// Verify manifest hash.
	manifestValid := verifyManifestHash(input.ArchivePath)

	// Filter and sort runs by collection time.
	type parsedRun struct {
		run  collect.ManifestRun
		time time.Time
	}
	var allRuns []parsedRun
	for _, r := range manifest.Runs {
		t, parseErr := time.Parse(time.RFC3339, r.CollectedAt)
		if parseErr != nil {
			continue
		}
		allRuns = append(allRuns, parsedRun{run: r, time: t})
	}
	sort.Slice(allRuns, func(i, j int) bool {
		return allRuns[i].time.Before(allRuns[j].time)
	})

	// Filter to period.
	var inPeriod []parsedRun
	for _, r := range allRuns {
		if !r.time.Before(input.PeriodStart) && !r.time.After(input.PeriodEnd) {
			inPeriod = append(inPeriod, r)
		}
	}

	// Verify each run.
	var runs []RunResult
	var invalidRuns []InvalidRun
	validCount := 0

	for _, pr := range inPeriod {
		rr := RunResult{
			RunID:       pr.run.RunID,
			CollectedAt: pr.run.CollectedAt,
			ManifestOK:  manifestValid,
		}

		// Verify per-run checksums.
		checksumOK, detail := verifyRunChecksums(input.ArchivePath, pr.run.RunID)
		rr.ChecksumOK = checksumOK

		if !checksumOK {
			invalidRuns = append(invalidRuns, InvalidRun{
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

	if !manifestValid {
		invalidRuns = append(invalidRuns, InvalidRun{
			RunID:         "manifest",
			FailureReason: "manifest_hash_mismatch",
			Detail:        "manifest.json SHA-256 does not match manifest.json.sha256",
		})
	}

	// Temporal continuity.
	var gaps []GapResult
	gapsExceeding := 0

	// Check coverage of period start.
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

	// Check between consecutive runs.
	for i := 1; i < len(inPeriod); i++ {
		gap := inPeriod[i].time.Sub(inPeriod[i-1].time).Hours()
		if gap > input.MaxGapHours || (input.Strict && gap > 0) {
			exceeds := gap > input.MaxGapHours
			if input.Strict {
				exceeds = true
			}
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

	// Check coverage of period end.
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

	// Coverage percentage.
	periodHours := input.PeriodEnd.Sub(input.PeriodStart).Hours()
	var totalGapHours float64
	for _, g := range gaps {
		totalGapHours += g.DurationHours
	}
	coveragePct := 100.0
	if periodHours > 0 {
		coveragePct = (1.0 - totalGapHours/periodHours) * 100
		if coveragePct < 0 {
			coveragePct = 0
		}
	}

	// Verdict.
	verdict := "PASS"
	reason := ""
	if len(invalidRuns) > 0 {
		verdict = "FAIL"
		reason = fmt.Sprintf("%d bundles failed integrity verification", len(invalidRuns))
	} else if gapsExceeding > 0 {
		verdict = "FAIL"
		reason = fmt.Sprintf("%d gaps exceed maximum allowed gap of %.0fh", gapsExceeding, input.MaxGapHours)
	}

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

	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			continue
		}
		expectedHash := parts[0]
		filename := parts[1]
		filePath := filepath.Join(runDir, filename)
		fileData, readErr := os.ReadFile(filePath) //nolint:gosec
		if readErr != nil {
			return false, filename + ": file missing"
		}
		actualHash := "sha256:" + sha256Hex(fileData)
		if actualHash != expectedHash {
			return false, fmt.Sprintf("%s: expected %s, got %s", filename, expectedHash, actualHash)
		}
	}
	return true, ""
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
