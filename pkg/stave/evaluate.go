package stave

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/profile"
	"github.com/sufield/stave/internal/profile/exception"
	"github.com/sufield/stave/internal/profile/reporter"
)

// EvaluateSnapshot runs every control in a compliance profile against an
// observation snapshot, applies acknowledged exceptions from the project
// stave.yaml, and renders the report in the requested format (already
// resolved by the caller — "text"/"json"). It returns the rendered bytes
// and a non-empty failure summary string when the run gates non-zero (the
// caller maps that to exit 1 via ui.ErrSecurityAuditFindings — the report
// is still rendered). Input failures (snapshot, schema, profile, --now)
// wrap [ErrInvalidInput] (exit 2); evaluation/render failures stay plain
// (exit 4). It is the library entry point behind `stave evaluate`.
func EvaluateSnapshot(ctx context.Context, snapshotPath, profileID, format, nowRaw string) (output []byte, failureMsg string, err error) {
	snap, err := evalLoadSnapshot(snapshotPath)
	if err != nil {
		return nil, "", fmt.Errorf("load snapshot: %w: %w", err, ErrInvalidInput)
	}
	if schemaErr := evalValidateSchema(snap.SchemaVersion); schemaErr != nil {
		return nil, "", fmt.Errorf("validate schema: %w: %w", schemaErr, ErrInvalidInput)
	}

	prof, err := profile.LoadProfile(profileID)
	if err != nil {
		return nil, "", fmt.Errorf("load profile: %w: %w", err, ErrInvalidInput)
	}

	report, err := prof.Evaluate(ctx, snap, evalAllRegistries()...)
	if err != nil {
		return nil, "", fmt.Errorf("evaluate: %w", err)
	}

	// Load and apply exceptions from project root stave.yaml. Its absence
	// is the common case and must not be a hard failure.
	const staveYAML = "stave.yaml"
	excs, excErr := exception.LoadExceptions(staveYAML)
	if excErr != nil {
		if errors.Is(excErr, os.ErrNotExist) {
			slog.Debug("no exceptions file found; continuing with empty exception list", "path", staveYAML)
			excs = nil
		} else {
			return nil, "", fmt.Errorf("load exceptions: %w", excErr)
		}
	}
	if len(excs) > 0 {
		nowAt, nowErr := evalResolveNow(nowRaw)
		if nowErr != nil {
			return nil, "", fmt.Errorf("--now: %w: %w", nowErr, ErrInvalidInput)
		}
		acks := exception.ApplyExceptions(excs, report.Results, evalExtractBucketName(snap), nowAt)
		validAcks := make(map[string]struct{}, len(acks))
		for i := range acks {
			ack := &acks[i]
			if !ack.IsValid() {
				continue
			}
			validAcks[string(ack.ControlID)] = struct{}{}
			report.Acknowledged = append(report.Acknowledged, ack.ToAcknowledgedEntry())
		}
		report.FilterUnacknowledgedCompound(validAcks)
	}

	// Recount from the final filtered results regardless of whether
	// exceptions were applied.
	report.Recount()

	if snap.CapturedAt.IsZero() {
		slog.Warn("snapshot has zero captured_at; report timestamp will render as 0001-01-01T00:00:00Z",
			"bucket", evalExtractBucketName(snap),
			"account", evalExtractAccountID(snap),
		)
	}
	meta := reporter.ReportMeta{
		BucketName: evalExtractBucketName(snap),
		AccountID:  evalExtractAccountID(snap),
		Timestamp:  snap.CapturedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	rep, repErr := reporter.New(format)
	if repErr != nil {
		return nil, "", fmt.Errorf("create reporter: %w", repErr)
	}

	var buf bytes.Buffer
	if err := rep.Write(&buf, report, meta); err != nil {
		return nil, "", fmt.Errorf("write report: %w", err)
	}

	if msg, fail := report.FailureSummary(); fail {
		failureMsg = msg
	}
	return buf.Bytes(), failureMsg, nil
}

func evalLoadSnapshot(path string) (asset.Snapshot, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from CLI flag
	if err != nil {
		return asset.Snapshot{}, fmt.Errorf("read %s: %w", path, err)
	}
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return asset.Snapshot{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return snap, nil
}

func evalValidateSchema(version kernel.Schema) error {
	if version != kernel.SchemaObservation {
		return fmt.Errorf("unsupported schema version %q (expected %s)", version, kernel.SchemaObservation)
	}
	return nil
}

func evalAllRegistries() []*compliance.ControlCatalog {
	return []*compliance.ControlCatalog{
		compliance.GetControlRegistry(),
	}
}

func evalExtractBucketName(snap asset.Snapshot) string {
	for _, a := range snap.Assets {
		if name, ok := a.Properties["bucket_name"].(string); ok {
			return name
		}
	}
	if len(snap.Assets) > 0 {
		return string(snap.Assets[0].ID)
	}
	return "unknown"
}

func evalExtractAccountID(snap asset.Snapshot) string {
	for i := range snap.Assets {
		curr := string(snap.Assets[i].ID)
		found := true
		for j := 0; j < 4; j++ {
			idx := strings.IndexByte(curr, ':')
			if idx == -1 {
				found = false
				break
			}
			curr = curr[idx+1:]
		}
		if !found {
			continue
		}
		var accountID string
		if nextIdx := strings.IndexByte(curr, ':'); nextIdx != -1 {
			accountID = curr[:nextIdx]
		} else {
			accountID = curr
		}
		if accountID != "" {
			return accountID
		}
	}
	return ""
}

// evalResolveNow returns the instant the evaluation treats as "now" for
// exception expiry math. Empty defers to time.Now(); otherwise RFC3339.
func evalResolveNow(raw string) (time.Time, error) {
	if raw == "" {
		return time.Now(), nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("expected RFC3339 timestamp, got %q: %w", raw, err)
	}
	return t, nil
}
