package stave

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	apptelemetry "github.com/sufield/stave/internal/app/telemetry"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// MapTelemetry parses a stave-apply assessment (JSON) and emits one
// structured telemetry event per finding as NDJSON (one compact JSON
// object per line), optionally filtered by a comma-separated severity
// list and/or a resource ARN. It is the library entry point behind
// `stave telemetry`.
func MapTelemetry(data []byte, severity, resourceARN string) ([]byte, error) {
	var assessment report.Assessment
	if err := json.Unmarshal(data, &assessment); err != nil {
		return nil, fmt.Errorf("parse assessment: %w", err)
	}

	filter := apptelemetry.Filter{ResourceARN: resourceARN}
	if severity != "" {
		filter.Severities = make(map[string]struct{})
		for s := range strings.SplitSeq(severity, ",") {
			trimmed := strings.TrimSpace(strings.ToLower(s))
			if trimmed != "" {
				filter.Severities[trimmed] = struct{}{}
			}
		}
	}

	events := apptelemetry.MapAssessment(&assessment, filter, nil)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return nil, fmt.Errorf("encode telemetry event: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// MapTelemetryHistory reads all assessment JSON files from dir,
// processes them chronologically with window tracking, and emits
// NDJSON with window_id for time-series consumption.
func MapTelemetryHistory(dir, severity, resourceARN string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, filepath.Join(dir, e.Name()))
	}
	slices.Sort(files)

	if len(files) == 0 {
		return nil, fmt.Errorf("no JSON files in %s", dir)
	}

	filter := apptelemetry.Filter{ResourceARN: resourceARN}
	if severity != "" {
		filter.Severities = make(map[string]struct{})
		for s := range strings.SplitSeq(severity, ",") {
			trimmed := strings.TrimSpace(strings.ToLower(s))
			if trimmed != "" {
				filter.Severities[trimmed] = struct{}{}
			}
		}
	}

	tracker := apptelemetry.NewWindowTracker()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for _, path := range files {
		data, err := fsutil.ReadFileLimited(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var assessment report.Assessment
		if err := json.Unmarshal(data, &assessment); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}

		events := apptelemetry.MapAssessmentWithWindows(&assessment, filter, nil, tracker)

		currentKeys := make(map[string]struct{}, len(events))
		for i := range events {
			currentKeys[events[i].ResourceID+"/"+events[i].ControlID] = struct{}{}
			if err := enc.Encode(&events[i]); err != nil {
				return nil, fmt.Errorf("encode event: %w", err)
			}
		}
		tracker.CloseAbsent(currentKeys)
	}

	return buf.Bytes(), nil
}
