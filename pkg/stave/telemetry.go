package stave

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	apptelemetry "github.com/sufield/stave/internal/app/telemetry"
	"github.com/sufield/stave/internal/core/report"
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
		filter.Severities = make(map[string]bool)
		for s := range strings.SplitSeq(severity, ",") {
			trimmed := strings.TrimSpace(strings.ToLower(s))
			if trimmed != "" {
				filter.Severities[trimmed] = true
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
