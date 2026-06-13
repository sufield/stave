// Package nepcmd is the engine behind `stave permissions` (net effective
// permissions / CIEM): it resolves the six AWS IAM policy layers from a
// snapshot and renders the principal / resource / summary views. It is the
// engine behind pkg/stave.ResolvePrincipal / ResolveResourceAccess /
// NepSummary; the command keeps only flag wiring, the output write, the
// stderr warnings, and the exit-1 security signal.
package nepcmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// loadSnapshots loads snapshots from a file, supporting both bundle format
// ({"snapshots": [...]}) and single snapshot format ({"schema_version": ...}).
func loadSnapshots(path string) ([]asset.Snapshot, error) {
	snaps, err := observations.LoadBundle(path)
	if err == nil && len(snaps) > 0 {
		return snaps, nil
	}
	data, readErr := fsutil.ReadFileLimited(path)
	if readErr != nil {
		return nil, fmt.Errorf("read %s: %w", path, readErr)
	}
	var single asset.Snapshot
	if jsonErr := json.Unmarshal(data, &single); jsonErr != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, jsonErr)
	}
	if len(single.Assets) > 0 || len(single.Identities) > 0 {
		return []asset.Snapshot{single}, nil
	}
	return nil, fmt.Errorf("no snapshot data in %s", path)
}

func truncateARN(arn string, maxLen int) string {
	if len(arn) <= maxLen {
		return arn
	}
	return arn[:maxLen-3] + "..."
}

func shortARN(arn string) string {
	return arn[strings.LastIndexByte(arn, '/')+1:]
}

// dotQuote wraps a string in double quotes for DOT format, escaping inner quotes.
func dotQuote(s string) string {
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func resolveStringProperty(props map[string]any, path []string) string {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			return ""
		}
	}
	s, ok := current.(string)
	if !ok {
		return ""
	}
	return s
}

func resolveMapProperty(props map[string]any, path []string) map[string]any {
	var current any = props
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[key]
		if !ok {
			return nil
		}
	}
	m, ok := current.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func extractAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func extractService(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}
