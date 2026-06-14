package artifacts

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/core/asset"
	"gopkg.in/yaml.v3"
)

// CanonicalizeByExtension applies deterministic formatting based on file extension.
// Returns nil if the extension is not recognized.
func CanonicalizeByExtension(path string, data []byte) ([]byte, error) {
	ext := filepath.Ext(path)
	if strings.EqualFold(ext, ".json") {
		return FormatJSON(data)
	}
	if strings.EqualFold(ext, ".yaml") || strings.EqualFold(ext, ".yml") {
		return FormatYAML(data)
	}
	return nil, nil
}

// FormatJSON normalizes observation JSON into canonical indented form.
func FormatJSON(data []byte) ([]byte, error) {
	var snap asset.Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse observation json: %w", err)
	}
	out, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal observation json: %w", err)
	}
	return append(out, '\n'), nil
}

// FormatYAML normalizes control YAML into canonical form.
func FormatYAML(data []byte) ([]byte, error) {
	var dto any
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("parse control yaml: %w", err)
	}
	out, err := yaml.Marshal(dto)
	if err != nil {
		return nil, fmt.Errorf("parse control yaml: %w", err)
	}
	if len(out) == 0 || out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return out, nil
}
