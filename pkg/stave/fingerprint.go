package stave

import (
	"context"
	"fmt"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
)

// FingerprintExplainResult holds the policy fingerprint preimage
// and derived diagnosis fields.
type FingerprintExplainResult struct {
	EvalVersion        string                    `json:"eval_version"`
	EvalVersionPresent bool                      `json:"eval_version_present"`
	Controls           []FingerprintControlEntry `json:"controls"`
	ControlCount       int                       `json:"control_count"`
	Preimage           string                    `json:"preimage"`
	Fingerprint        string                    `json:"fingerprint"`
}

// FingerprintControlEntry is one control's contribution to the
// policy fingerprint.
type FingerprintControlEntry struct {
	ID               string `json:"id"`
	Hash             string `json:"hash"`
	AssetTypesHashed bool   `json:"asset_types_hashed"`
}

// FingerprintExplain loads the control catalog and returns the
// policy fingerprint preimage with diagnostic flags.
func FingerprintExplain(ctx context.Context, cfg Config) (*FingerprintExplainResult, error) {
	controls, err := applycore.LoadControls(cfg.ControlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}

	hasher := crypto.NewHasher()
	assessor := engine.NewAssessor(
		engine.WithControls(controls),
		engine.WithHasher(hasher),
	)

	preimageLines := assessor.PolicyPreimage()
	if preimageLines == nil {
		return &FingerprintExplainResult{
			EvalVersion: engine.EvalVersion,
		}, nil
	}

	preimage := strings.Join(preimageLines, "\n")
	fingerprint := string(assessor.FingerprintPolicy())

	evalVersionPresent := strings.Contains(preimage, "eval_version:")

	var controlEntries []FingerprintControlEntry
	for _, line := range preimageLines {
		if strings.HasPrefix(line, "eval_version:") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			controlEntries = append(controlEntries, FingerprintControlEntry{
				ID:               parts[0],
				Hash:             parts[1],
				AssetTypesHashed: true,
			})
		}
	}

	return &FingerprintExplainResult{
		EvalVersion:        engine.EvalVersion,
		EvalVersionPresent: evalVersionPresent,
		Controls:           controlEntries,
		ControlCount:       len(controlEntries),
		Preimage:           preimage,
		Fingerprint:        "sha256:" + fingerprint,
	}, nil
}
