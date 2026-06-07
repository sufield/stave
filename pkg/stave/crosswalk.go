package stave

import (
	"fmt"
	"time"

	comp "github.com/sufield/stave/internal/compliance"
)

// ResolveCrosswalk validates the requested compliance frameworks,
// resolves the control crosswalk in raw (YAML or JSON) against them for
// the given check IDs, and returns the resolution as JSON bytes. now
// stamps the resolution so output is deterministic when the caller pins
// it.
//
// It is the library entry point behind `stave inspect compliance`:
// the command reads the crosswalk file and calls this, so cmd/ depends
// only on pkg/stave rather than internal/compliance. An empty
// frameworks slice means "all frameworks"; an empty checkIDs slice
// means "all checks in the document".
func ResolveCrosswalk(raw []byte, frameworks, checkIDs []string, now time.Time) ([]byte, error) {
	for _, f := range frameworks {
		if _, err := comp.ParseFramework(f); err != nil {
			return nil, fmt.Errorf("invalid framework: %w", err)
		}
	}
	resolution, err := comp.ResolveControlCrosswalk(raw, frameworks, checkIDs, now)
	if err != nil {
		return nil, fmt.Errorf("resolve crosswalk: %w", err)
	}
	return resolution.ResolutionJSON, nil
}
