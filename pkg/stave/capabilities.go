package stave

import (
	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/app/coverage"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/version"
)

// Capabilities is a snapshot of what this build of Stave can do,
// read from the same embedded registries the evaluation engine
// uses. Every count is sourced from real data — never a hardcoded
// literal — so it cannot drift from what the binary actually ships.
//
// OutputFormats lists the formats the apply evaluation path emits.
// It is the documented set rather than a count scraped from a
// registry, because formats are per-command and there is no single
// renderer registry to enumerate; reporting the apply formats is
// honest where a fabricated total would not be.
type Capabilities struct {
	Version       string   `json:"version"`
	Controls      int      `json:"controls"`
	Packs         int      `json:"packs"`
	Frameworks    int      `json:"frameworks"`
	AttackTactics int      `json:"attack_tactics"`
	OutputFormats []string `json:"output_formats"`
	Offline       bool     `json:"offline"`
	Tagline       string   `json:"tagline"`
}

// GetCapabilities reports this build's version and capability counts.
// It loads the embedded builtin catalog, pack registry, supported
// compliance frameworks, and ATT&CK tactic set — all deterministic,
// offline, and independent of the working directory.
func GetCapabilities() (Capabilities, error) {
	controls, err := builtinControls()
	if err != nil {
		return Capabilities{}, err
	}

	packs := 0
	if reg, perr := pack.NewEmbeddedRegistry(); perr == nil {
		packs = len(reg.PackNames())
	}

	return Capabilities{
		Version:       version.String,
		Controls:      len(controls),
		Packs:         packs,
		Frameworks:    len(compliance.SupportedFrameworks()),
		AttackTactics: len(coverage.AllTactics),
		OutputFormats: []string{"text", "json", "sarif"},
		Offline:       true,
		Tagline:       "Air-gapped evaluation. No credentials required.",
	}, nil
}
