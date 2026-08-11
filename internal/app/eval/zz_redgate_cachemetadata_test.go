package eval

import (
	"testing"

	"github.com/sufield/stave/internal/app/eval/cache"
	"github.com/sufield/stave/internal/core/evaluation"
)

// Test_RedGate_CacheMetadata asserts the CORRECT behavior: the
// assessment cache's persist/load round-trip must preserve
// ComplianceReport.Metadata. NewConfig always populates
// Metadata.ControlSource.Source = ControlSourceDir, and a cache HIT
// reuses the loaded report verbatim (workflow.go:214-215) without
// re-attaching Metadata (only ControlRemediation is rehydrated).
// Metadata feeds output/envelope.go's Extensions block via
// ToExtensions(); ToExtensions() returns nil when
// ControlSource.Source == "". So if the round-trip drops Metadata,
// a byte-identical second run (cache hit) silently emits NO
// extensions block, violating the documented cache invariant
// (cache.go:8-11) and the applycore contract that the extensions
// block must survive.
//
// This is white-box at the unit-observable layer the bug report
// names: Persist a report with non-empty Metadata, Load it back, and
// require Metadata to survive. It fails against current code because
// ComplianceReport.Metadata is tagged json:"-" (audit.go:350) so the
// cache's JSON encode/decode silently drops it.
func Test_RedGate_CacheMetadata(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during cache metadata round-trip: %v", r)
		}
	}()

	dir := t.TempDir()
	c := cache.New(dir)
	k := cache.Key{
		StaveVersion:    "v0.0.0-redgate",
		EvalVersion:     "redgate-eval",
		ControlsDigest:  "ctl-digest",
		InputHashesHash: "input-digest",
		ChainsDigest:    "no-chains",
		ConfigDigest:    "cfg-digest",
		SourcePaths:     "src-paths",
	}

	want := evaluation.ComplianceReport{
		SecurityState: evaluation.StateCompliant,
		Findings:      []evaluation.Finding{},
		Metadata: evaluation.Metadata{
			ContextName: "default",
			ControlSource: evaluation.ControlSourceInfo{
				Source: evaluation.ControlSourceDir,
			},
			ResolvedPaths: evaluation.ResolvedPaths{
				Controls:     "controls",
				Observations: "observations",
			},
		},
	}

	if err := c.Persist(k, &want); err != nil {
		t.Fatalf("persist: %v", err)
	}
	got, ok := c.Load(k)
	if !ok {
		t.Fatalf("post-persist load should hit")
	}

	// CORRECT behavior: Metadata survives the cache round-trip so a
	// cache-hit run emits the same extensions block as the cache-miss
	// run. Current code drops it (Metadata is json:"-"), so this
	// assertion goes RED.
	if got.Metadata.ControlSource.Source != evaluation.ControlSourceDir {
		t.Fatalf("cache round-trip dropped Metadata.ControlSource.Source: got %q, want %q (extensions block would be lost on a cache hit)",
			got.Metadata.ControlSource.Source, evaluation.ControlSourceDir)
	}
	if got.Metadata.ResolvedPaths.Controls != "controls" {
		t.Fatalf("cache round-trip dropped Metadata.ResolvedPaths.Controls: got %q, want %q",
			got.Metadata.ResolvedPaths.Controls, "controls")
	}
}
