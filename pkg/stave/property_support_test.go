package stave_test

// Shared foundation for the rapid property tests (Phase 2). The generators and
// the temp-dir harness here are reused by every property file in this package.
//
// Properties run against the PUBLIC pipeline (stave.Apply) on purpose: the
// determinism-relevant transforms (content-addressed cache, output-layer
// sanitization/enrichment) live above the engine, so an engine-only harness
// would miss exactly the class of bug these properties target.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/pkg/stave"
)

// fixedNow is a deterministic evaluation clock so output never depends on the
// wall clock.
var fixedNow = time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)

// propTestControlYAML is a minimal, self-contained ctrl.v1 control: a
// test_resource asset whose properties.exposed == true is unsafe. Self-contained
// so the properties don't couple to the evolving built-in catalog, yet exercise
// the real control loader, CEL evaluator, and full output pipeline.
const propTestControlYAML = `dsl_version: ctrl.v1
id: CTL.PROPTEST.EXPOSED.001
name: Property Test Exposed Resource
description: Test-only control; a resource carrying exposed=true is unsafe.
domain: exposure
severity: high
type: unsafe_state
classification: state_assertion
applicable_asset_types:
  - test_resource
unsafe_predicate:
  all:
    - field: type
      op: eq
      value: test_resource
    - field: properties.exposed
      op: eq
      value: true
`

// genSnapshots draws a small, valid observation history: 1-3 per-timestamp
// snapshots, each with 0-6 test_resource assets carrying a boolean exposed
// property. Asset IDs are unique within a snapshot.
func genSnapshots(rt *rapid.T) []asset.Snapshot {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := rapid.IntRange(1, 3).Draw(rt, "snapshots")
	snaps := make([]asset.Snapshot, n)
	for i := range snaps {
		m := rapid.IntRange(0, 6).Draw(rt, "assets_in_snapshot")
		assets := make([]asset.Asset, m)
		seen := make(map[string]struct{}, m)
		for j := range assets {
			// Unique id within the snapshot: a stable index prefix plus a drawn
			// suffix gives variety without collisions.
			var id string
			for {
				id = fmt.Sprintf("res-%d-%s", j, rapid.StringMatching(`[a-z0-9]{1,8}`).Draw(rt, "id_suffix"))
				if _, dup := seen[id]; !dup {
					break
				}
			}
			seen[id] = struct{}{}
			assets[j] = asset.Asset{
				ID:         asset.ID(id),
				Type:       "test_resource",
				Vendor:     "aws",
				Properties: map[string]any{"exposed": rapid.Bool().Draw(rt, "exposed")},
			}
		}
		snaps[i] = asset.Snapshot{
			SchemaVersion: "obs.v0.1",
			Source:        "deployed", // obs.v0.1 schema: source ∈ {deployed, planned, local}
			CapturedAt:    base.Add(time.Duration(i) * 24 * time.Hour),
			Assets:        assets,
		}
	}
	return snaps
}

// writePropFixture writes the control + per-timestamp observation files into a fresh
// temp dir and returns a Config pointing at them plus a cleanup func. Filesystem
// setup failures use t.Fatalf (they are harness faults, not property failures).
func writePropFixture(t *testing.T, snaps []asset.Snapshot) (stave.Config, func()) {
	t.Helper()
	root, err := os.MkdirTemp("", "stave-prop-*")
	if err != nil {
		t.Fatalf("mkdir temp: %v", err)
	}
	ctlDir := filepath.Join(root, "controls")
	obsDir := filepath.Join(root, "observations")
	for _, d := range []string{ctlDir, obsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(ctlDir, "CTL.PROPTEST.EXPOSED.001.yaml"), []byte(propTestControlYAML), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}
	for i, snap := range snaps {
		b, err := json.Marshal(snap)
		if err != nil {
			t.Fatalf("marshal snapshot %d: %v", i, err)
		}
		// Zero-padded index filenames sort chronologically (CapturedAt rises
		// with index), matching the directory loader's name-sorted ordering.
		if err := os.WriteFile(filepath.Join(obsDir, fmt.Sprintf("%03d.json", i)), b, 0o644); err != nil {
			t.Fatalf("write snapshot %d: %v", i, err)
		}
	}
	cfg := stave.Config{ControlsDir: ctlDir, SnapshotsDir: obsDir, Now: fixedNow}
	return cfg, func() { _ = os.RemoveAll(root) }
}

// applyOrFatal runs the public pipeline. An error on a well-formed generated
// fixture is a property failure (rt.Fatalf so rapid shrinks the input).
func applyOrFatal(rt *rapid.T, cfg stave.Config) *stave.Assessment {
	a, err := stave.Apply(context.Background(), cfg)
	if err != nil {
		rt.Fatalf("Apply returned an error on a well-formed fixture: %v", err)
	}
	return a
}

// canonicalJSON marshals an assessment to bytes. Go's encoding/json is
// deterministic for struct fields and sorts map keys, so equal byte output ==
// identical assessment.
func canonicalJSON(rt *rapid.T, a *stave.Assessment) []byte {
	b, err := json.Marshal(a)
	if err != nil {
		rt.Fatalf("marshal assessment: %v", err)
	}
	return b
}
