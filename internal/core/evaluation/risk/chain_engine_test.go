package risk

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func failingControls(assetID asset.ID, ctlIDs ...kernel.ControlID) []FailingControl {
	out := make([]FailingControl, len(ctlIDs))
	for i, cid := range ctlIDs {
		out[i] = FailingControl{ControlID: cid, AssetID: assetID}
	}
	return out
}

func TestDetectChains(t *testing.T) {
	chains := []policy.ChainDefinition{
		{
			ID:                  "phi_exposure",
			Description:         "PHI data exposed",
			ControlIDs:          []kernel.ControlID{"CTL.S3.PUBLIC.001", "CTL.S3.ENCRYPT.001", "CTL.S3.LOG.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		},
		{
			ID:                  "root_path",
			Description:         "Root compromise",
			ControlIDs:          []kernel.ControlID{"CTL.IAM.ROOT.MFA.001", "CTL.IAM.ROOT.ACCESSKEY.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		},
	}

	ctlPublic := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
	}
	ctlEncrypt := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{"attack_stage": "exfiltration"}),
	}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.S3.PUBLIC.001":  ctlPublic,
		"CTL.S3.ENCRYPT.001": ctlEncrypt,
	}

	t.Run("two controls on same asset trigger chain", func(t *testing.T) {
		failures := failingControls("bucket-1", "CTL.S3.PUBLIC.001", "CTL.S3.ENCRYPT.001")
		findings := DetectChains(failures, chains, lookup, nil)
		if len(findings) != 1 {
			t.Fatalf("expected 1 compound finding, got %d", len(findings))
		}
		f := findings[0]
		if f.ChainID != "phi_exposure" {
			t.Errorf("ChainID = %q, want phi_exposure", f.ChainID)
		}
		if f.AssetID != "bucket-1" {
			t.Errorf("AssetID = %q, want bucket-1", f.AssetID)
		}
		if len(f.ControlsFailing) != 2 {
			t.Errorf("ControlsFailing = %d, want 2", len(f.ControlsFailing))
		}
		// MissingSafeguards = controls in chain that are NOT failing
		if len(f.MissingSafeguards) != 1 {
			t.Errorf("MissingSafeguards = %d, want 1 (CTL.S3.LOG.001 is still holding)", len(f.MissingSafeguards))
		}
		if f.Severity != policy.SeverityCritical {
			t.Errorf("Severity = %v, want CRITICAL", f.Severity)
		}
		if f.CompoundScore <= 0 {
			t.Errorf("CompoundScore = %f, want > 0", f.CompoundScore)
		}
		if len(f.AttackStages) != 2 {
			t.Errorf("AttackStages = %v, want 2 stages", f.AttackStages)
		}
	})

	t.Run("controls on different assets do not trigger chain", func(t *testing.T) {
		// CTL.S3.PUBLIC.001 fails on bucket-A, CTL.S3.ENCRYPT.001 fails on bucket-B.
		// The chain should NOT fire because no single asset has both gaps.
		failures := []FailingControl{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-a"},
			{ControlID: "CTL.S3.ENCRYPT.001", AssetID: "bucket-b"},
		}
		findings := DetectChains(failures, chains, lookup, nil)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for cross-asset controls, got %d", len(findings))
		}
	})

	t.Run("below threshold no finding", func(t *testing.T) {
		failures := failingControls("bucket-1", "CTL.S3.PUBLIC.001")
		findings := DetectChains(failures, chains, lookup, nil)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings below threshold, got %d", len(findings))
		}
	})

	t.Run("no failing controls", func(t *testing.T) {
		findings := DetectChains(nil, chains, lookup, nil)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("multiple chains can fire for different assets", func(t *testing.T) {
		// S3 chain fires for bucket-1, IAM chain fires for account-root.
		failures := []FailingControl{
			{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-1"},
			{ControlID: "CTL.S3.ENCRYPT.001", AssetID: "bucket-1"},
			{ControlID: "CTL.IAM.ROOT.MFA.001", AssetID: "account-root"},
			{ControlID: "CTL.IAM.ROOT.ACCESSKEY.001", AssetID: "account-root"},
		}
		findings := DetectChains(failures, chains, lookup, nil)
		if len(findings) != 2 {
			t.Errorf("expected 2 compound findings, got %d", len(findings))
		}
	})

	t.Run("blast multiplier affects score", func(t *testing.T) {
		blastCtl := &policy.ControlDefinition{
			Params: policy.NewParams(map[string]any{
				"attack_stage": "detection_evasion",
				"blast_radius": map[string]any{
					"type":       "detection",
					"scope":      "account",
					"multiplier": float64(2.5),
				},
			}),
		}
		detectionChain := []policy.ChainDefinition{{
			ID:                  "blind",
			Description:         "Detection disabled",
			ControlIDs:          []kernel.ControlID{"CTL.CLOUDTRAIL.001", "CTL.GUARDDUTY.001"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityCritical,
		}}
		detectionLookup := map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.CLOUDTRAIL.001": blastCtl,
			"CTL.GUARDDUTY.001":  blastCtl,
		}
		failures := failingControls("account", "CTL.CLOUDTRAIL.001", "CTL.GUARDDUTY.001")
		findings := DetectChains(failures, detectionChain, detectionLookup, nil)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		// With account-scoped blast multiplier 2.5: score = 10 * 1.8 * 2.5 = 45.0
		if findings[0].CompoundScore < 40.0 {
			t.Errorf("CompoundScore = %f, expected >= 40 with blast multiplier", findings[0].CompoundScore)
		}
	})

	t.Run("scope attenuation reduces multiplier", func(t *testing.T) {
		// Resource-scoped blast (S3 logging) should be attenuated.
		resourceCtl := &policy.ControlDefinition{
			Params: policy.NewParams(map[string]any{
				"blast_radius": map[string]any{
					"type":       "detection",
					"scope":      "resource",
					"multiplier": float64(2.0),
				},
			}),
		}
		// Account-scoped (CloudTrail) should NOT be attenuated.
		accountCtl := &policy.ControlDefinition{
			Params: policy.NewParams(map[string]any{
				"blast_radius": map[string]any{
					"type":       "detection",
					"scope":      "account",
					"multiplier": float64(2.0),
				},
			}),
		}

		chain := []policy.ChainDefinition{{
			ID:                  "scope_test",
			ControlIDs:          []kernel.ControlID{"A", "B"},
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
		}}

		// Resource-scoped: effective = 1.0 + (2.0-1.0)*0.50 = 1.5
		resourceFindings := DetectChains(
			failingControls("asset-1", "A", "B"),
			chain,
			map[kernel.ControlID]*policy.ControlDefinition{"A": resourceCtl, "B": resourceCtl},
			nil,
		)

		// Account-scoped: effective = 2.0 (no attenuation)
		accountFindings := DetectChains(
			failingControls("asset-1", "A", "B"),
			chain,
			map[kernel.ControlID]*policy.ControlDefinition{"A": accountCtl, "B": accountCtl},
			nil,
		)

		if len(resourceFindings) != 1 || len(accountFindings) != 1 {
			t.Fatal("expected 1 finding each")
		}

		// Account-scoped score should be higher than resource-scoped.
		if accountFindings[0].CompoundScore <= resourceFindings[0].CompoundScore {
			t.Errorf("account score (%f) should be > resource score (%f)",
				accountFindings[0].CompoundScore, resourceFindings[0].CompoundScore)
		}
		t.Logf("account=%f resource=%f",
			accountFindings[0].CompoundScore, resourceFindings[0].CompoundScore)
	})
}

// TestDetectChains_ScopeFieldGroupsAcrossAssets exercises the
// scope_field path: two failing controls on different asset.IDs that
// share a scope value bucket together and trip the chain threshold.
// Mirrors the cognito_ghost_authflow shape — per-trigger predicates
// force one logical user pool to surface as N distinct assets.
func TestDetectChains_ScopeFieldGroupsAcrossAssets(t *testing.T) {
	chains := []policy.ChainDefinition{{
		ID:                  "scoped",
		ControlIDs:          []kernel.ControlID{"CTL.A", "CTL.B"},
		EscalationThreshold: 2,
		CompoundSeverity:    policy.SeverityHigh,
		ScopeField:          "properties.identity.cognito.user_pool_id",
	}}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"CTL.A": {Params: policy.NewParams(map[string]any{"attack_stage": "initial_access"})},
		"CTL.B": {Params: policy.NewParams(map[string]any{"attack_stage": "exfiltration"})},
	}
	failures := []FailingControl{
		{ControlID: "CTL.A", AssetID: "asset-trigger-A"},
		{ControlID: "CTL.B", AssetID: "asset-trigger-B"},
	}
	resolver := func(id asset.ID, _ string) (string, bool) {
		// Both assets resolve to the same logical pool.
		return "shared-pool", true
	}

	findings := DetectChains(failures, chains, lookup, resolver)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (chain reunites across asset.IDs via scope_field), got %d", len(findings))
	}
	f := findings[0]
	if f.ScopeID != "shared-pool" {
		t.Errorf("ScopeID = %q, want shared-pool", f.ScopeID)
	}
	if f.ScopeField == "" {
		t.Errorf("ScopeField should be populated when chain.ScopeField is set")
	}
	if len(f.ContributingAssets) != 2 {
		t.Errorf("ContributingAssets = %v, want 2 (both contributing assets)", f.ContributingAssets)
	}
	// AssetID is the deterministic representative — lowest under string sort.
	if f.AssetID != "asset-trigger-A" {
		t.Errorf("AssetID = %q, want asset-trigger-A (lowest contributing)", f.AssetID)
	}
}

// TestDetectChains_ScopeFieldFallsBackOnUnresolved confirms that a
// chain with ScopeField set but a resolver that fails to read the
// path falls back to asset.ID grouping for that one (asset, chain)
// pair. Same fixture as the legacy test — same outcome.
func TestDetectChains_ScopeFieldFallsBackOnUnresolved(t *testing.T) {
	chain := []policy.ChainDefinition{{
		ID:                  "fallback",
		ControlIDs:          []kernel.ControlID{"X", "Y"},
		EscalationThreshold: 2,
		CompoundSeverity:    policy.SeverityHigh,
		ScopeField:          "properties.identity.cognito.user_pool_id",
	}}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"X": {Params: policy.NewParams(map[string]any{})},
		"Y": {Params: policy.NewParams(map[string]any{})},
	}
	// Resolver returns false for every lookup → all failures fall back to asset.ID.
	resolver := func(_ asset.ID, _ string) (string, bool) { return "", false }

	// Both controls fail on the SAME asset.ID — should still trip the chain
	// because the fallback is asset.ID, identical to the legacy semantics.
	findings := DetectChains(failingControls("only-asset", "X", "Y"), chain, lookup, resolver)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (fallback to asset.ID grouping), got %d", len(findings))
	}
	if findings[0].AssetID != "only-asset" {
		t.Errorf("AssetID = %q, want only-asset", findings[0].AssetID)
	}
	if findings[0].ScopeID != "" {
		t.Errorf("ScopeID = %q, want empty when resolver returned false", findings[0].ScopeID)
	}
}

// TestDetectChains_ScopeFieldNilResolverFallsBack confirms that a
// chain declaring ScopeField with a nil resolver passed to
// DetectChains still groups by asset.ID. Production callers may
// legitimately pass a nil resolver when they have no asset
// properties at hand (e.g. a downstream tool that consumes the
// FailingControl slice from a serialized output).
func TestDetectChains_ScopeFieldNilResolverFallsBack(t *testing.T) {
	chain := []policy.ChainDefinition{{
		ID:                  "nilres",
		ControlIDs:          []kernel.ControlID{"X", "Y"},
		EscalationThreshold: 2,
		CompoundSeverity:    policy.SeverityHigh,
		ScopeField:          "properties.x.y",
	}}
	lookup := map[kernel.ControlID]*policy.ControlDefinition{
		"X": {Params: policy.NewParams(map[string]any{})},
		"Y": {Params: policy.NewParams(map[string]any{})},
	}
	failures := []FailingControl{
		{ControlID: "X", AssetID: "a-1"},
		{ControlID: "Y", AssetID: "a-2"},
	}
	findings := DetectChains(failures, chain, lookup, nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (nil resolver → asset.ID grouping, no asset has both)")
	}
}

func TestScopeAdjustedBlast_MultiplierAtOne(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{
			"blast_radius": map[string]any{"scope": "account", "multiplier": float64(1.0)},
		}),
	}
	got := scopeAdjustedBlast(ctl)
	if got != 1.0 {
		t.Fatalf("multiplier=1.0 should return 1.0, got %f", got)
	}
}

func TestScopeAdjustedBlast_MultiplierBelowOne(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{
			"blast_radius": map[string]any{"scope": "account", "multiplier": float64(0.5)},
		}),
	}
	got := scopeAdjustedBlast(ctl)
	if got != 1.0 {
		t.Fatalf("multiplier<1.0 should return 1.0, got %f", got)
	}
}

func TestScopeAdjustedBlast_NetworkScope(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{
			"blast_radius": map[string]any{"scope": "network", "multiplier": float64(2.0)},
		}),
	}
	got := scopeAdjustedBlast(ctl)
	// Network: 1.0 + (2.0-1.0)*0.75 = 1.75
	if got != 1.75 {
		t.Fatalf("network scope got %f, want 1.75", got)
	}
}

func TestScopeAdjustedBlast_ResourceScope(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{
			"blast_radius": map[string]any{"scope": "resource", "multiplier": float64(2.0)},
		}),
	}
	got := scopeAdjustedBlast(ctl)
	// Resource: 1.0 + (2.0-1.0)*0.50 = 1.50
	if got != 1.50 {
		t.Fatalf("resource scope got %f, want 1.50", got)
	}
}

func TestScopeAdjustedBlast_UnknownScope(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{
			"blast_radius": map[string]any{"scope": "unknown", "multiplier": float64(3.0)},
		}),
	}
	got := scopeAdjustedBlast(ctl)
	// Unknown scope falls through to default — returns full multiplier.
	if got != 3.0 {
		t.Fatalf("unknown scope got %f, want 3.0 (full multiplier)", got)
	}
}

func TestScopeAdjustedBlast_NoBlastRadius(t *testing.T) {
	ctl := &policy.ControlDefinition{
		Params: policy.NewParams(map[string]any{}),
	}
	got := scopeAdjustedBlast(ctl)
	// No blast_radius → BlastMultiplier() returns 1.0 → early exit.
	if got != 1.0 {
		t.Fatalf("no blast radius got %f, want 1.0", got)
	}
}
