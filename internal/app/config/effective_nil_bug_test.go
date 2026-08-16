package config

import (
	"testing"
)

func TestGovernanceResolver_BuildEffectiveConfig_NilReceiverHandledSafely(t *testing.T) {
	var g *GovernanceResolver

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("BuildEffectiveConfig panicked on nil GovernanceResolver receiver: %v", rec)
		}
	}()

	cfg := g.BuildEffectiveConfig()
	if cfg.ConfigFile != "" {
		t.Errorf("expected empty ConfigFile for nil GovernanceResolver")
	}
}
