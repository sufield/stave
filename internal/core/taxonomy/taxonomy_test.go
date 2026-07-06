package taxonomy

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestAll_HasExpectedCount(t *testing.T) {
	if got := len(All); got != 27 {
		t.Fatalf("expected 27 categories, got %d", got)
	}
}

func TestInit_RegistersVocabulary(t *testing.T) {
	for _, cat := range All {
		if err := cat.Validate(); err != nil {
			t.Errorf("category %q failed validation after init: %v", cat, err)
		}
	}
}

func TestInit_RejectsUnknown(t *testing.T) {
	typo := kernel.CategoryID("trsut-boundary")
	if typo.IsValid() {
		t.Fatal("typo should be rejected after vocabulary registration")
	}
}

func TestConstants_MatchStrings(t *testing.T) {
	cases := map[kernel.CategoryID]string{
		LeastPrivilege:      "least-privilege",
		FormalSemantics:     "formal-semantics",
		DetectionEvasion:    "detection-evasion",
		Deprecation:         "deprecation",
		DataProtection:      "data-protection",
		EncryptionAtRest:    "encryption-at-rest",
		EncryptionInTransit: "encryption-in-transit",
		AIGuardrails:        "ai-guardrails",
		AISupplyChain:       "ai-supply-chain",
	}
	for constant, expected := range cases {
		if string(constant) != expected {
			t.Errorf("constant %v != %q", constant, expected)
		}
	}
}
