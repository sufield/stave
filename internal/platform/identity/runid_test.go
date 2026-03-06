package identity

import (
	"testing"

	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

func TestComputeRunID(t *testing.T) {
	runID := ComputeRunID("1.0.0", "hash1", "hash2")
	if len(runID) != RunIDLength {
		t.Errorf("ComputeRunID() length = %d, want %d", len(runID), RunIDLength)
	}

	runID2 := ComputeRunID("1.0.0", "hash1", "hash2")
	if runID != runID2 {
		t.Errorf("ComputeRunID() not deterministic: %s != %s", runID, runID2)
	}

	runID3 := ComputeRunID("1.0.1", "hash1", "hash2")
	if runID == runID3 {
		t.Errorf("ComputeRunID() should produce different output for different inputs")
	}
}

func TestComputeRunID_SeparatorsPreventConcatenationAmbiguity(t *testing.T) {
	// Without separators, both would hash "abc".
	a := ComputeRunID("ab", "c", "")
	b := ComputeRunID("a", "bc", "")
	if a == b {
		t.Fatalf("ComputeRunID() should differ when input boundaries differ: %q", a)
	}
}

func TestComputeRunIDParts_Compatibility(t *testing.T) {
	oldStyle := ComputeRunID("1.0.0", "hash1", "hash2")
	variadic := ComputeRunIDParts("1.0.0", "hash1", "hash2")
	if oldStyle != variadic {
		t.Fatalf("ComputeRunIDParts() should match ComputeRunID(); got %q, want %q", variadic, oldStyle)
	}
}

func TestComputeRunIDParts_Boundaries(t *testing.T) {
	a := ComputeRunIDParts("ab", "c")
	b := ComputeRunIDParts("a", "bc")
	if a == b {
		t.Fatalf("ComputeRunIDParts() should differ when part boundaries differ")
	}
}

func TestHashString(t *testing.T) {
	hash1 := HashString("test")
	hash2 := HashString("test")
	if hash1 != hash2 {
		t.Errorf("HashString() not deterministic: %s != %s", hash1, hash2)
	}

	hash3 := HashString("different")
	if hash1 == hash3 {
		t.Error("HashString() should produce different hash for different input")
	}
}

func TestHashString_UsesPlatformHashBytes(t *testing.T) {
	input := "test"
	got := HashString(input)
	want := string(platformcrypto.HashBytes([]byte(input)))
	if got != want {
		t.Fatalf("HashString() = %q, want %q", got, want)
	}
}

func TestHashStrings(t *testing.T) {
	strs := []string{"a", "b", "c"}

	hash1 := HashStrings(strs)
	hash2 := HashStrings(strs)
	if hash1 != hash2 {
		t.Errorf("HashStrings() not deterministic: %s != %s", hash1, hash2)
	}

	reversed := []string{"c", "b", "a"}
	hash3 := HashStrings(reversed)
	if hash1 != hash3 {
		t.Errorf("HashStrings() not order-independent: %s != %s", hash1, hash3)
	}
}

func TestHashStrings_ConcatenationBoundarySafe(t *testing.T) {
	// Without separators, both would hash "abc".
	a := HashStrings([]string{"ab", "c"})
	b := HashStrings([]string{"a", "bc"})
	if a == b {
		t.Fatalf("HashStrings() should differ when element boundaries differ")
	}
}

func TestHashStrings_Empty(t *testing.T) {
	hash := HashStrings([]string{})
	if hash != "" {
		t.Errorf("HashStrings() for empty = %q, want empty string", hash)
	}
}
