package fsutil

import "testing"

func TestSetMaxInputFileBytes_PositiveValue(t *testing.T) {
	orig := maxInputFileBytes
	t.Cleanup(func() { maxInputFileBytes = orig })

	SetMaxInputFileBytes(512 << 20) // 512 MB
	if maxInputFileBytes != 512<<20 {
		t.Errorf("maxInputFileBytes = %d, want %d", maxInputFileBytes, 512<<20)
	}
}

func TestSetMaxInputFileBytes_ZeroIgnored(t *testing.T) {
	orig := maxInputFileBytes
	t.Cleanup(func() { maxInputFileBytes = orig })

	SetMaxInputFileBytes(0)
	if maxInputFileBytes != orig {
		t.Error("zero value should be ignored by SetMaxInputFileBytes")
	}
}

func TestSetMaxInputFileBytes_NegativeIgnored(t *testing.T) {
	orig := maxInputFileBytes
	t.Cleanup(func() { maxInputFileBytes = orig })

	SetMaxInputFileBytes(-1024)
	if maxInputFileBytes != orig {
		t.Error("negative value should be ignored by SetMaxInputFileBytes")
	}
}

func TestSetMaxInputFileBytes_DefaultValue(t *testing.T) {
	// Verify the default is 256 MB.
	if DefaultMaxInputFileBytes != 256<<20 {
		t.Errorf("DefaultMaxInputFileBytes = %d, want %d", DefaultMaxInputFileBytes, 256<<20)
	}
}
