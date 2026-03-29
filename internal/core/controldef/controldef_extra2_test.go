package controldef

import (
	"encoding/json"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

// ---------------------------------------------------------------------------
// ControlType — JSON/YAML unmarshal edge cases
// ---------------------------------------------------------------------------

func TestControlType_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var ct ControlType
	err := ct.UnmarshalJSON([]byte(`42`)) // not a string
	if err == nil {
		t.Fatal("expected error for non-string JSON")
	}
}

func TestControlType_UnmarshalJSON_UnknownType(t *testing.T) {
	var ct ControlType
	err := ct.UnmarshalJSON([]byte(`"totally_invalid"`))
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestControlType_UnmarshalYAML_Unknown(t *testing.T) {
	var ct ControlType
	err := ct.UnmarshalYAML(func(v any) error {
		ptr, ok := v.(*string)
		if ok {
			*ptr = "nonexistent_type"
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestControlType_UnmarshalYAML_BadInput(t *testing.T) {
	var ct ControlType
	err := ct.UnmarshalYAML(func(v any) error {
		return json.Unmarshal([]byte(`42`), v)
	})
	if err == nil {
		t.Fatal("expected error for bad input")
	}
}

// ---------------------------------------------------------------------------
// Severity — JSON/YAML unmarshal edge cases
// ---------------------------------------------------------------------------

func TestSeverity_UnmarshalJSON_InvalidJSON(t *testing.T) {
	var s Severity
	err := s.UnmarshalJSON([]byte(`42`))
	if err == nil {
		t.Fatal("expected error for non-string JSON")
	}
}

func TestSeverity_UnmarshalJSON_UnknownSeverity(t *testing.T) {
	var s Severity
	err := s.UnmarshalJSON([]byte(`"ultra_mega_critical"`))
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestSeverity_UnmarshalYAML_Unknown(t *testing.T) {
	var s Severity
	err := s.UnmarshalYAML(func(v any) error {
		ptr, ok := v.(*string)
		if ok {
			*ptr = "mega_critical"
		}
		return nil
	})
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
}

func TestSeverity_UnmarshalYAML_BadInput(t *testing.T) {
	var s Severity
	err := s.UnmarshalYAML(func(v any) error {
		return json.Unmarshal([]byte(`42`), v)
	})
	if err == nil {
		t.Fatal("expected error for bad input")
	}
}

// ---------------------------------------------------------------------------
// Catalog.PackHash
// ---------------------------------------------------------------------------

type stubDigester struct{}

func (s *stubDigester) Digest(items []string, sep byte) kernel.Digest {
	return kernel.Digest("sha256:stub")
}

func TestCatalog_PackHash_NonNil(t *testing.T) {
	cat := NewCatalog([]ControlDefinition{
		{ID: "CTL.B.001"},
		{ID: "CTL.A.001"},
	})
	hash := cat.PackHash(&stubDigester{})
	if hash != "sha256:stub" {
		t.Fatalf("PackHash = %v", hash)
	}
}

func TestCatalog_PackHash_Nil(t *testing.T) {
	var cat *Catalog
	hash := cat.PackHash(&stubDigester{})
	if hash != "" {
		t.Fatalf("nil catalog hash should be empty, got %v", hash)
	}
}

func TestCatalog_PackHash_EmptyControls(t *testing.T) {
	cat := NewCatalog(nil)
	hash := cat.PackHash(&stubDigester{})
	if hash != "" {
		t.Fatalf("empty catalog hash should be empty, got %v", hash)
	}
}

func TestCatalog_PackHash_NilHasher(t *testing.T) {
	cat := NewCatalog([]ControlDefinition{{ID: "CTL.A.001"}})
	hash := cat.PackHash(nil)
	if hash != "" {
		t.Fatalf("nil hasher should return empty, got %v", hash)
	}
}

// ---------------------------------------------------------------------------
// ControlParamsJSON — UnmarshalJSON edge case
// ---------------------------------------------------------------------------

func TestControlParamsJSON_UnmarshalJSON_Null(t *testing.T) {
	var p ControlParams
	err := json.Unmarshal([]byte(`null`), &p)
	if err != nil {
		t.Fatalf("null unmarshal: %v", err)
	}
}

func TestControlParamsJSON_UnmarshalJSON_Valid(t *testing.T) {
	var p ControlParams
	err := json.Unmarshal([]byte(`{"protected_prefixes": ["data/"]}`), &p)
	if err != nil {
		t.Fatalf("valid unmarshal: %v", err)
	}
}

func TestControlParamsJSON_UnmarshalJSON_Invalid(t *testing.T) {
	var p ControlParams
	err := json.Unmarshal([]byte(`{bad`), &p)
	if err == nil {
		t.Fatal("expected error for bad JSON")
	}
}
