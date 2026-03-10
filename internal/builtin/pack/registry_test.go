package pack

import (
	"errors"
	"strings"
	"testing"

	ctl "github.com/sufield/stave/internal/adapters/input/controls/builtin"
)

func TestListPacksStableOrder(t *testing.T) {
	packs, err := ListPacks()
	if err != nil {
		t.Fatalf("ListPacks error: %v", err)
	}
	if len(packs) < 2 {
		t.Fatalf("pack count = %d, want >= 2", len(packs))
	}
	if packs[0].Name > packs[1].Name {
		t.Fatalf("packs not sorted: %q > %q", packs[0].Name, packs[1].Name)
	}
}

func TestDefaultRegistry(t *testing.T) {
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry error: %v", err)
	}
	if reg == nil {
		t.Fatal("expected default registry")
	}
	if strings.TrimSpace(reg.Version()) == "" {
		t.Fatal("expected non-empty registry version")
	}
}

func TestResolveEnabledPacks(t *testing.T) {
	ids, err := ResolveEnabledPacks([]string{"s3/public-exposure"})
	if err != nil {
		t.Fatalf("ResolveEnabledPacks error: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("resolved IDs = %d, want 3", len(ids))
	}
	if ids[0] != "CTL.S3.ACL.WRITE.001" {
		t.Fatalf("first id = %q, want %q", ids[0], "CTL.S3.ACL.WRITE.001")
	}
}

func TestResolveEnabledPacksUnknown(t *testing.T) {
	_, err := ResolveEnabledPacks([]string{"does-not-exist"})
	if err == nil {
		t.Fatal("expected error for unknown pack")
	}
}

func TestResolveEnabledPacksDedupSorted(t *testing.T) {
	ids, err := ResolveEnabledPacks([]string{"s3/public-exposure", "s3"})
	if err != nil {
		t.Fatalf("ResolveEnabledPacks error: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("expected non-empty IDs")
	}
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			t.Fatalf("ids not strictly sorted at %d: %q >= %q", i, ids[i-1], ids[i])
		}
	}
}

func TestNewRegistry_RejectsEmptyPacks(t *testing.T) {
	_, err := NewRegistry([]byte("version: v1\npacks: {}\n"))
	if err == nil {
		t.Fatal("expected error for empty packs")
	}
	if !errors.Is(err, ErrEmptyRegistry) {
		t.Fatalf("expected ErrEmptyRegistry, got: %v", err)
	}
}

func TestNewRegistry_RejectsUndefinedControlReference(t *testing.T) {
	_, err := NewRegistry([]byte(`
version: v1
packs:
  s3/public-exposure:
    description: Public exposure checks
    controls:
      - CTL.S3.PUBLIC.001
      - CTL.S3.MISSING.999
controls:
  CTL.S3.PUBLIC.001:
    path: internal/adapters/input/controls/builtin/embedded/s3/CTL.S3.PUBLIC.001.yaml
    summary: Public access blocked
`))
	if err == nil {
		t.Fatal("expected error for undefined control reference")
	}
	if !strings.Contains(err.Error(), `undefined control "CTL.S3.MISSING.999"`) {
		t.Fatalf("expected undefined control error, got: %v", err)
	}
}

func TestRegistryValidateStrict(t *testing.T) {
	reg, err := DefaultRegistry()
	if err != nil {
		t.Fatalf("DefaultRegistry error: %v", err)
	}
	if err := reg.ValidateStrict(ctl.EmbeddedFS()); err != nil {
		t.Fatalf("ValidateStrict error: %v", err)
	}
}

func TestRegistryValidateStrict_MissingFile(t *testing.T) {
	reg, err := NewRegistry([]byte(`
version: v1
packs:
  s3/public-exposure:
    description: Public exposure checks
    controls:
      - CTL.S3.PUBLIC.001
controls:
  CTL.S3.PUBLIC.001:
    path: internal/adapters/input/controls/builtin/embedded/s3/public/DOES_NOT_EXIST.yaml
    summary: Public access blocked
`))
	if err != nil {
		t.Fatalf("NewRegistry error: %v", err)
	}
	err = reg.ValidateStrict(ctl.EmbeddedFS())
	if err == nil {
		t.Fatal("expected strict validation error for missing file")
	}
	if !strings.Contains(err.Error(), "strict validation failed") {
		t.Fatalf("expected strict validation error, got: %v", err)
	}
}

func TestRegistry_ListPacksReturnsClones(t *testing.T) {
	if err := ensureDefault(); err != nil {
		t.Fatalf("ensureDefault error: %v", err)
	}
	packs := defaultRegistry.ListPacks()
	if len(packs) == 0 || len(packs[0].Controls) == 0 {
		t.Fatal("expected non-empty pack controls")
	}
	original := packs[0].Controls[0]
	packs[0].Controls[0] = "MUTATED"

	fresh := defaultRegistry.ListPacks()
	if fresh[0].Controls[0] != original {
		t.Fatalf("registry pack controls mutated via caller slice: got %q want %q", fresh[0].Controls[0], original)
	}
}

func TestRegistry_LookupPackReturnsClone(t *testing.T) {
	if err := ensureDefault(); err != nil {
		t.Fatalf("ensureDefault error: %v", err)
	}
	names := defaultRegistry.PackNames()
	if len(names) == 0 {
		t.Fatal("expected at least one pack")
	}

	p, ok := defaultRegistry.LookupPack(names[0])
	if !ok || len(p.Controls) == 0 {
		t.Fatalf("expected pack with controls, ok=%v", ok)
	}
	original := p.Controls[0]
	p.Controls[0] = "MUTATED"

	fresh, ok := defaultRegistry.LookupPack(names[0])
	if !ok {
		t.Fatalf("expected pack lookup ok")
	}
	if fresh.Controls[0] != original {
		t.Fatalf("lookup pack controls mutated via caller slice: got %q want %q", fresh.Controls[0], original)
	}
}

func TestRegistry_ControlRefsReturnsClone(t *testing.T) {
	if err := ensureDefault(); err != nil {
		t.Fatalf("ensureDefault error: %v", err)
	}
	refs := defaultRegistry.ControlRefs()
	if len(refs) == 0 {
		t.Fatal("expected control refs")
	}
	var key string
	var original ControlRef
	for k, v := range refs {
		key = k
		original = v
		break
	}
	refs[key] = ControlRef{Path: "MUTATED", Summary: "MUTATED"}

	fresh := defaultRegistry.ControlRefs()
	if fresh[key] != original {
		t.Fatalf("control refs map mutated via caller write: got %+v want %+v", fresh[key], original)
	}
}
