package coverage

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadEmbedded_HasProwlerInventories(t *testing.T) {
	inventories, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}

	want := map[string]int{
		"prowler|s3":  21,
		"prowler|iam": 47,
	}
	got := make(map[string]int)
	for _, inv := range inventories {
		got[inv.Tool+"|"+inv.Domain] = len(inv.Checks)
	}
	for key, n := range want {
		if got[key] != n {
			t.Errorf("inventory %s: got %d checks, want %d", key, got[key], n)
		}
	}
}

func TestLoadEmbedded_SortedDeterministic(t *testing.T) {
	a, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	b, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded second call: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("length mismatch: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Tool != b[i].Tool || a[i].Domain != b[i].Domain {
			t.Errorf("ordering not deterministic at index %d", i)
		}
	}
}

func TestLoadFromFS_DuplicateToolDomain(t *testing.T) {
	fsys := fstest.MapFS{
		"root/a.yaml": {Data: []byte("tool: t\ndomain: d\nchecks:\n  - id: x\n")},
		"root/b.yaml": {Data: []byte("tool: t\ndomain: d\nchecks:\n  - id: y\n")},
	}
	_, err := loadFromFS(fsys, "root")
	if err == nil || !strings.Contains(err.Error(), "duplicate inventory") {
		t.Fatalf("expected duplicate-inventory error, got: %v", err)
	}
}

func TestLoadFromFS_EmptyToolField(t *testing.T) {
	fsys := fstest.MapFS{
		"root/bad.yaml": {Data: []byte("domain: d\nchecks:\n  - id: x\n")},
	}
	_, err := loadFromFS(fsys, "root")
	if err == nil || !strings.Contains(err.Error(), "tool field is required") {
		t.Fatalf("expected tool-required error, got: %v", err)
	}
}

func TestLoadFromFS_EmptyCheckID(t *testing.T) {
	fsys := fstest.MapFS{
		"root/bad.yaml": {Data: []byte("tool: t\ndomain: d\nchecks:\n  - id: \"\"\n")},
	}
	_, err := loadFromFS(fsys, "root")
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty-id error, got: %v", err)
	}
}
