package pack

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	ctl "github.com/sufield/stave/internal/adapters/controls/builtin"
)

func TestRegistryPacksAreValid(t *testing.T) {
	reg := testRegistry(t)

	packs := reg.ListPacks()
	refs := reg.ControlRefs()

	for _, p := range packs {
		pack := p
		t.Run("Pack_"+pack.Name, func(t *testing.T) {
			if len(pack.Controls) == 0 {
				t.Fatalf("pack %q has no controls", pack.Name)
			}
			for _, id := range pack.Controls {
				if _, ok := refs[id]; !ok {
					t.Fatalf("pack %q references control %q missing from index controls map", pack.Name, id)
				}
			}
		})
	}
}

func TestRegistryEmbeddedFilesExist(t *testing.T) {
	reg := testRegistry(t)

	root, err := moduleRootFromThisFile()
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}

	rootFS := os.DirFS(root)
	for id, ref := range reg.ControlRefs() {
		ctlID := id
		ctlRef := ref
		t.Run(ctlID, func(t *testing.T) {
			if strings.TrimSpace(ctlRef.Path) == "" {
				t.Fatalf("control %q has empty path", ctlID)
			}

			cleanPath := filepath.ToSlash(filepath.Clean(ctlRef.Path))
			info, statErr := fs.Stat(rootFS, cleanPath)
			if statErr != nil {
				t.Fatalf("file missing for control %s: %s (%v)", ctlID, ctlRef.Path, statErr)
			}
			if info.IsDir() {
				t.Fatalf("path for control %s is a directory, expected a YAML file: %s", ctlID, ctlRef.Path)
			}

			base := strings.TrimSuffix(filepath.Base(ctlRef.Path), filepath.Ext(ctlRef.Path))
			if base != ctlID {
				t.Fatalf("control %q path basename mismatch: got %q from %s", ctlID, base, ctlRef.Path)
			}
		})
	}
}

func TestIndexCoversAllEmbeddedBuiltins(t *testing.T) {
	reg := testRegistry(t)

	root, err := moduleRootFromThisFile()
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}

	embeddedRoot := filepath.Join(root, "internal", "controldata", "embedded")
	paths, err := collectEmbeddedControlPaths(embeddedRoot)
	if err != nil {
		t.Fatalf("collect embedded controls: %v", err)
	}

	refs := reg.ControlRefs()
	var missing []string
	for _, p := range paths {
		id := strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
		if _, ok := refs[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("index.yaml missing metadata entries for embedded controls: %s", strings.Join(missing, ", "))
	}
}

func TestRegistryNoOrphanedFiles(t *testing.T) {
	reg := testRegistry(t)

	orphans, err := reg.VerifyNoOrphans(ctl.EmbeddedFS(), "embedded")
	if err != nil {
		t.Fatalf("failed to walk embedded FS: %v", err)
	}
	if len(orphans) > 0 {
		t.Errorf("found %d orphaned files in embedded directory (not in index.yaml):", len(orphans))
		for _, p := range orphans {
			t.Logf("  - %s", p)
		}
		t.Fail()
	}
}

func moduleRootFromThisFile() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", os.ErrNotExist
	}
	// internal/builtin/pack -> module root is three directories up.
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..")), nil
}

func collectEmbeddedControlPaths(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		base := filepath.Base(path)
		if !strings.HasPrefix(base, "CTL.") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
