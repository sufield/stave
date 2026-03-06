package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/envvar"
)

func TestSaveLoadAndResolveSelected(t *testing.T) {
	t.Setenv(envvar.ContextsFile.Name, filepath.Join(t.TempDir(), "contexts.yaml"))
	st := &Store{Active: "prod", Contexts: map[string]Context{
		"prod": {ProjectRoot: "/repo/prod", ProjectConfig: "stave.yaml", Defaults: Defaults{ControlsDir: "controls", ObservationsDir: "observations"}},
		"dev":  {ProjectRoot: "/repo/dev", ProjectConfig: "stave.yaml"},
	}}
	if err := st.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, _, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Active != "prod" {
		t.Fatalf("active = %q", loaded.Active)
	}
	name, ctx, ok, err := loaded.ResolveSelected()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !ok || name != "prod" || ctx.ProjectRoot != "/repo/prod" {
		t.Fatalf("unexpected resolve result: ok=%v name=%q ctx=%+v", ok, name, ctx)
	}

	t.Setenv(envvar.Context.Name, "dev")
	name, ctx, ok, err = loaded.ResolveSelected()
	if err != nil {
		t.Fatalf("resolve env override: %v", err)
	}
	if !ok || name != "dev" || ctx.ProjectRoot != "/repo/dev" {
		t.Fatalf("unexpected env resolve result: ok=%v name=%q ctx=%+v", ok, name, ctx)
	}
}

func TestResolveSelectedMissingEnvContext(t *testing.T) {
	st := &Store{Active: "prod", Contexts: map[string]Context{"prod": {ProjectRoot: "/repo/prod"}}}
	t.Setenv(envvar.Context.Name, "missing")
	_, _, _, err := st.ResolveSelected()
	if err == nil {
		t.Fatal("expected error for missing env context")
	}
}

func TestSortedNamesDeterministic(t *testing.T) {
	st := &Store{Contexts: map[string]Context{"z": {}, "a": {}, "m": {}}}
	got := st.Names()
	want := []string{"a", "m", "z"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sorted names = %v, want %v", got, want)
	}
}

func TestAbsPath(t *testing.T) {
	ctx := Context{ProjectRoot: "/repo/root"}
	if got := ctx.AbsPath("controls"); got != "/repo/root/controls" {
		t.Fatalf("AbsPath relative = %q", got)
	}
	if got := ctx.AbsPath("/abs/path"); got != "/abs/path" {
		t.Fatalf("AbsPath absolute = %q", got)
	}
}

func TestLoadMissingFileReturnsEmptyStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nope.yaml")
	t.Setenv(envvar.ContextsFile.Name, p)
	st, path, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if path != p {
		t.Fatalf("path=%q want=%q", path, p)
	}
	if st == nil || st.Contexts == nil || len(st.Contexts) != 0 {
		t.Fatalf("unexpected store: %#v", st)
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatalf("file should not be created on load")
	}
}

func TestContextsFilePathDefaultsToUserConfigDir(t *testing.T) {
	t.Setenv(envvar.ContextsFile.Name, "")
	cfgDir, err := os.UserConfigDir()
	if err != nil || cfgDir == "" {
		t.Skip("user config dir unavailable in test environment")
	}

	got, err := resolveStorePath()
	if err != nil {
		t.Fatalf("resolveStorePath: %v", err)
	}
	want := filepath.Join(cfgDir, "stave", "contexts.yaml")
	if got != want {
		t.Fatalf("contextsFilePath=%q want=%q", got, want)
	}
}
