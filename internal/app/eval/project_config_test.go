package eval

import (
	"context"
	"testing"

	"github.com/sufield/stave/internal/adapters/input/controls/builtin"
	"github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
)

func defaultPackRegistry(t *testing.T) *pack.Registry {
	t.Helper()
	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		t.Fatalf("load pack registry: %v", err)
	}
	return reg
}

func TestResolveProjectConfig_InvalidExceptionExpiry(t *testing.T) {
	_, err := ResolveProjectConfig(context.Background(), ProjectConfigInput{
		Exceptions: []ExceptionInput{
			{
				ControlID: kernel.ControlID("CTL.S3.PUBLIC.001"),
				AssetID:   asset.ID("res-1"),
				Reason:    "test",
				Expires:   "bad-date",
			},
		},
	})
	if err == nil {
		t.Fatal("expected invalid exception expiry error")
	}
}

func TestResolveProjectConfig_PackSelectionConflict(t *testing.T) {
	_, err := ResolveProjectConfig(context.Background(), ProjectConfigInput{
		EnabledControlPacks: []string{"s3/public-exposure"},
		ControlsFlagSet:     true,
	})
	if err == nil {
		t.Fatal("expected conflict error when packs and --controls are both set")
	}
}

func TestResolveProjectConfig_UnknownPack(t *testing.T) {
	_, err := ResolveProjectConfig(context.Background(), ProjectConfigInput{
		EnabledControlPacks: []string{"does-not-exist"},
		PackRegistry:        defaultPackRegistry(t),
	})
	if err == nil {
		t.Fatal("expected unknown pack error")
	}
}

func TestResolveProjectConfig_LoadsEnabledPack(t *testing.T) {
	got, err := ResolveProjectConfig(context.Background(), ProjectConfigInput{
		EnabledControlPacks: []string{"s3/public-exposure"},
		BuiltinLoader:       builtin.NewRegistry(builtin.EmbeddedFS(), "embedded").All,
		PackRegistry:        defaultPackRegistry(t),
	})
	if err != nil {
		t.Fatalf("ResolveProjectConfig() error = %v", err)
	}
	if len(got.PreloadedControls) == 0 {
		t.Fatal("expected preloaded controls for enabled pack")
	}
	if got.ControlSource.Source != "packs" {
		t.Fatalf("ControlSource.Source = %q, want packs", got.ControlSource.Source)
	}
}

func TestResolveProjectConfig_NoPacks(t *testing.T) {
	got, err := ResolveProjectConfig(context.Background(), ProjectConfigInput{})
	if err != nil {
		t.Fatalf("ResolveProjectConfig() error = %v", err)
	}
	if len(got.PreloadedControls) != 0 {
		t.Fatal("expected no preloaded controls when no packs")
	}
	if got.ControlSource.Source != "" {
		t.Fatalf("ControlSource.Source = %q, want empty", got.ControlSource.Source)
	}
}
