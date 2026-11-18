package stave

import (
	"context"
	"strings"
	"testing"
)

func TestNetworkEnumerate_Validation(t *testing.T) {
	_, err := NetworkEnumerate(context.Background(), NetworkEnumerateConfig{
		SnapshotsDir: "",
	})
	if err == nil {
		t.Fatal("expected error when SnapshotsDir is empty")
	}
	if !strings.Contains(err.Error(), "--observations is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestNetworkProve_Validation(t *testing.T) {
	_, err := NetworkProve(context.Background(), NetworkProveConfig{
		SnapshotsDir: "",
	})
	if err == nil {
		t.Fatal("expected error when SnapshotsDir is empty")
	}
	if !strings.Contains(err.Error(), "--observations is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestLoadNetworkGraph_NonexistentDir(t *testing.T) {
	_, err := loadNetworkGraph(context.Background(), "/nonexistent/path/to/observations")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestLoadNetworkGraph_ValidDir(t *testing.T) {
	const validDir = "../../testdata/e2e/e2e-disclosure-lordofheaven-2025/observations"
	g, err := loadNetworkGraph(context.Background(), validDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g == nil {
		t.Fatal("expected non-nil Graph")
	}
}

func Test_normalizePort(t *testing.T) {
	tests := []struct {
		name  string
		input int
		want  int
	}{
		{name: "zero port defaults to DefaultSSHPort", input: 0, want: DefaultSSHPort},
		{name: "negative port defaults to DefaultSSHPort", input: -1, want: DefaultSSHPort},
		{name: "explicit port 22 preserved", input: 22, want: 22},
		{name: "custom port preserved", input: 2222, want: 2222},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizePort(tc.input); got != tc.want {
				t.Errorf("normalizePort(%d) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestNetworkEnumerateConfig_Validate(t *testing.T) {
	t.Run("empty SnapshotsDir returns error", func(t *testing.T) {
		cfg := NetworkEnumerateConfig{SnapshotsDir: ""}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid SnapshotsDir returns nil", func(t *testing.T) {
		cfg := NetworkEnumerateConfig{SnapshotsDir: "/path/to/obs"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestNetworkEnumerateConfig_NormalizedPort(t *testing.T) {
	t.Run("defaults when zero or negative", func(t *testing.T) {
		cfg := NetworkEnumerateConfig{Port: 0}
		if p := cfg.NormalizedPort(); p != DefaultSSHPort {
			t.Errorf("NormalizedPort() = %d, want %d", p, DefaultSSHPort)
		}
	})

	t.Run("preserves positive port", func(t *testing.T) {
		cfg := NetworkEnumerateConfig{Port: 2222}
		if p := cfg.NormalizedPort(); p != 2222 {
			t.Errorf("NormalizedPort() = %d, want 2222", p)
		}
	})
}

func TestNetworkProveConfig_Validate(t *testing.T) {
	t.Run("empty SnapshotsDir returns error", func(t *testing.T) {
		cfg := NetworkProveConfig{SnapshotsDir: ""}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid SnapshotsDir returns nil", func(t *testing.T) {
		cfg := NetworkProveConfig{SnapshotsDir: "/path/to/obs"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestNetworkProveConfig_NormalizedPort(t *testing.T) {
	t.Run("defaults when zero or negative", func(t *testing.T) {
		cfg := NetworkProveConfig{Port: -1}
		if p := cfg.NormalizedPort(); p != DefaultSSHPort {
			t.Errorf("NormalizedPort() = %d, want %d", p, DefaultSSHPort)
		}
	})

	t.Run("preserves positive port", func(t *testing.T) {
		cfg := NetworkProveConfig{Port: 443}
		if p := cfg.NormalizedPort(); p != 443 {
			t.Errorf("NormalizedPort() = %d, want 443", p)
		}
	})
}

