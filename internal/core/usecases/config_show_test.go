package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockConfigResolver struct {
	data any
	err  error
}

func (m *mockConfigResolver) ResolveEffectiveConfig(_ context.Context) (any, error) {
	return m.data, m.err
}

func TestConfigShow(t *testing.T) {
	sampleConfig := map[string]any{"max_unsafe": "168h", "ci_policy": "fail_on_any_violation"}

	tests := []struct {
		name     string
		resolver *mockConfigResolver
		wantNil  bool
		wantErr  bool
	}{
		{
			name:     "happy path",
			resolver: &mockConfigResolver{data: sampleConfig},
		},
		{
			name:     "resolver error",
			resolver: &mockConfigResolver{err: errors.New("no project config")},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := ConfigShowDeps{Resolver: tc.resolver}
			resp, err := ConfigShow(context.Background(), domain.ConfigShowRequest{Format: "text"}, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.ConfigData == nil {
				t.Error("ConfigData: got nil")
			}
		})
	}
}

func TestConfigShow_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := ConfigShowDeps{Resolver: &mockConfigResolver{}}
	_, err := ConfigShow(ctx, domain.ConfigShowRequest{}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
