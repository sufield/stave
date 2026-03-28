package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockAliasRegistry struct {
	resp domain.InspectAliasesResponse
	err  error
}

func (m *mockAliasRegistry) ListAliases(_ context.Context, _ string) (domain.InspectAliasesResponse, error) {
	return m.resp, m.err
}

func TestInspectAliases(t *testing.T) {
	sampleResp := domain.InspectAliasesResponse{
		Aliases:            []any{map[string]any{"name": "is_encrypted"}},
		SupportedOperators: []string{"eq", "ne"},
	}

	tests := []struct {
		name     string
		req      domain.InspectAliasesRequest
		registry *mockAliasRegistry
		wantErr  bool
	}{
		{
			name:     "happy path all aliases",
			req:      domain.InspectAliasesRequest{},
			registry: &mockAliasRegistry{resp: sampleResp},
		},
		{
			name:     "filtered by category",
			req:      domain.InspectAliasesRequest{Category: "Encryption"},
			registry: &mockAliasRegistry{resp: sampleResp},
		},
		{
			name:     "registry error",
			req:      domain.InspectAliasesRequest{},
			registry: &mockAliasRegistry{err: errors.New("registry unavailable")},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InspectAliasesDeps{Registry: tc.registry}
			resp, err := InspectAliases(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Aliases == nil {
				t.Error("Aliases: got nil")
			}
			if len(resp.SupportedOperators) == 0 {
				t.Error("SupportedOperators: got empty")
			}
		})
	}
}

func TestInspectAliases_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InspectAliasesDeps{Registry: &mockAliasRegistry{}}
	_, err := InspectAliases(ctx, domain.InspectAliasesRequest{}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
