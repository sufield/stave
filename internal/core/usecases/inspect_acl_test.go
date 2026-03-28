package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockACLAnalyzer struct {
	resp domain.InspectACLResponse
	err  error
}

func (m *mockACLAnalyzer) AnalyzeACL(_ context.Context, _ []byte) (domain.InspectACLResponse, error) {
	return m.resp, m.err
}

type mockACLInputReader struct {
	data []byte
	err  error
}

func (m *mockACLInputReader) ReadInput(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

func TestInspectACL(t *testing.T) {
	sampleResp := domain.InspectACLResponse{
		Assessment:   map[string]any{"has_public": true},
		GrantDetails: []any{map[string]any{"grantee": "AllUsers"}},
	}

	tests := []struct {
		name     string
		req      domain.InspectACLRequest
		analyzer *mockACLAnalyzer
		reader   *mockACLInputReader
		wantErr  bool
	}{
		{
			name:     "happy path with file",
			req:      domain.InspectACLRequest{FilePath: "grants.json"},
			analyzer: &mockACLAnalyzer{resp: sampleResp},
			reader:   &mockACLInputReader{data: []byte(`[{"grantee":"AllUsers"}]`)},
		},
		{
			name:     "happy path with stdin data",
			req:      domain.InspectACLRequest{InputData: []byte(`[{"grantee":"AllUsers"}]`)},
			analyzer: &mockACLAnalyzer{resp: sampleResp},
			reader:   &mockACLInputReader{},
		},
		{
			name:     "no input",
			req:      domain.InspectACLRequest{},
			analyzer: &mockACLAnalyzer{},
			reader:   &mockACLInputReader{},
			wantErr:  true,
		},
		{
			name:     "reader error",
			req:      domain.InspectACLRequest{FilePath: "missing.json"},
			analyzer: &mockACLAnalyzer{},
			reader:   &mockACLInputReader{err: errors.New("file not found")},
			wantErr:  true,
		},
		{
			name:     "analyzer error",
			req:      domain.InspectACLRequest{InputData: []byte(`bad`)},
			analyzer: &mockACLAnalyzer{err: errors.New("parse ACL grants: invalid JSON")},
			reader:   &mockACLInputReader{},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InspectACLDeps{Analyzer: tc.analyzer, Reader: tc.reader}
			resp, err := InspectACL(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Assessment == nil {
				t.Error("Assessment: got nil")
			}
			if resp.GrantDetails == nil {
				t.Error("GrantDetails: got nil")
			}
		})
	}
}

func TestInspectACL_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InspectACLDeps{
		Analyzer: &mockACLAnalyzer{},
		Reader:   &mockACLInputReader{},
	}
	_, err := InspectACL(ctx, domain.InspectACLRequest{FilePath: "grants.json"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
