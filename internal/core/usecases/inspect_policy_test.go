package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockPolicyAnalyzer struct {
	resp domain.InspectPolicyResponse
	err  error
}

func (m *mockPolicyAnalyzer) AnalyzePolicy(_ context.Context, _ []byte) (domain.InspectPolicyResponse, error) {
	return m.resp, m.err
}

type mockPolicyInputReader struct {
	data []byte
	err  error
}

func (m *mockPolicyInputReader) ReadInput(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

func TestInspectPolicy(t *testing.T) {
	sampleResp := domain.InspectPolicyResponse{
		Assessment:  map[string]any{"public": true},
		PrefixScope: map[string]any{"scopes": 2},
		Risk:        map[string]any{"level": "HIGH"},
		RequiredIAM: []string{"s3:GetObject"},
	}

	tests := []struct {
		name     string
		req      domain.InspectPolicyRequest
		analyzer *mockPolicyAnalyzer
		reader   *mockPolicyInputReader
		wantErr  bool
	}{
		{
			name:     "happy path with file",
			req:      domain.InspectPolicyRequest{FilePath: "policy.json"},
			analyzer: &mockPolicyAnalyzer{resp: sampleResp},
			reader:   &mockPolicyInputReader{data: []byte(`{"Version":"2012-10-17"}`)},
		},
		{
			name:     "happy path with stdin data",
			req:      domain.InspectPolicyRequest{InputData: []byte(`{"Version":"2012-10-17"}`)},
			analyzer: &mockPolicyAnalyzer{resp: sampleResp},
			reader:   &mockPolicyInputReader{},
		},
		{
			name:     "no input",
			req:      domain.InspectPolicyRequest{},
			analyzer: &mockPolicyAnalyzer{},
			reader:   &mockPolicyInputReader{},
			wantErr:  true,
		},
		{
			name:     "reader error",
			req:      domain.InspectPolicyRequest{FilePath: "missing.json"},
			analyzer: &mockPolicyAnalyzer{},
			reader:   &mockPolicyInputReader{err: errors.New("file not found")},
			wantErr:  true,
		},
		{
			name:     "analyzer error",
			req:      domain.InspectPolicyRequest{InputData: []byte(`bad`)},
			analyzer: &mockPolicyAnalyzer{err: errors.New("parse policy: invalid JSON")},
			reader:   &mockPolicyInputReader{},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InspectPolicyDeps{Analyzer: tc.analyzer, Reader: tc.reader}
			resp, err := InspectPolicy(context.Background(), tc.req, deps)
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
			if len(resp.RequiredIAM) == 0 {
				t.Error("RequiredIAM: got empty")
			}
		})
	}
}

func TestInspectPolicy_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InspectPolicyDeps{
		Analyzer: &mockPolicyAnalyzer{},
		Reader:   &mockPolicyInputReader{},
	}
	_, err := InspectPolicy(ctx, domain.InspectPolicyRequest{FilePath: "policy.json"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
