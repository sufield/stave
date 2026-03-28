package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockRiskScorer struct {
	resp domain.InspectRiskResponse
	err  error
}

func (m *mockRiskScorer) ScoreRisk(_ context.Context, _ []byte) (domain.InspectRiskResponse, error) {
	return m.resp, m.err
}

type mockRiskInputReader struct {
	data []byte
	err  error
}

func (m *mockRiskInputReader) ReadInput(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

func TestInspectRisk(t *testing.T) {
	sampleResp := domain.InspectRiskResponse{
		NormalizedActions: []string{"s3:GetObject"},
		Permissions:       map[string]any{"read": true},
		Report:            map[string]any{"level": "HIGH"},
	}

	tests := []struct {
		name    string
		req     domain.InspectRiskRequest
		scorer  *mockRiskScorer
		reader  *mockRiskInputReader
		wantErr bool
	}{
		{
			name:   "happy path with file",
			req:    domain.InspectRiskRequest{FilePath: "statement.json"},
			scorer: &mockRiskScorer{resp: sampleResp},
			reader: &mockRiskInputReader{data: []byte(`{"actions":["s3:GetObject"]}`)},
		},
		{
			name:   "happy path with stdin data",
			req:    domain.InspectRiskRequest{InputData: []byte(`{"actions":["s3:GetObject"]}`)},
			scorer: &mockRiskScorer{resp: sampleResp},
			reader: &mockRiskInputReader{},
		},
		{
			name:    "no input",
			req:     domain.InspectRiskRequest{},
			scorer:  &mockRiskScorer{},
			reader:  &mockRiskInputReader{},
			wantErr: true,
		},
		{
			name:    "reader error",
			req:     domain.InspectRiskRequest{FilePath: "missing.json"},
			scorer:  &mockRiskScorer{},
			reader:  &mockRiskInputReader{err: errors.New("file not found")},
			wantErr: true,
		},
		{
			name:    "scorer error",
			req:     domain.InspectRiskRequest{InputData: []byte(`bad`)},
			scorer:  &mockRiskScorer{err: errors.New("parse risk input: invalid JSON")},
			reader:  &mockRiskInputReader{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InspectRiskDeps{Scorer: tc.scorer, Reader: tc.reader}
			resp, err := InspectRisk(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Report == nil {
				t.Error("Report: got nil")
			}
		})
	}
}

func TestInspectRisk_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InspectRiskDeps{
		Scorer: &mockRiskScorer{},
		Reader: &mockRiskInputReader{},
	}
	_, err := InspectRisk(ctx, domain.InspectRiskRequest{FilePath: "statement.json"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
