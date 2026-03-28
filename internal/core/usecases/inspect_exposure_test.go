package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockExposureClassifier struct {
	resp domain.InspectExposureResponse
	err  error
}

func (m *mockExposureClassifier) ClassifyExposure(_ context.Context, _ []byte) (domain.InspectExposureResponse, error) {
	return m.resp, m.err
}

type mockExposureInputReader struct {
	data []byte
	err  error
}

func (m *mockExposureInputReader) ReadInput(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

func TestInspectExposure(t *testing.T) {
	sampleResp := domain.InspectExposureResponse{
		Classifications: []any{map[string]any{"name": "bucket-a", "exposure": "PUBLIC"}},
		Visibility:      map[string]any{"effective": "public"},
	}

	tests := []struct {
		name       string
		req        domain.InspectExposureRequest
		classifier *mockExposureClassifier
		reader     *mockExposureInputReader
		wantErr    bool
	}{
		{
			name:       "happy path with file",
			req:        domain.InspectExposureRequest{FilePath: "resources.json"},
			classifier: &mockExposureClassifier{resp: sampleResp},
			reader:     &mockExposureInputReader{data: []byte(`{"resources":[]}`)},
		},
		{
			name:       "happy path with stdin data",
			req:        domain.InspectExposureRequest{InputData: []byte(`{"resources":[]}`)},
			classifier: &mockExposureClassifier{resp: sampleResp},
			reader:     &mockExposureInputReader{},
		},
		{
			name:       "no input",
			req:        domain.InspectExposureRequest{},
			classifier: &mockExposureClassifier{},
			reader:     &mockExposureInputReader{},
			wantErr:    true,
		},
		{
			name:       "reader error",
			req:        domain.InspectExposureRequest{FilePath: "missing.json"},
			classifier: &mockExposureClassifier{},
			reader:     &mockExposureInputReader{err: errors.New("file not found")},
			wantErr:    true,
		},
		{
			name:       "classifier error",
			req:        domain.InspectExposureRequest{InputData: []byte(`bad`)},
			classifier: &mockExposureClassifier{err: errors.New("parse exposure input: invalid JSON")},
			reader:     &mockExposureInputReader{},
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InspectExposureDeps{Classifier: tc.classifier, Reader: tc.reader}
			resp, err := InspectExposure(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Classifications == nil {
				t.Error("Classifications: got nil")
			}
		})
	}
}

func TestInspectExposure_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InspectExposureDeps{
		Classifier: &mockExposureClassifier{},
		Reader:     &mockExposureInputReader{},
	}
	_, err := InspectExposure(ctx, domain.InspectExposureRequest{FilePath: "resources.json"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
