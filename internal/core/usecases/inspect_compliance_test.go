package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockComplianceResolver struct {
	resp domain.InspectComplianceResponse
	err  error
}

func (m *mockComplianceResolver) ResolveCrosswalk(_ context.Context, _ []byte, _, _ []string) (domain.InspectComplianceResponse, error) {
	return m.resp, m.err
}

type mockComplianceInputReader struct {
	data []byte
	err  error
}

func (m *mockComplianceInputReader) ReadInput(_ context.Context, _ string) ([]byte, error) {
	return m.data, m.err
}

func TestInspectCompliance(t *testing.T) {
	sampleResp := domain.InspectComplianceResponse{
		ResolutionJSON: []byte(`{"resolved":true}`),
	}

	tests := []struct {
		name     string
		req      domain.InspectComplianceRequest
		resolver *mockComplianceResolver
		reader   *mockComplianceInputReader
		wantErr  bool
	}{
		{
			name:     "happy path with file",
			req:      domain.InspectComplianceRequest{FilePath: "crosswalk.yaml"},
			resolver: &mockComplianceResolver{resp: sampleResp},
			reader:   &mockComplianceInputReader{data: []byte("checks:\n  CTL.A: {}")},
		},
		{
			name:     "happy path with stdin data",
			req:      domain.InspectComplianceRequest{InputData: []byte("checks:\n  CTL.A: {}")},
			resolver: &mockComplianceResolver{resp: sampleResp},
			reader:   &mockComplianceInputReader{},
		},
		{
			name: "with frameworks and check IDs",
			req: domain.InspectComplianceRequest{
				FilePath:   "crosswalk.yaml",
				Frameworks: []string{"nist_800_53"},
				CheckIDs:   []string{"CTL.S3.PUBLIC.001"},
			},
			resolver: &mockComplianceResolver{resp: sampleResp},
			reader:   &mockComplianceInputReader{data: []byte("checks:\n  CTL.A: {}")},
		},
		{
			name:     "no input",
			req:      domain.InspectComplianceRequest{},
			resolver: &mockComplianceResolver{},
			reader:   &mockComplianceInputReader{},
			wantErr:  true,
		},
		{
			name:     "reader error",
			req:      domain.InspectComplianceRequest{FilePath: "missing.yaml"},
			resolver: &mockComplianceResolver{},
			reader:   &mockComplianceInputReader{err: errors.New("file not found")},
			wantErr:  true,
		},
		{
			name:     "resolver error",
			req:      domain.InspectComplianceRequest{InputData: []byte("bad")},
			resolver: &mockComplianceResolver{err: errors.New("invalid framework")},
			reader:   &mockComplianceInputReader{},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := InspectComplianceDeps{Resolver: tc.resolver, Reader: tc.reader}
			resp, err := InspectCompliance(context.Background(), tc.req, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp.ResolutionJSON) == 0 {
				t.Error("ResolutionJSON: got empty")
			}
		})
	}
}

func TestInspectCompliance_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := InspectComplianceDeps{
		Resolver: &mockComplianceResolver{},
		Reader:   &mockComplianceInputReader{},
	}
	_, err := InspectCompliance(ctx, domain.InspectComplianceRequest{FilePath: "crosswalk.yaml"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
