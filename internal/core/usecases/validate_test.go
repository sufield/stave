package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/sufield/stave/internal/core/domain"
)

type mockProjectValidator struct {
	resp domain.ValidateResponse
	err  error
}

func (m *mockProjectValidator) Validate(_ context.Context, _, _ string) (domain.ValidateResponse, error) {
	return m.resp, m.err
}

type mockFileValidator struct {
	resp domain.ValidateResponse
	err  error
}

func (m *mockFileValidator) ValidateFile(_ context.Context, _, _ string) (domain.ValidateResponse, error) {
	return m.resp, m.err
}

func TestValidate_Project(t *testing.T) {
	tests := []struct {
		name      string
		validator *mockProjectValidator
		wantValid bool
		wantErr   bool
	}{
		{
			name: "valid project",
			validator: &mockProjectValidator{resp: domain.ValidateResponse{
				Valid:   true,
				Summary: domain.ValidateSummary{ControlsChecked: 3, ObservationsChecked: 2},
			}},
			wantValid: true,
		},
		{
			name: "invalid project",
			validator: &mockProjectValidator{resp: domain.ValidateResponse{
				Valid:  false,
				Errors: []domain.ValidateDiagnostic{{Message: "bad schema"}},
			}},
			wantValid: false,
		},
		{
			name:      "validator error",
			validator: &mockProjectValidator{err: errors.New("cannot read controls")},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := ValidateDeps{ProjectValidator: tc.validator}
			resp, err := Validate(context.Background(), domain.ValidateRequest{
				ControlsDir:     "controls",
				ObservationsDir: "observations",
			}, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Valid != tc.wantValid {
				t.Errorf("Valid: got %v, want %v", resp.Valid, tc.wantValid)
			}
		})
	}
}

func TestValidate_SingleFile(t *testing.T) {
	tests := []struct {
		name      string
		validator *mockFileValidator
		wantValid bool
		wantErr   bool
	}{
		{
			name: "valid file",
			validator: &mockFileValidator{resp: domain.ValidateResponse{
				Valid: true,
			}},
			wantValid: true,
		},
		{
			name:      "validator error",
			validator: &mockFileValidator{err: errors.New("parse error")},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deps := ValidateDeps{FileValidator: tc.validator}
			resp, err := Validate(context.Background(), domain.ValidateRequest{
				InputFile: "input.yaml",
				Kind:      "control",
			}, deps)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.Valid != tc.wantValid {
				t.Errorf("Valid: got %v, want %v", resp.Valid, tc.wantValid)
			}
		})
	}
}

func TestValidate_NilFileValidator(t *testing.T) {
	deps := ValidateDeps{} // no file validator
	_, err := Validate(context.Background(), domain.ValidateRequest{
		InputFile: "input.yaml",
	}, deps)
	if err == nil {
		t.Fatal("expected error for nil file validator")
	}
}

func TestValidate_NilProjectValidator(t *testing.T) {
	deps := ValidateDeps{} // no project validator
	_, err := Validate(context.Background(), domain.ValidateRequest{
		ControlsDir: "controls",
	}, deps)
	if err == nil {
		t.Fatal("expected error for nil project validator")
	}
}

func TestValidate_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deps := ValidateDeps{
		ProjectValidator: &mockProjectValidator{},
	}
	_, err := Validate(ctx, domain.ValidateRequest{ControlsDir: "controls"}, deps)
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
