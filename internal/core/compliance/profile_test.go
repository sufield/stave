package compliance

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestValidateProfile(t *testing.T) {
	tests := []struct {
		name    string
		ids     []kernel.ControlID
		wantErr bool
		errLike string
	}{
		{
			name:    "no conflicts",
			ids:     []kernel.ControlID{"ACCESS.001", "CONTROLS.001", "AUDIT.001"},
			wantErr: false,
		},
		{
			name:    "incompatible pair present",
			ids:     []kernel.ControlID{"CONTROLS.003", "RETENTION.001", "ACCESS.001"},
			wantErr: true,
			errLike: "CONTROLS.003 and RETENTION.001 are incompatible",
		},
		{
			name:    "only one of the pair — ok",
			ids:     []kernel.ControlID{"CONTROLS.003", "ACCESS.001"},
			wantErr: false,
		},
		{
			name:    "empty profile — ok",
			ids:     []kernel.ControlID{},
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateProfile(tc.ids)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if tc.errLike != "" && !strings.Contains(err.Error(), tc.errLike) {
					t.Errorf("error should contain %q, got: %v", tc.errLike, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
