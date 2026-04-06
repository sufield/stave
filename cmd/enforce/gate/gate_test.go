package gate

import (
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
)

func TestParseEnforcementGate(t *testing.T) {
	tests := []struct {
		in      string
		want    appconfig.EnforcementGate
		wantErr bool
	}{
		{in: string(appconfig.GateStrict), want: appconfig.GateStrict},
		{in: "  FAIL_ON_NEW_VIOLATION  ", want: appconfig.GateRegression},
		{in: string(appconfig.GateSLA), want: appconfig.GateSLA},
		{in: "unknown", wantErr: true},
	}
	for _, tc := range tests {
		got, err := appconfig.ParseEnforcementGate(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseEnforcementGate(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseEnforcementGate(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseEnforcementGate(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
