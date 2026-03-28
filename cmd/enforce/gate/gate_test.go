package gate

import (
	"testing"

	appconfig "github.com/sufield/stave/internal/app/config"
)

func TestParseGatePolicy(t *testing.T) {
	tests := []struct {
		in      string
		want    appconfig.GatePolicy
		wantErr bool
	}{
		{in: string(appconfig.GatePolicyAny), want: appconfig.GatePolicyAny},
		{in: "  FAIL_ON_NEW_VIOLATION  ", want: appconfig.GatePolicyNew},
		{in: string(appconfig.GatePolicyOverdue), want: appconfig.GatePolicyOverdue},
		{in: "unknown", wantErr: true},
	}
	for _, tc := range tests {
		got, err := appconfig.ParseGatePolicy(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseGatePolicy(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseGatePolicy(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseGatePolicy(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
