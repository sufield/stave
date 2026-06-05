package apply

import (
	"testing"
	"time"
)

// Test_RedGate_ProfileMaxUnsafeDayUnit asserts that profile mode parses
// --max-unsafe with the same duration grammar as the standard apply path.
//
// The standard path resolves --max-unsafe via kernel.ParseDuration, which
// accepts the 'd' (day) unit ("7d" -> 168h). unit_test.go's "valid flags
// with --now" subcase proves the standard path turns "7d" into 7*24h.
//
// resolveProfileMode (options_profile.go) instead parses the SAME flag with
// the stdlib time.ParseDuration, which rejects any 'd' suffix. The in-code
// comment claims "the same duration semantic applies whether the user runs
// profile or standard mode" — this test pins the correct behavior so the
// claim becomes enforceable: "7d" must resolve to 168h in profile mode too.
//
// Against current code this FAILS because time.ParseDuration("7d") returns
// `time: unknown unit "d"`, so resolveProfileMode returns an error instead
// of a RunConfig with MaxUnsafeDuration == 168h.
func Test_RedGate_ProfileMaxUnsafeDayUnit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("resolveProfileMode panicked: %v", r)
		}
	}()

	o := &Options{
		Profile:   string(ProfileAWSS3),
		InputFile: "obs.json", // non-empty; resolveProfileMode does not stat it
		SharedOptions: SharedOptions{
			Format:            "json",
			MaxUnsafeDuration: "7d", // identical value standard mode accepts as 168h
		},
	}

	cfg, err := resolveProfileMode(o, cobraState{})
	if err != nil {
		t.Fatalf("profile mode rejected --max-unsafe=7d but standard mode accepts it as 168h: %v", err)
	}
	if cfg.Profile == nil {
		t.Fatalf("RunConfig.Profile is nil; cannot verify parsed --max-unsafe")
	}
	if got, want := cfg.Profile.MaxUnsafeDuration, 7*24*time.Hour; got != want {
		t.Fatalf("MaxUnsafeDuration = %v, want %v (7d == 168h to match standard mode)", got, want)
	}
}
