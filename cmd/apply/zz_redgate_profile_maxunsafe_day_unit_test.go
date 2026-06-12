package apply

import (
	"testing"
)

// Test_RedGate_ProfileMaxUnsafeDayUnit asserts that profile mode accepts the
// same --max-unsafe duration grammar as the standard apply path, including the
// 'd' (day) unit ("7d" -> 168h).
//
// Parsing now lives in the facade (stave.EvaluateProfile -> parseProfileMaxUnsafe,
// which uses kernel.ParseDuration and accepts 'd'). The command must NOT parse
// the flag itself — it passes the raw string through verbatim. An earlier shape
// parsed it command-side with stdlib time.ParseDuration, which rejects any 'd'
// suffix and broke the "same duration semantic" contract. This test pins the
// passthrough: resolveProfileMode must accept "7d" without erroring and carry
// it forward unchanged for the facade to parse.
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
		t.Fatalf("RunConfig.Profile is nil; cannot verify --max-unsafe passthrough")
	}
	if got, want := cfg.Profile.MaxUnsafeDuration, "7d"; got != want {
		t.Fatalf("MaxUnsafeDuration = %q, want %q (raw string passed through to the facade)", got, want)
	}
}
