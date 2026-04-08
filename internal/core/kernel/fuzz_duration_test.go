package kernel

import "testing"

func FuzzParseDuration(f *testing.F) {
	seeds := []string{
		"", "0", "1h", "7d", "168h",
		"1.5d", "1d12h", "24h",
		"-1h", "0d", "999d",
		"abc", "d", "h", "1x",
		"9999999999999999999h",
		string(make([]byte, 1024)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input.
		_, _ = ParseDuration(input)
	})
}
