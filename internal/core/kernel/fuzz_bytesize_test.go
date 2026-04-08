package kernel

import "testing"

func FuzzParseByteSize(f *testing.F) {
	seeds := []string{
		"", "0", "1", "-1",
		"256MB", "1GB", "512mb", "1024",
		"100KB", "10TB", "999PB",
		"abc", "MB", "1.5GB",
		"9999999999999999999GB",
		string(make([]byte, 1024)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Must not panic on any input.
		_, _ = ParseByteSize(input)
	})
}
