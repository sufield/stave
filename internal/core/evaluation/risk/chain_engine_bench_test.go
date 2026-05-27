package risk

import (
	"fmt"
	"testing"
)

// BenchmarkDetectChains measures the inverted-index implementation
// across chain-catalog and failure-set sizes that span today's
// scale (597 chains) and the projected next-three-years scale
// (~2,000 chains).
//
// Compare against BenchmarkDetectChainsLegacy to confirm the
// expected speedup curve before retiring the legacy implementation
// from the parity test.
func BenchmarkDetectChains(b *testing.B) {
	cases := []struct {
		chains   int
		controls int
		failures int
	}{
		{100, 200, 100},
		{597, 1000, 1000},
		{597, 1000, 5000},
		{2000, 1000, 5000},
	}
	for _, tc := range cases {
		name := fmt.Sprintf("chains=%d_failures=%d", tc.chains, tc.failures)
		b.Run(name, func(b *testing.B) {
			chains, controls := makeSyntheticCatalog(tc.chains, tc.controls)
			failures := makeSyntheticFailures(tc.controls, tc.failures)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = DetectChains(failures, chains, controls, nil)
			}
		})
	}
}

func BenchmarkDetectChainsLegacy(b *testing.B) {
	cases := []struct {
		chains   int
		controls int
		failures int
	}{
		{100, 200, 100},
		{597, 1000, 1000},
		{597, 1000, 5000},
		{2000, 1000, 5000},
	}
	for _, tc := range cases {
		name := fmt.Sprintf("chains=%d_failures=%d", tc.chains, tc.failures)
		b.Run(name, func(b *testing.B) {
			chains, controls := makeSyntheticCatalog(tc.chains, tc.controls)
			failures := makeSyntheticFailures(tc.controls, tc.failures)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = detectChainsLegacy(failures, chains, controls, nil)
			}
		})
	}
}
