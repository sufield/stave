package crypto

import (
	"testing"
)

func TestHashDelimited_DelimiterCollision(t *testing.T) {
	t.Parallel()

	parts1 := []string{"a\nb", "c"}
	parts2 := []string{"a", "b", "c"}

	h1 := HashDelimited(parts1, '\n')
	h2 := HashDelimited(parts2, '\n')

	if h1 == h2 {
		t.Errorf("CRITICAL BUG: HashDelimited produced identical digest %q for distinct component lists %v and %v; delimiter in part causes collision", h1, parts1, parts2)
	}
}
