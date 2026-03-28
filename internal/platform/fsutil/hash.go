package fsutil

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// HashFile returns the SHA-256 hash for a file as a kernel.Digest.
func HashFile(path string) (kernel.Digest, error) {
	data, err := ReadFileLimited(path)
	if err != nil {
		return "", err
	}
	return platformcrypto.HashBytes(data), nil
}

// HashDirByExt returns a deterministic SHA-256 hash of files in dir matching extensions.
// Files are hashed as "name=hash\n" lines sorted by name, then the concatenation is hashed.
func HashDirByExt(dir string, exts ...string) (kernel.Digest, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	matches := buildExtMatcher(exts)

	type namedHash struct {
		name string
		hash string
	}

	pairs := make([]namedHash, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !matches(e.Name()) {
			continue
		}

		h, err := HashFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		pairs = append(pairs, namedHash{name: e.Name(), hash: string(h)})
	}

	slices.SortFunc(pairs, func(a, b namedHash) int {
		return strings.Compare(a.name, b.name)
	})

	var b strings.Builder
	for _, p := range pairs {
		b.WriteString(p.name)
		b.WriteByte('=')
		b.WriteString(p.hash)
		b.WriteByte('\n')
	}

	return platformcrypto.HashBytes([]byte(b.String())), nil
}

func buildExtMatcher(exts []string) func(name string) bool {
	normalized := make([]string, 0, len(exts))
	for _, ext := range exts {
		trimmed := strings.TrimSpace(ext)
		if trimmed == "" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return func(string) bool { return true }
	}

	return func(name string) bool {
		for _, ext := range normalized {
			if strings.HasSuffix(name, ext) {
				return true
			}
		}
		return false
	}
}
