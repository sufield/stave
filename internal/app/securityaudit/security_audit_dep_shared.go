package securityaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func findRepoRoot(start string) (string, error) {
	dir := start
	if strings.TrimSpace(dir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		dir = wd
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(abs, "go.mod")); statErr == nil {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fmt.Errorf("could not locate repository root from %s", start)
		}
		abs = parent
	}
}
