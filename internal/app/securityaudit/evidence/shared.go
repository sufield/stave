package evidence

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

func findRepoRootWith(start string, getwd func() (string, error), statFile func(string) (fs.FileInfo, error)) (string, error) {
	dir := start
	if strings.TrimSpace(dir) == "" {
		wd, err := getwd()
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
		if _, statErr := statFile(filepath.Join(abs, "go.mod")); statErr == nil {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fmt.Errorf("could not locate repository root from %s", start)
		}
		abs = parent
	}
}
