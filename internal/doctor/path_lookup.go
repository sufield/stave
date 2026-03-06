package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func LookPathInEnv(file string) (string, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return "", errors.New("PATH is empty")
	}

	candidates := candidateExecutableNames(file, runtime.GOOS, os.Getenv("PATHEXT"))
	for _, dir := range filepath.SplitList(pathEnv) {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		for _, name := range candidates {
			full := filepath.Join(dir, name)
			if isExecutableFile(full) {
				return full, nil
			}
		}
	}
	return "", fmt.Errorf("%s not found in PATH", file)
}

func candidateExecutableNames(file, goos, pathExt string) []string {
	if goos != "windows" {
		return []string{file}
	}
	if filepath.Ext(file) != "" {
		return []string{file}
	}

	var exts []string
	if strings.TrimSpace(pathExt) == "" {
		exts = []string{".EXE", ".BAT", ".CMD", ".COM"}
	} else {
		exts = strings.Split(pathExt, ";")
	}

	out := make([]string, 0, len(exts))
	for _, ext := range exts {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		out = append(out, file+ext)
	}
	if len(out) == 0 {
		return []string{file + ".EXE"}
	}
	return out
}

func isExecutableFile(path string) bool {
	// #nosec G703 -- path is a local executable candidate derived from PATH traversal.
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}
