package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LookPathInEnv searches for an executable in the system PATH.
// It is the default implementation for SystemEnvironment.PathLookupFn.
func LookPathInEnv(file string) (string, error) {
	return lookPath(file, os.Getenv("PATH"), os.Getenv("PATHEXT"), runtime.GOOS)
}

// lookPath is the testable core that searches for file across pathEnv directories.
func lookPath(file, pathEnv, pathExt, goos string) (string, error) {
	if pathEnv == "" {
		return "", errors.New("path is empty")
	}

	candidates := candidateExecutableNames(file, goos, pathExt)
	for _, dir := range filepath.SplitList(pathEnv) {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		for _, name := range candidates {
			full := filepath.Join(dir, name)
			if isExecutable(full, goos) {
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

	var out []string
	if strings.TrimSpace(pathExt) == "" {
		staticExts := [...]string{".EXE", ".BAT", ".CMD", ".COM"}
		out = make([]string, 0, len(staticExts))
		for _, ext := range staticExts {
			out = append(out, file+ext)
		}
	} else {
		n := strings.Count(pathExt, ";") + 1
		out = make([]string, 0, n)
		p := pathExt
		for p != "" {
			var ext string
			ext, p, _ = strings.Cut(p, ";")
			ext = strings.TrimSpace(ext)
			if ext == "" {
				continue
			}
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			out = append(out, file+ext)
		}
	}
	if len(out) == 0 {
		return []string{file + ".EXE"}
	}
	return out
}

func isExecutable(path, goos string) bool {
	// #nosec G703 -- path is a local executable candidate derived from PATH traversal.
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if goos == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}
