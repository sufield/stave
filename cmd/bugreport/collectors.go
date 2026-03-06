package bugreport

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/logging"
)

type doctorResult struct {
	Ready  bool           `json:"ready"`
	Checks []doctor.Check `json:"checks"`
}

type buildInfo struct {
	Available bool              `json:"available"`
	GoVersion string            `json:"go_version,omitempty"`
	Path      string            `json:"path,omitempty"`
	Main      buildModule       `json:"main"`
	Deps      []buildModule     `json:"deps,omitempty"`
	Settings  map[string]string `json:"settings,omitempty"`
	Runtime   map[string]string `json:"runtime"`
}

type buildModule struct {
	Path    string       `json:"path,omitempty"`
	Version string       `json:"version,omitempty"`
	Sum     string       `json:"sum,omitempty"`
	Replace *buildModule `json:"replace,omitempty"`
}

type envEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func collectBuildInfo() buildInfo {
	out := buildInfo{
		Runtime: map[string]string{
			"goos":   runtime.GOOS,
			"goarch": runtime.GOARCH,
		},
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return out
	}
	out.Available = true
	out.GoVersion = info.GoVersion
	out.Path = info.Path
	out.Main = toBuildModule(info.Main)
	out.Deps = make([]buildModule, 0, len(info.Deps))
	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		out.Deps = append(out.Deps, toBuildModule(*dep))
	}
	if len(info.Settings) > 0 {
		out.Settings = make(map[string]string, len(info.Settings))
		for _, s := range info.Settings {
			out.Settings[s.Key] = s.Value
		}
	}
	return out
}

func toBuildModule(in debug.Module) buildModule {
	out := buildModule{
		Path:    in.Path,
		Version: in.Version,
		Sum:     in.Sum,
	}
	if in.Replace != nil {
		r := toBuildModule(*in.Replace)
		out.Replace = &r
	}
	return out
}

func collectEnv() []envEntry {
	entries := make([]envEntry, 0, 32)
	for _, kv := range os.Environ() {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || !shouldCollectEnvKey(key) {
			continue
		}
		if strings.TrimSpace(value) == "" {
			continue
		}
		if isSensitiveEnvKey(key) {
			value = "[SANITIZED]"
		}
		entries = append(entries, envEntry{Key: key, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

func collectArgs() []string {
	args := append([]string(nil), os.Args...)
	return logging.SanitizeArgs(args)
}

func shouldCollectEnvKey(key string) bool {
	if strings.HasPrefix(key, "STAVE_") || strings.HasPrefix(key, "AWS_") {
		return true
	}
	switch key {
	case "PATH", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ",
		"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "JENKINS_URL", "BUILDKITE":
		return true
	default:
		return false
	}
}

func isSensitiveEnvKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	if k == "aws_access_key_id" || k == "aws_secret_access_key" || k == "aws_session_token" {
		return true
	}
	sensitive := []string{
		"secret", "token", "password", "private", "credential", "auth", "api_key", "access_key",
	}
	for _, part := range sensitive {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

func findConfigPath() (string, bool) {
	path, ok := cmdutil.FindNearestFile(cmdutil.ProjectConfigFile)
	if !ok || strings.TrimSpace(path) == "" {
		return "", false
	}
	return path, true
}

func findLogPath(cmd *cobra.Command, cwd string) (string, bool) {
	candidates := make([]string, 0, 2)
	if p := strings.TrimSpace(cmdutil.LogFilePath(cmd)); p != "" {
		candidates = append(candidates, fsutil.CleanUserPath(p))
	}
	candidates = append(candidates, filepath.Join(cwd, "stave.log"))

	for _, c := range candidates {
		if strings.TrimSpace(c) == "" {
			continue
		}
		info, err := os.Stat(c)
		if err != nil || info.IsDir() {
			continue
		}
		return c, true
	}
	return "", false
}

func tailBytesByLine(data []byte, maxLines int) []byte {
	if maxLines <= 0 || len(data) == 0 {
		return nil
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) <= maxLines {
		return data
	}
	start := len(lines) - maxLines
	out := bytes.Join(lines[start:], []byte{'\n'})
	return out
}
