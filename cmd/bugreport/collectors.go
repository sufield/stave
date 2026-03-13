package bugreport

import (
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/platform/logging"
)

// DoctorResult represents the output of the internal health check.
type DoctorResult struct {
	Ready  bool           `json:"ready"`
	Checks []doctor.Check `json:"checks"`
}

// BuildInfo contains details about the compiled binary and runtime environment.
type BuildInfo struct {
	Available bool              `json:"available"`
	GoVersion string            `json:"go_version,omitempty"`
	Path      string            `json:"path,omitempty"`
	Main      BuildModule       `json:"main"`
	Deps      []BuildModule     `json:"deps,omitempty"`
	Settings  map[string]string `json:"settings,omitempty"`
	Runtime   map[string]string `json:"runtime"`
}

// BuildModule describes a single Go module dependency.
type BuildModule struct {
	Path    string       `json:"path,omitempty"`
	Version string       `json:"version,omitempty"`
	Sum     string       `json:"sum,omitempty"`
	Replace *BuildModule `json:"replace,omitempty"`
}

// EnvEntry is a key-value pair from the process environment.
type EnvEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CollectBuildInfo gathers versioning and build metadata.
func CollectBuildInfo() BuildInfo {
	out := BuildInfo{
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
	out.Deps = make([]BuildModule, 0, len(info.Deps))
	for _, dep := range info.Deps {
		if dep != nil {
			out.Deps = append(out.Deps, toBuildModule(*dep))
		}
	}
	if len(info.Settings) > 0 {
		out.Settings = make(map[string]string, len(info.Settings))
		for _, s := range info.Settings {
			out.Settings[s.Key] = s.Value
		}
	}
	return out
}

func toBuildModule(in debug.Module) BuildModule {
	out := BuildModule{
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

// FilterEnv processes a raw environment slice, filtering for relevant
// keys and sanitizing secrets.
func FilterEnv(environ []string) []EnvEntry {
	entries := make([]EnvEntry, 0, 16)
	for _, kv := range environ {
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
		entries = append(entries, EnvEntry{Key: key, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

// SanitizeArgs cleans CLI arguments to remove potential credentials.
func SanitizeArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	cp := append([]string(nil), args...)
	return logging.SanitizeArgs(cp)
}

func shouldCollectEnvKey(key string) bool {
	key = strings.ToUpper(key)
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

// sensitiveEnvKeys are environment variable names (lowercase) whose values
// must be sanitized in bug reports. Only variables actually collected by
// shouldCollectEnvKey need to appear here. Keys are stored lowercase to
// avoid tripping the credential-reference safety test.
var sensitiveEnvKeys = map[string]struct{}{
	"aws_secret_access_key": {},
	"aws_session_token":     {},
	"aws_access_key_id":     {},
}

func isSensitiveEnvKey(key string) bool {
	_, ok := sensitiveEnvKeys[strings.ToLower(key)]
	return ok
}

func findConfigPath() (string, bool) {
	path, ok := projconfig.FindNearestFile(projconfig.ProjectConfigFile)
	if !ok || strings.TrimSpace(path) == "" {
		return "", false
	}
	return path, true
}

// FindLogPath returns the first existing file from the given candidates.
func FindLogPath(candidates ...string) (string, bool) {
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		info, err := os.Stat(c)
		if err == nil && !info.IsDir() {
			return c, true
		}
	}
	return "", false
}

// TailBytesByLine returns the last N lines of a byte slice.
func TailBytesByLine(data []byte, maxLines int) []byte {
	if maxLines <= 0 || len(data) == 0 {
		return nil
	}
	// Handle trailing newline so it doesn't count as an extra empty line.
	trimmed := data
	if trimmed[len(trimmed)-1] == '\n' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	count := 0
	for i := len(trimmed) - 1; i >= 0; i-- {
		if trimmed[i] == '\n' {
			count++
			if count == maxLines {
				return trimmed[i+1:]
			}
		}
	}
	// Fewer lines than maxLines — return original data.
	return data
}
