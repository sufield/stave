package doctor

import (
	"os"
	"strings"
)

func detectOSVersion(goos string) string {
	switch goos {
	case "linux":
		return detectLinuxOSVersion()
	case "darwin":
		return detectDarwinOSVersion()
	default:
		return ""
	}
}

func detectLinuxOSVersion() string {
	paths := []string{"/etc/os-release", "/usr/lib/os-release"}
	for _, path := range paths {
		// #nosec G304 -- path iterates over fixed trusted Linux os-release locations.
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if v := parseLinuxOSRelease(data); v != "" {
			return v
		}
	}
	return ""
}

func parseLinuxOSRelease(data []byte) string {
	const (
		fieldPrettyName = "PRETTY_NAME"
		fieldName       = "NAME"
		fieldVersionID  = "VERSION_ID"
	)

	fields := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		fields[key] = value
	}

	if v := strings.TrimSpace(fields[fieldPrettyName]); v != "" {
		return v
	}

	name := strings.TrimSpace(fields[fieldName])
	versionID := strings.TrimSpace(fields[fieldVersionID])
	if name != "" && versionID != "" {
		return name + " " + versionID
	}
	if name != "" {
		return name
	}
	return ""
}

func detectDarwinOSVersion() string {
	data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		return ""
	}
	const key = "<key>ProductVersion</key>"
	_, after, ok := strings.Cut(string(data), key)
	if !ok {
		return ""
	}
	version, ok := plistStringValue(after)
	if !ok {
		return ""
	}
	return "macOS " + version
}

func plistStringValue(raw string) (string, bool) {
	start := strings.Index(raw, "<string>")
	end := strings.Index(raw, "</string>")
	if start < 0 || end < 0 || end <= start {
		return "", false
	}
	return raw[start+len("<string>") : end], true
}

func detectCI(getenv func(string) string) string {
	type provider struct {
		name string
		key  string
		kind string // "eq" or "set"
		val  string
	}

	providers := []provider{
		{name: "GitHub Actions", key: "GITHUB_ACTIONS", kind: "eq", val: "true"},
		{name: "GitLab CI", key: "GITLAB_CI", kind: "eq", val: "true"},
		{name: "CircleCI", key: "CIRCLECI", kind: "eq", val: "true"},
		{name: "Jenkins", key: "JENKINS_URL", kind: "set"},
		{name: "Buildkite", key: "BUILDKITE", kind: "eq", val: "true"},
		{name: "Travis CI", key: "TRAVIS", kind: "eq", val: "true"},
	}
	for _, p := range providers {
		v := getenv(p.key)
		if p.kind == "set" && v != "" {
			return p.name
		}
		if p.kind == "eq" && v == p.val {
			return p.name
		}
	}
	if getenv("CI") == "true" || getenv("CI") == "1" {
		return "CI (unknown provider)"
	}
	return ""
}

func detectContainer() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Docker"
	}
	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return ""
	}
	s := string(data)
	if strings.Contains(s, "docker") {
		return "Docker"
	}
	if strings.Contains(s, "kubepods") {
		return "Kubernetes"
	}
	if strings.Contains(s, "lxc") {
		return "LXC"
	}
	return ""
}
