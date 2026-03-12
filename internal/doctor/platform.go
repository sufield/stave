package doctor

import (
	"bufio"
	"bytes"
	"os"
	"strings"
)

// detectOSVersion dispatches OS discovery based on the runtime environment.
func detectOSVersion(goos string) string {
	switch goos {
	case "linux":
		return detectLinux()
	case "darwin":
		return detectDarwin()
	default:
		return ""
	}
}

// detectLinux attempts to parse standard Linux distribution files.
func detectLinux() string {
	paths := []string{"/etc/os-release", "/usr/lib/os-release"}
	for _, path := range paths {
		// #nosec G304 -- path iterates over fixed trusted Linux os-release locations.
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if v := parseOSRelease(data); v != "" {
			return v
		}
	}
	return ""
}

// parseOSRelease parses the shell-compatible key-value format of os-release files.
func parseOSRelease(data []byte) string {
	fields := make(map[string]string)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		fields[key] = val
	}

	if v, ok := fields["PRETTY_NAME"]; ok && v != "" {
		return v
	}

	name := fields["NAME"]
	version := fields["VERSION_ID"]
	if name != "" && version != "" {
		return name + " " + version
	}

	return name
}

// detectDarwin reads the macOS system version Plist.
func detectDarwin() string {
	data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		return ""
	}

	_, after, ok := strings.Cut(string(data), "<key>ProductVersion</key>")
	if !ok {
		return ""
	}

	val, ok := extractXMLTag(after, "string")
	if !ok {
		return ""
	}

	return "macOS " + val
}

// extractXMLTag finds the content between <tag> and </tag>.
func extractXMLTag(s, tag string) (string, bool) {
	_, after, ok := strings.Cut(s, "<"+tag+">")
	if !ok {
		return "", false
	}

	val, _, ok := strings.Cut(after, "</"+tag+">")
	if !ok {
		return "", false
	}

	return val, true
}

// detectCI uses environment variables to identify known CI providers.
func detectCI(getenv func(string) string) string {
	providers := []struct {
		name string
		env  string
		want string // if empty, any non-empty value matches
	}{
		{"GitHub Actions", "GITHUB_ACTIONS", "true"},
		{"GitLab CI", "GITLAB_CI", "true"},
		{"CircleCI", "CIRCLECI", "true"},
		{"Buildkite", "BUILDKITE", "true"},
		{"Travis CI", "TRAVIS", "true"},
		{"Jenkins", "JENKINS_URL", ""},
		{"Azure Pipelines", "TF_BUILD", "True"},
	}

	for _, p := range providers {
		val := getenv(p.env)
		if val == "" {
			continue
		}
		if p.want == "" || val == p.want {
			return p.name
		}
	}

	if generic := getenv("CI"); generic == "true" || generic == "1" {
		return "CI (unknown provider)"
	}

	return ""
}

// detectContainer checks for common containerization markers.
func detectContainer() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "Docker"
	}

	data, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return ""
	}

	heuristics := []struct {
		pattern string
		label   string
	}{
		{"docker", "Docker"},
		{"kubepods", "Kubernetes"},
		{"lxc", "LXC"},
	}

	content := string(data)
	for _, h := range heuristics {
		if strings.Contains(content, h.pattern) {
			return h.label
		}
	}

	return ""
}
