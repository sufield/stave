package version

import "runtime/debug"

// Build metadata defaults. Release builds override these with ldflags.
var (
	Version    = "dev"
	Prerelease = ""
	Commit     = ""
	Date       = ""
	BuiltBy    = ""
)

// ShortCommit returns a 7-character prefix of the commit hash,
// suitable for CLI display. Returns the full string if shorter.
func ShortCommit() string {
	if len(Commit) > 7 {
		return Commit[:7]
	}
	return Commit
}

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	dirty := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if Commit == "" {
				Commit = setting.Value
			}
		case "vcs.time":
			if Date == "" {
				Date = setting.Value
			}
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if dirty && Commit != "" {
		Commit += "-dirty"
	}
}
