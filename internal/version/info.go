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

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
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
		}
	}
}
