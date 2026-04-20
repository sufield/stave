package cliflags

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/config"
)

// GlobalSettingsFrom extracts the root persistent flags from cmd
// into a pure [config.GlobalSettings] value. Call this once in RunE
// at the adapter boundary; pass the result to command logic so the
// rest of the codebase sees plain data rather than a cobra command.
//
// The caller's control flow stays identical to the older
// GlobalFlags-based code — this function exists so non-adapter
// packages can accept a typed settings value without transitively
// importing cobra or pflag.
func GlobalSettingsFrom(cmd *cobra.Command) config.GlobalSettings {
	if cmd == nil {
		return config.GlobalSettings{}
	}
	rootFlags := cmd.Root().PersistentFlags()
	return config.GlobalSettings{
		Quiet:           getBool(rootFlags, FlagQuiet),
		Yes:             getBool(rootFlags, FlagYes),
		Force:           getBool(rootFlags, FlagForce),
		Sanitize:        getBool(rootFlags, FlagSanitize),
		PathMode:        ParsePathMode(getStr(rootFlags, FlagPathMode)),
		Strict:          getBool(rootFlags, FlagStrict),
		LogFile:         getStr(rootFlags, FlagLogFile),
		RequireOffline:  getBool(rootFlags, FlagOffline),
		AllowSymlinkOut: getBool(rootFlags, FlagSymlink),
	}
}
