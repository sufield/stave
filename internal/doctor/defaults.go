package doctor

import (
	"os"
	"runtime"
)

// FillDefaults populates empty fields in the SystemEnvironment with standard system values.
func (c *SystemEnvironment) FillDefaults() {
	if c == nil {
		return
	}

	if c.PathLookupFn == nil {
		c.PathLookupFn = LookPathInEnv
	}
	if c.EnvVarFn == nil {
		c.EnvVarFn = os.Getenv
	}
	if c.OS == "" {
		c.OS = runtime.GOOS
	}
	if c.Arch == "" {
		c.Arch = runtime.GOARCH
	}
	if c.Runtime == "" {
		c.Runtime = runtime.Version()
	}
}

// NewEnvironment returns a SystemEnvironment initialized with system defaults.
func NewEnvironment() *SystemEnvironment {
	ctx := &SystemEnvironment{}
	ctx.FillDefaults()
	return ctx
}
