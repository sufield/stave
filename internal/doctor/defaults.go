package doctor

import (
	"os"
	"runtime"
)

// FillDefaults populates empty fields in the Context with standard system values.
func (c *Context) FillDefaults() {
	if c == nil {
		return
	}

	if c.LookPathFn == nil {
		c.LookPathFn = LookPathInEnv
	}
	if c.GetenvFn == nil {
		c.GetenvFn = os.Getenv
	}
	if c.Goos == "" {
		c.Goos = runtime.GOOS
	}
	if c.Goarch == "" {
		c.Goarch = runtime.GOARCH
	}
	if c.GoVersion == "" {
		c.GoVersion = runtime.Version()
	}
}

// NewContext returns a Context initialized with system defaults.
func NewContext() *Context {
	ctx := &Context{}
	ctx.FillDefaults()
	return ctx
}
