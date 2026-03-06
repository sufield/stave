package doctor

import (
	"os"
	"runtime"
)

func withDefaults(ctx Context) Context {
	if ctx.LookPathFn == nil {
		ctx.LookPathFn = LookPathInEnv
	}
	if ctx.GetenvFn == nil {
		ctx.GetenvFn = os.Getenv
	}
	if ctx.Goos == "" {
		ctx.Goos = runtime.GOOS
	}
	if ctx.Goarch == "" {
		ctx.Goarch = runtime.GOARCH
	}
	if ctx.GoVersion == "" {
		ctx.GoVersion = runtime.Version()
	}
	return ctx
}
