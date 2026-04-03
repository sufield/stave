package doctor

import (
	"fmt"
	"os"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/outcome"
)

// Check Names
const (
	CheckVersionInfo       = "version-info"
	CheckOSVersion         = "os-version"
	CheckShell             = "shell"
	CheckCIEnv             = "ci-environment"
	CheckContainer         = "container"
	CheckWorkspaceWritable = "workspace-writable"
	CheckGit               = "git"
	CheckAWSCLI            = "aws-cli"
	CheckJQ                = "jq"
	CheckGraphviz          = "graphviz"
	CheckClipboard         = "clipboard-tool"
	CheckProxyEnv          = "offline-proxy-env"
)

func checkVersionInfo(ctx *Context) Check {
	var sb strings.Builder
	fmt.Fprintf(&sb, "stave_version=%s go_version=%s os=%s arch=%s",
		ctx.StaveVersion, ctx.GoVersion, ctx.Goos, ctx.Goarch)

	if ctx.BinaryPath != "" {
		fmt.Fprintf(&sb, " binary=%s", ctx.BinaryPath)
	}

	return Check{
		Name:    CheckVersionInfo,
		Status:  outcome.Pass,
		Message: sb.String(),
	}
}

func checkOSVersion(ctx *Context) Check {
	if ver := detectOSVersion(ctx.Goos); ver != "" {
		return Check{Name: CheckOSVersion, Status: outcome.Pass, Message: ver}
	}
	return Check{}
}

func checkShell(ctx *Context) Check {
	if shell := ctx.GetenvFn("SHELL"); shell != "" {
		return Check{Name: CheckShell, Status: outcome.Pass, Message: shell}
	}
	return Check{}
}

func checkCI(ctx *Context) Check {
	if ci := detectCI(ctx.GetenvFn); ci != "" {
		return Check{Name: CheckCIEnv, Status: outcome.Pass, Message: ci}
	}
	return Check{}
}

func checkContainer(_ *Context) Check {
	if container := detectContainer(); container != "" {
		return Check{Name: CheckContainer, Status: outcome.Pass, Message: container}
	}
	return Check{}
}

func checkWorkspaceWritable(ctx *Context) Check {
	if err := IsDirectoryWritable(ctx.Cwd); err != nil {
		return Check{
			Name:    CheckWorkspaceWritable,
			Status:  outcome.Fail,
			Message: fmt.Sprintf("cannot write in %s: %v", ctx.Cwd, err),
			Fix:     "run in a writable directory or adjust permissions (chmod/chown)",
		}
	}
	return Check{
		Name:    CheckWorkspaceWritable,
		Status:  outcome.Pass,
		Message: fmt.Sprintf("directory is writable: %s", ctx.Cwd),
	}
}

func checkGit(ctx *Context) Check {
	return checkBinary(ctx, BinaryRequest{
		Binary:      "git",
		Name:        CheckGit,
		WarnMessage: "git not found; project workflows and bootstrap may be limited",
		Fix:         "install git (https://git-scm.com/downloads)",
	})
}

func checkAWS(ctx *Context) Check {
	// #nosec G101 -- contains tool names/docs URLs; no credentials are embedded.
	return checkBinary(ctx, BinaryRequest{
		Binary:      "aws",
		Name:        CheckAWSCLI,
		WarnMessage: "aws not found; cannot collect live cloud snapshots",
		Fix:         "install AWS CLI (https://aws.amazon.com/cli/)",
		PassMessage: "AWS CLI available",
	})
}

func checkJQ(ctx *Context) Check {
	return checkBinary(ctx, BinaryRequest{
		Binary:      "jq",
		Name:        CheckJQ,
		WarnMessage: "jq not found; JSON filtering examples will not function",
		Fix:         "install jq (https://jqlang.org/download/)",
	})
}

func checkGraphviz(ctx *Context) Check {
	return checkBinary(ctx, BinaryRequest{
		Binary:      "dot",
		Name:        CheckGraphviz,
		WarnMessage: "dot (graphviz) not found; cannot render DOT files to images",
		Fix:         "install graphviz (https://graphviz.org/download/)",
	})
}

func checkClipboard(ctx *Context) Check {
	switch ctx.Goos {
	case "darwin":
		return checkBinary(ctx, BinaryRequest{
			Binary:      "pbcopy",
			Name:        CheckClipboard,
			WarnMessage: "pbcopy not found",
			Fix:         "ensure pbcopy is available for clipboard integration",
		})
	case "linux":
		_, errX := ctx.LookPathFn("xclip")
		_, errW := ctx.LookPathFn("wl-copy")
		if errX != nil && errW != nil {
			return Check{
				Name:    CheckClipboard,
				Status:  outcome.Warn,
				Message: "neither xclip nor wl-copy found",
				Fix:     "install xclip or wl-clipboard for clipboard piping",
			}
		}
		return Check{Name: CheckClipboard, Status: outcome.Pass, Message: "clipboard tool available"}
	default:
		return Check{
			Name:    CheckClipboard,
			Status:  outcome.Warn,
			Message: fmt.Sprintf("clipboard check not supported on %s", ctx.Goos),
		}
	}
}

func checkOfflineProxyEnv(ctx *Context) Check {
	var found []string
	for _, env := range kernel.DefaultPolicy().ProxyEnvVars() {
		if val := strings.TrimSpace(ctx.GetenvFn(env)); val != "" {
			found = append(found, env)
		}
	}

	if len(found) > 0 {
		return Check{
			Name:    CheckProxyEnv,
			Status:  outcome.Warn,
			Message: fmt.Sprintf("active proxy variables detected: %s", strings.Join(found, ", ")),
			Fix:     "unset proxy variables for strict air-gap compliance, or use --require-offline",
		}
	}

	return Check{
		Name:    CheckProxyEnv,
		Status:  outcome.Pass,
		Message: "no proxy environment variables detected",
	}
}

// IsDirectoryWritable attempts to create and remove a temporary file to verify write access.
func IsDirectoryWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".stave-probe-*")
	if err != nil {
		return err
	}
	path := f.Name()
	_ = f.Close()
	// #nosec G703 -- path is generated by CreateTemp under the caller-selected directory.
	return os.Remove(path)
}
