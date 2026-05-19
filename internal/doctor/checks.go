package doctor

import (
	"fmt"
	"os"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/outcome"
)

// Diagnostic Names
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

func checkVersionInfo(ctx *SystemEnvironment) Diagnostic {
	var sb strings.Builder
	fmt.Fprintf(&sb, "stave_version=%s go_version=%s os=%s arch=%s",
		ctx.BuildVersion, ctx.Runtime, ctx.OS, ctx.Arch)

	if ctx.BinaryPath != "" {
		fmt.Fprintf(&sb, " binary=%s", ctx.BinaryPath)
	}

	return Diagnostic{
		Name:    CheckVersionInfo,
		Status:  outcome.Pass,
		Message: sb.String(),
	}
}

func checkOSVersion(ctx *SystemEnvironment) Diagnostic {
	if ver := detectOSVersion(ctx.OS); ver != "" {
		return Diagnostic{Name: CheckOSVersion, Status: outcome.Pass, Message: ver}
	}
	return Diagnostic{}
}

func checkShell(ctx *SystemEnvironment) Diagnostic {
	if shell := ctx.EnvVarFn("SHELL"); shell != "" {
		return Diagnostic{Name: CheckShell, Status: outcome.Pass, Message: shell}
	}
	return Diagnostic{}
}

func checkCI(ctx *SystemEnvironment) Diagnostic {
	if ci := detectCI(ctx.EnvVarFn); ci != "" {
		return Diagnostic{Name: CheckCIEnv, Status: outcome.Pass, Message: ci}
	}
	return Diagnostic{}
}

func checkContainer(_ *SystemEnvironment) Diagnostic {
	if container := detectContainer(); container != "" {
		return Diagnostic{Name: CheckContainer, Status: outcome.Pass, Message: container}
	}
	return Diagnostic{}
}

func checkWorkspaceWritable(ctx *SystemEnvironment) Diagnostic {
	if err := IsDirectoryWritable(ctx.Cwd); err != nil {
		return Diagnostic{
			Name:        CheckWorkspaceWritable,
			Status:      outcome.Fail,
			Message:     fmt.Sprintf("cannot write in %s: %v", ctx.Cwd, err),
			Remediation: "run in a writable directory or adjust permissions (chmod/chown)",
		}
	}
	return Diagnostic{
		Name:    CheckWorkspaceWritable,
		Status:  outcome.Pass,
		Message: "directory is writable: " + ctx.Cwd,
	}
}

func checkGit(ctx *SystemEnvironment) Diagnostic {
	return checkBinary(ctx, BinaryRequest{
		Binary:      "git",
		Name:        CheckGit,
		WarnMessage: "git not found; project workflows and bootstrap may be limited",
		Remediation: "install git (https://git-scm.com/downloads)",
	})
}

func checkAWS(ctx *SystemEnvironment) Diagnostic {
	// #nosec G101 -- contains tool names/docs URLs; no credentials are embedded.
	return checkBinary(ctx, BinaryRequest{
		Binary:      "aws",
		Name:        CheckAWSCLI,
		WarnMessage: "aws not found; cannot collect live cloud snapshots",
		Remediation: "install AWS CLI (https://aws.amazon.com/cli/)",
		PassMessage: "AWS CLI available",
	})
}

func checkJQ(ctx *SystemEnvironment) Diagnostic {
	return checkBinary(ctx, BinaryRequest{
		Binary:      "jq",
		Name:        CheckJQ,
		WarnMessage: "jq not found; JSON filtering examples will not function",
		Remediation: "install jq (https://jqlang.org/download/)",
	})
}

func checkGraphviz(ctx *SystemEnvironment) Diagnostic {
	return checkBinary(ctx, BinaryRequest{
		Binary:      "dot",
		Name:        CheckGraphviz,
		WarnMessage: "dot (graphviz) not found; stave graph coverage DOT output requires graphviz for rendering",
		Remediation: "install graphviz (https://graphviz.org/download/) or use stave graph export --format json with docs/integrations/ adapters",
	})
}

func checkClipboard(ctx *SystemEnvironment) Diagnostic {
	switch ctx.OS {
	case "darwin":
		return checkBinary(ctx, BinaryRequest{
			Binary:      "pbcopy",
			Name:        CheckClipboard,
			WarnMessage: "pbcopy not found",
			Remediation: "ensure pbcopy is available for clipboard integration",
		})
	case "linux":
		_, errX := ctx.PathLookupFn("xclip")
		_, errW := ctx.PathLookupFn("wl-copy")
		if errX != nil && errW != nil {
			return Diagnostic{
				Name:        CheckClipboard,
				Status:      outcome.Warn,
				Message:     "neither xclip nor wl-copy found",
				Remediation: "install xclip or wl-clipboard for clipboard piping",
			}
		}
		return Diagnostic{Name: CheckClipboard, Status: outcome.Pass, Message: "clipboard tool available"}
	default:
		return Diagnostic{
			Name:    CheckClipboard,
			Status:  outcome.Warn,
			Message: "clipboard check not supported on " + ctx.OS,
		}
	}
}

func checkOfflineProxyEnv(ctx *SystemEnvironment) Diagnostic {
	var found []string
	for _, env := range kernel.DefaultPolicy().ProxyEnvVars() {
		if val := strings.TrimSpace(ctx.EnvVarFn(env)); val != "" {
			found = append(found, env)
		}
	}

	if len(found) > 0 {
		return Diagnostic{
			Name:        CheckProxyEnv,
			Status:      outcome.Warn,
			Message:     "active proxy variables detected: " + strings.Join(found, ", "),
			Remediation: "unset proxy variables for strict air-gap compliance, or use --require-offline",
		}
	}

	return Diagnostic{
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
	// Best-effort close before removal; writability was already proven.
	_ = f.Close()
	_ = os.Remove(path) // Cleanup: if temp file is already gone, writability check passed.
	return nil
}
