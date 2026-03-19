//go:build stavedev

package securityaudit

import (
	"os"
	"path/filepath"
	"time"

	"github.com/sufield/stave/internal/adapters/govulncheck"
	appsa "github.com/sufield/stave/internal/app/securityaudit"
	"github.com/sufield/stave/internal/compliance"
	"github.com/sufield/stave/internal/doctor"
	"github.com/sufield/stave/internal/domain/kernel"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func buildRunnerDeps() appsa.RunnerDeps {
	return appsa.RunnerDeps{
		ReadFile: fsutil.ReadFileLimited,
		HashFile: fsutil.HashFile,
		HashBytes: func(data []byte) kernel.Digest {
			return platformcrypto.HashBytes(data)
		},
		GovulncheckRunner: govulncheck.Run,
		SignatureVerifier: nil,
		RunDiagnostics: func(cwd, binaryPath, staveVersion string) {
			_, _ = doctor.Run(&doctor.Context{
				Cwd:          cwd,
				BinaryPath:   binaryPath,
				StaveVersion: staveVersion,
			})
		},
		ResolveCrosswalk: func(raw []byte, frameworks, checkIDs []string, now time.Time) (appsa.CrosswalkResult, error) {
			resolved, resolveErr := compliance.ResolveControlCrosswalk(raw, frameworks, checkIDs, now)
			if resolveErr != nil {
				return appsa.CrosswalkResult{}, resolveErr
			}
			return appsa.CrosswalkResult{
				ByCheck:        resolved.ByCheck,
				MissingChecks:  resolved.MissingChecks,
				ResolutionJSON: resolved.ResolutionJSON,
			}, nil
		},
		StatFile:     os.Stat,
		Getenv:       os.Getenv,
		IsPrivileged: func() bool { return os.Geteuid() == 0 },
		WalkDir: func(root string, fn appsa.WalkFunc) error {
			return filepath.Walk(root, filepath.WalkFunc(fn))
		},
		Getwd: os.Getwd,
	}
}
