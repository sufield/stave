package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
)

// resolvePathInference resolves controls and observations directories using
// PrepareEvaluationContext. Dir validation is deferred to validateDirsWithConfig
// because it depends on the loaded project config (pack awareness).
func resolvePathInference(controlsDir, observationsDir string, controlsSet, obsChanged bool) (compose.EvalContext, error) {
	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:                controlsDir,
		ObservationsDir:            observationsDir,
		ControlsChanged:            controlsSet,
		ObsChanged:                 obsChanged || observationsDir == "-",
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
		SkipMaxUnsafe:              true,
		SkipClock:                  true,
		SkipFormat:                 true,
	})
	if err != nil {
		return compose.EvalContext{}, fmt.Errorf("resolve path inference: %w", err)
	}
	return ec, nil
}

// --- Standard mode resolution ---

// Resolve transforms raw CLI options into a RunConfig.
// Pure function — reads from o and cs, writes nothing.
func Resolve(o *Options, cs cobraState) (RunConfig, error) {
	if o.Profile != "" {
		return resolveProfileMode(o, cs)
	}

	ec, err := resolvePathInference(o.ControlsDir, o.ObservationsDir, o.controlsSet, o.obsSet)
	if err != nil {
		return RunConfig{}, err
	}
	controlsDir := ec.ControlsDir
	observationsDir := ec.ObservationsDir

	// Integrity flag validation, restored from the removed appeval.Validate
	// path: these are CLI flag checks (public-key needs a manifest, the
	// manifest is incompatible with stdin, both paths must exist), so they
	// belong command-side, validated before the evaluation progress span.
	if err = validateIntegrityFlags(o.IntegrityManifest, o.IntegrityPublicKey, observationsDir); err != nil {
		return RunConfig{}, err
	}

	// --max-unsafe and --eval-time are validated + parsed in the facade
	// (stave.EvaluateStandard); the command passes the raw flag strings.

	// Load project config once — shared by validateDirs and the facade.
	projCfg, cfgPath, err := projconfig.FindProjectConfigWithPath("")
	if err != nil {
		return RunConfig{}, fmt.Errorf("resolve run config: %w", ui.WithHint(
			fmt.Errorf("load project config: %w", err),
			ui.ErrHintProjectConfig,
		))
	}

	// Built-in catalog fallback: when --controls was not passed AND no
	// controls/ directory exists, evaluate against the embedded catalog
	// instead of erroring. An explicit --controls flag (even to a missing
	// path) and enabled_control_packs both take precedence and are
	// validated normally.
	hasPacks := !o.controlsSet && projCfg != nil && len(projCfg.EnabledControlPacks) > 0
	// Fall back to the built-in catalog only when the controls path is
	// genuinely absent. A path that exists but is a file (or otherwise not
	// a directory) is a misconfiguration and must still surface the normal
	// "is not a directory" error via validateDirsWithConfig.
	useBuiltin := !o.controlsSet && !hasPacks && !pathExists(controlsDir)

	if !useBuiltin {
		if err := validateDirsWithConfig(controlsDir, observationsDir, hasPacks); err != nil {
			return RunConfig{}, err
		}
	} else if observationsDir != "-" {
		// Still validate observations when controls fall back to builtin.
		if err := dircheck.ValidateFlagDir("--observations", observationsDir, "observations", ui.ErrHintObservationsNotAccessible, nil); err != nil {
			return RunConfig{}, fmt.Errorf("validate observations directory: %w", err)
		}
	}

	return RunConfig{
		Mode:              runModeStandard,
		ControlsDir:       controlsDir,
		ObservationsDir:   observationsDir,
		projectConfigPath: cfgPath,
		UseBuiltinCatalog: useBuiltin,
	}, nil
}

// pathExists reports whether path exists (file or directory). Used to
// decide the built-in-catalog fallback: only when the controls path is
// entirely absent. An existing-but-non-directory path is left to the
// normal directory validator so its misconfiguration still errors.
func pathExists(path string) bool {
	if path == "" || path == "-" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// projectContext holds resolved project-level paths and identity.
type projectContext struct {
	Root           string
	ContextName    string
	UserConfigPath string
}

// resolveProjectContext discovers the project root, active context, and
// user config path. Pure I/O — no dependency on Options.
func resolveProjectContext() (projectContext, error) {
	resolver, err := projctx.NewResolver()
	if err != nil {
		return projectContext{}, fmt.Errorf("resolve project context: %w", ui.WithHint(
			fmt.Errorf("resolve project context: %w", err),
			ui.ErrHintProjectContext,
		))
	}
	root := resolver.ProjectRoot()

	_, userPath, _, uErr := projconfig.FindUserConfigWithPath()
	if uErr != nil {
		return projectContext{}, fmt.Errorf("load user config: %w", ui.WithHint(
			fmt.Errorf("load user config: %w", uErr),
			ui.ErrHintProjectConfig,
		))
	}

	selectedContext := ""
	if sc, scErr := resolver.ResolveSelected(); scErr == nil && sc.IsUsable() {
		selectedContext = sc.Name
	}

	return projectContext{
		Root:           root,
		ContextName:    resolveContextName(root, selectedContext),
		UserConfigPath: userPath,
	}, nil
}

// resolveContextName returns the project context label: the selected context
// name when set, else the project-root basename, else "default". Inlined from
// internal/app/apply.ResolveContextName (pure stdlib) so the command holds no
// internal/app import.
func resolveContextName(projectRoot, selectedContext string) string {
	if s := strings.TrimSpace(selectedContext); s != "" {
		return s
	}
	base := filepath.Base(projectRoot)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "default"
	}
	return base
}

// validateIntegrityFlags reproduces the pre-facade integrity checks that lived
// in appeval.Options.Validate (removed with parseDomainOptions): the public key
// requires a manifest, the manifest is incompatible with stdin observations,
// and both paths, when set, must reference existing files. These are CLI flag
// validations — they stay command-side and surface as input errors (exit 2),
// matching the original messages byte-for-byte.
func validateIntegrityFlags(manifest, publicKey, observationsDir string) error {
	manifest = strings.TrimSpace(manifest)
	publicKey = strings.TrimSpace(publicKey)

	if publicKey != "" && manifest == "" {
		return &ui.UserError{Err: errors.New("integrity-public-key requires integrity-manifest")}
	}
	if observationsDir == "-" && manifest != "" {
		return &ui.UserError{Err: errors.New("integrity-manifest cannot be used with observations - (stdin mode)")}
	}
	if err := validateIntegrityFilePath(manifest, "integrity-manifest"); err != nil {
		return &ui.UserError{Err: err}
	}
	if err := validateIntegrityFilePath(publicKey, "integrity-public-key"); err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}

// validateIntegrityFilePath mirrors appeval.validateFilePath: a non-empty flag
// value must reference an existing regular file, distinguishing not-found,
// permission, and is-a-directory cases.
func validateIntegrityFilePath(path, flag string) error {
	if path == "" {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s not found at path %q", flag, path)
		}
		if os.IsPermission(err) {
			return fmt.Errorf("%s not readable at path %q (check file permissions)", flag, path)
		}
		return fmt.Errorf("cannot access %s at path %q: %w", flag, path, err)
	}
	if fi.IsDir() {
		return fmt.Errorf("%s must be a file, got directory %q", flag, path)
	}
	return nil
}

// validateDirsWithConfig ensures directories exist unless enabled control
// packs (hasPacks) supply controls, or observations come from stdin.
func validateDirsWithConfig(controlsDir, observationsDir string, hasPacks bool) error {
	if !hasPacks {
		if err := dircheck.ValidateFlagDir("--controls", controlsDir, "controls", ui.ErrHintControlsNotAccessible, nil); err != nil {
			return fmt.Errorf("validate controls directory: %w", err)
		}
	}

	if observationsDir != "-" {
		if err := dircheck.ValidateFlagDir("--observations", observationsDir, "observations", ui.ErrHintObservationsNotAccessible, nil); err != nil {
			return fmt.Errorf("validate observations directory: %w", err)
		}
	}

	return nil
}
