package config

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	cliconfig "github.com/sufield/stave/internal/cli/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

func (cc *configCommand) newProjectConfigEditor(cmd *cobra.Command) *cliconfig.Editor[projconfig.ProjectConfig] {
	var stderr io.Writer = os.Stderr
	if cc.rt != nil && cc.rt.Stderr != nil {
		stderr = cc.rt.Stderr
	}

	store := projectConfigStore{allowSymlink: cmdutil.AllowSymlinkOutEnabled(cmd), svc: cc.svc}
	return &cliconfig.Editor[projconfig.ProjectConfig]{
		SetStore:    store,
		DeleteStore: store,
		Stderr:      stderr,
		Force:       cmdutil.ForceEnabled(cmd),
		IsTTY:       cc.isTTY,
		Confirm:     ui.Confirm,
	}
}

func (cc *configCommand) isTTY() bool {
	if cc.rt != nil && cc.rt.IsTTY != nil {
		return *cc.rt.IsTTY
	}
	return ui.IsStderrTTY()
}

func (cc *configCommand) stderrWriter() io.Writer {
	if cc.rt != nil && cc.rt.Stderr != nil {
		return cc.rt.Stderr
	}
	return os.Stderr
}

func (cc *configCommand) writeConfigMutationResult(
	cmd *cobra.Command,
	result configKeyValueOutput,
	textLine string,
	showHint bool,
) error {
	format, err := compose.ResolveFormatValue(cmd, cc.opts.Format)
	if err != nil {
		return err
	}
	if format.IsJSON() {
		return jsonutil.WriteIndented(cmd.OutOrStdout(), result)
	}

	if _, err := fmt.Fprintln(cmd.OutOrStdout(), textLine); err != nil {
		return err
	}
	if showHint && !cmdutil.QuietEnabled(cmd) {
		ui.WriteHint(cc.stderrWriter(), "stave config show")
	}
	return nil
}

func (cc *configCommand) runConfigGet(cmd *cobra.Command, key string) error {
	key = strings.TrimSpace(key)
	cfg, cfgPath, _ := projconfig.FindProjectConfigWithPath("")
	eval := projconfig.NewEvaluator(cfg, cfgPath, nil, "")
	retTier := eval.RetentionTier()

	kv, err := resolveServiceConfigKeyValue(cc.svc, key, cfg, cfgPath, retTier.Value)
	if err != nil {
		return err
	}
	out := configKeyValueOutput{Key: kv.Key, Value: kv.Value, Source: kv.Source}

	format, err := compose.ResolveFormatValue(cmd, cc.opts.Format)
	if err != nil {
		return err
	}
	if format.IsJSON() {
		return jsonutil.WriteIndented(cmd.OutOrStdout(), out)
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\n", out.Value)
	return err
}

func (cc *configCommand) runConfigSet(cmd *cobra.Command, key, value string) error {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}

	editor := cc.newProjectConfigEditor(cmd)
	result, err := editor.Set(key, value)
	if err != nil {
		return err
	}
	if !result.Applied {
		return nil
	}

	return cc.writeConfigMutationResult(cmd, configKeyValueOutput{
		Key:   result.Key,
		Value: result.Value,
		Path:  result.Path,
	}, fmt.Sprintf("Set %s=%s in %s", result.Key, result.Value, result.Path), true)
}

func (cc *configCommand) runConfigDelete(cmd *cobra.Command, key string) error {
	key = strings.TrimSpace(key)

	editor := cc.newProjectConfigEditor(cmd)
	result, err := editor.Delete(key)
	if err != nil {
		return err
	}
	if !result.Applied {
		return nil
	}

	return cc.writeConfigMutationResult(cmd, configKeyValueOutput{
		Key:  result.Key,
		Path: result.Path,
	}, fmt.Sprintf("Deleted %s from %s (reverted to default)", result.Key, result.Path), false)
}

func (cc *configCommand) runConfigShow(cmd *cobra.Command) error {
	out := buildConfigShowOutput()
	format, err := compose.ResolveFormatValue(cmd, cc.opts.Format)
	if err != nil {
		return err
	}
	if format.IsJSON() {
		return writeConfigShowJSON(cmd, out)
	}
	return writeConfigShowText(cmd, out)
}
