package initcmd

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	"github.com/sufield/stave/internal/env"
)

//go:embed templates/github_actions.yml.tmpl
var githubActionsTemplateSrc string

// githubActionsData holds variables for the CI workflow template.
type githubActionsData struct {
	MaxUnsafeVar    string
	ScheduleBlock   string
	ShellDateFormat string
	ProjectConfig   string
	DefaultPolicy   string
}

func scaffoldGitHubActions(opts scaffoldOptions) (string, error) {
	data := githubActionsData{
		MaxUnsafeVar:    env.MaxUnsafe.Name,
		ScheduleBlock:   scheduleBlock(opts.CaptureCadence),
		ShellDateFormat: shellDateFormat(opts.CaptureCadence),
		ProjectConfig:   projectConfigFile,
		DefaultPolicy:   defaultCIFailurePolicy,
	}

	tmpl, err := template.New("github-actions").Parse(githubActionsTemplateSrc)
	if err != nil {
		return "", fmt.Errorf("parse github actions template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute github actions template: %w", err)
	}

	return buf.String(), nil
}

func scheduleBlock(cadence string) string {
	cron := "0 2 * * *"
	if cadence == cadenceHourly {
		cron = "0 * * * *"
	}
	return fmt.Sprintf("  schedule:\n    - cron: %q", cron)
}

func shellDateFormat(cadence string) string {
	if cadence == cadenceHourly {
		return "%Y-%m-%dT%H:00:00Z"
	}
	return "%Y-%m-%dT00:00:00Z"
}

func snapshotFilenameTemplate(cadence string) string {
	if cadence == cadenceHourly {
		return "YYYY-MM-DDTHH0000Z.json"
	}
	return "YYYY-MM-DDT000000Z.json"
}

func snapshotFilenameExample(cadence string) string {
	if cadence == cadenceHourly {
		return "2026-01-18T140000Z.json"
	}
	return "2026-01-18T000000Z.json"
}
