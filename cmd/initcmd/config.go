package initcmd

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	"github.com/sufield/stave/internal/env"
)

//go:embed templates/gitignore.txt
var gitignoreContent string

//go:embed templates/README.md.tmpl
var readmeTemplateSrc string

//go:embed templates/cli.yaml.tmpl
var userConfigTemplateSrc string

//go:embed templates/stave.lock.tmpl
var lockfileTemplateSrc string

// ScaffoldData holds all variables needed to render project templates.
type ScaffoldData struct {
	Version           string
	CaptureCadence    string
	SnapshotTemplate  string
	SnapshotExample   string
	ObsConvertCmd     string
	ProjectConfigFile string
	UserConfigEnv     string
	MaxUnsafeDuration string
	Retention         string
	RetentionTier     string
	CIFailurePolicy   string
}

// Scaffolder renders project scaffold templates using a populated ScaffoldData model.
type Scaffolder struct {
	Data ScaffoldData
}

// NewScaffolder creates a Scaffolder from scaffold options.
func NewScaffolder(opts scaffoldOptions) *Scaffolder {
	obsCmd := "Place observation JSON files in ./observations (see 'stave explain' for required fields)"
	if opts.Profile == profileAWSS3 {
		obsCmd = "Create observation JSON files in ./observations from your AWS S3 environment data"
	}
	return &Scaffolder{
		Data: ScaffoldData{
			Version:           Version(),
			CaptureCadence:    opts.CaptureCadence,
			SnapshotTemplate:  snapshotFilenameTemplate(opts.CaptureCadence),
			SnapshotExample:   snapshotFilenameExample(opts.CaptureCadence),
			ObsConvertCmd:     obsCmd,
			ProjectConfigFile: projectConfigFile,
			UserConfigEnv:     env.UserConfig.Name,
			MaxUnsafeDuration: defaultMaxUnsafeDuration,
			Retention:         defaultSnapshotRetention,
			RetentionTier:     defaultRetentionTier,
			CIFailurePolicy:   defaultCIFailurePolicy,
		},
	}
}

// Readme renders the project README from the embedded template.
func (s *Scaffolder) Readme() (string, error) {
	return renderTemplate(readmeTemplateSrc, "readme", s.Data)
}

// UserConfig renders the example CLI config from the embedded template.
func (s *Scaffolder) UserConfig() (string, error) {
	return renderTemplate(userConfigTemplateSrc, "userconfig", s.Data)
}

// Lockfile renders the stave.lock from the embedded template.
func (s *Scaffolder) Lockfile() (string, error) {
	return renderTemplate(lockfileTemplateSrc, "lockfile", s.Data)
}

func renderTemplate(src, name string, data ScaffoldData) (string, error) {
	tmpl, err := template.New(name).Parse(src)
	if err != nil {
		return "", fmt.Errorf("parse %s template: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute %s template: %w", name, err)
	}
	return buf.String(), nil
}
