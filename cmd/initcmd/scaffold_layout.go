package initcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	projectapp "github.com/sufield/stave/internal/app/project"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func scaffoldProject(baseDir string, overwrite bool, opts scaffoldOptions, allowSymlink bool) (projectapp.ScaffoldResult, error) {
	dirs, files, err := scaffoldLayout(opts)
	if err != nil {
		return projectapp.ScaffoldResult{}, err
	}

	for _, rel := range dirs {
		path := filepath.Join(baseDir, rel)
		if err := fsutil.SafeMkdirAll(path, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: allowSymlink}); err != nil {
			return projectapp.ScaffoldResult{}, fmt.Errorf("create directory %s: %w", path, err)
		}
	}

	var created, skipped []string
	for rel, content := range files {
		full := filepath.Join(baseDir, rel)
		wrote, err := writeScaffoldFile(full, []byte(content), overwrite, allowSymlink)
		if err != nil {
			return projectapp.ScaffoldResult{}, fmt.Errorf("write %s: %w", full, err)
		}
		if wrote {
			created = append(created, rel)
		} else {
			skipped = append(skipped, rel)
		}
	}

	return projectapp.ScaffoldResult{Dirs: dirs, Created: created, Skipped: skipped}, nil
}

func scaffoldPlan(baseDir string, overwrite bool, opts scaffoldOptions) (projectapp.ScaffoldResult, error) {
	dirs, files, err := scaffoldLayout(opts)
	if err != nil {
		return projectapp.ScaffoldResult{}, err
	}
	var created, skipped []string
	for rel := range files {
		full := filepath.Join(baseDir, rel)
		if overwrite {
			created = append(created, rel)
			continue
		}
		if _, statErr := os.Stat(full); statErr == nil {
			skipped = append(skipped, rel)
		} else if os.IsNotExist(statErr) {
			created = append(created, rel)
		} else {
			return projectapp.ScaffoldResult{}, fmt.Errorf("check %s: %w", full, statErr)
		}
	}
	sort.Strings(created)
	sort.Strings(skipped)
	return projectapp.ScaffoldResult{Dirs: dirs, Created: created, Skipped: skipped}, nil
}

func scaffoldLayout(opts scaffoldOptions) ([]string, map[string]string, error) {
	dirs := scaffoldDirectories(opts)
	files, err := scaffoldBaseFiles(opts)
	if err != nil {
		return nil, nil, err
	}
	addProfileScaffoldFiles(files, opts.Profile)
	addWorkflowScaffoldFiles(files, opts)
	return dirs, files, nil
}

func scaffoldDirectories(opts scaffoldOptions) []string {
	dirs := []string{
		"controls",
		"snapshots/raw",
		"observations",
		"output",
	}
	if opts.Profile == profileAWSS3 {
		dirs = append(dirs, "snapshots/raw/aws-s3")
	}
	if opts.WithGitHubActions {
		dirs = append(dirs, ".github/workflows")
	}
	return dirs
}

func scaffoldBaseFiles(opts scaffoldOptions) (map[string]string, error) {
	sc := NewScaffolder(opts)
	readme, err := sc.Readme()
	if err != nil {
		return nil, fmt.Errorf("render README template: %w", err)
	}
	userCfg, err := sc.UserConfig()
	if err != nil {
		return nil, fmt.Errorf("render cli.yaml template: %w", err)
	}
	lockfile, err := sc.Lockfile()
	if err != nil {
		return nil, fmt.Errorf("render stave.lock template: %w", err)
	}
	return map[string]string{
		".gitignore": gitignoreContent,
		"README.md":  readme,
		"cli.yaml":   userCfg,
		"stave.lock": lockfile,
		projectConfigFile: normalizeTemplate(
			"# Stave project manifest (user-editable configuration).\n" +
				"# This file controls default evaluation and snapshot workflow behavior for this project.\n" +
				"max_unsafe: " + defaultMaxUnsafeDuration + "\n" +
				"snapshot_retention: " + defaultSnapshotRetention + "\n" +
				"default_retention_tier: " + defaultRetentionTier + "\n" +
				"snapshot_retention_tiers:\n" +
				"  critical:\n" +
				"    older_than: 30d\n" +
				"    keep_min: 2\n" +
				"  non_critical:\n" +
				"    older_than: 14d\n" +
				"    keep_min: 2\n" +
				"ci_failure_policy: " + defaultCIFailurePolicy + "\n" +
				"capture_cadence: " + opts.CaptureCadence + "\n" +
				"snapshot_filename_template: " + snapshotFilenameTemplate(opts.CaptureCadence) + "\n" +
				"enabled_control_packs:\n" +
				"  - s3",
		),
		"observations/2026-01-11T000000Z.json":   normalizeTemplate(templateObservation),
		"observations/2026-01-18T000000Z.json":   strings.ReplaceAll(normalizeTemplate(templateObservation), "2026-01-11T00:00:00Z", "2026-01-18T00:00:00Z"),
		"snapshots/raw/observation.example.json": normalizeTemplate(templateObservationSample),
		"controls/control.example.yaml":          normalizeTemplate(templateControlSample),
		"stave.example.yaml":                     normalizeTemplate(templateStaveConfigSample),
		"output/.gitkeep":                        "",
	}, nil
}

func addProfileScaffoldFiles(files map[string]string, profile string) {
	if profile != profileAWSS3 {
		return
	}
	files["snapshots/raw/aws-s3/README.md"] = normalizeTemplate(`# AWS S3 Snapshot Input (aws-s3)

Expected input for:
stave ingest --profile aws-s3 --input ./snapshots/raw/aws-s3 --out ./observations

Include files such as:
- list-buckets.json
- get-bucket-tagging/<bucket>.json
- get-bucket-policy/<bucket>.json
- get-bucket-acl/<bucket>.json
- get-public-access-block/<bucket>.json
`)
}

func addWorkflowScaffoldFiles(files map[string]string, opts scaffoldOptions) {
	if !opts.WithGitHubActions {
		return
	}
	files[".github/workflows/stave.yml"] = normalizeTemplate(scaffoldGitHubActions(opts))
}

func writeScaffoldFile(path string, data []byte, overwrite, allowSymlink bool) (bool, error) {
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	opts := fsutil.ConfigWriteOpts()
	opts.Overwrite = overwrite
	opts.AllowSymlink = allowSymlink
	if err := fsutil.SafeWriteFile(path, data, opts); err != nil {
		return false, err
	}
	return true, nil
}
