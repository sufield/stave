package initcmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/gitinfo"
	projectapp "github.com/sufield/stave/internal/app/project"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

var initDir string
var initProfile string
var initDryRun bool
var initWithGitHubActions bool
var initCaptureCadence string

const (
	profileAWSS3 = "aws-s3"

	cadenceDaily  = "daily"
	cadenceHourly = "hourly"
)

type scaffoldOptions struct {
	Profile           string
	WithGitHubActions bool
	CaptureCadence    string
}

func runInit(_ *cobra.Command, _ []string) error {
	result, err := projectapp.RunInit(projectapp.InitRequest{
		Dir:               initDir,
		Profile:           initProfile,
		DryRun:            initDryRun,
		WithGitHubActions: initWithGitHubActions,
		CaptureCadence:    initCaptureCadence,
		Force:             globalForce,
	}, projectapp.InitDeps{
		ValidateInputs: validateScaffoldInputs,
		Plan: func(baseDir string, overwrite bool, opts projectapp.ScaffoldOptions) (projectapp.ScaffoldResult, error) {
			return scaffoldPlan(baseDir, overwrite, scaffoldOptions{
				Profile:           opts.Profile,
				WithGitHubActions: opts.WithGitHubActions,
				CaptureCadence:    opts.CaptureCadence,
			})
		},
		Scaffold: func(baseDir string, overwrite bool, opts projectapp.ScaffoldOptions) (projectapp.ScaffoldResult, error) {
			return scaffoldProject(baseDir, overwrite, scaffoldOptions{
				Profile:           opts.Profile,
				WithGitHubActions: opts.WithGitHubActions,
				CaptureCadence:    opts.CaptureCadence,
			})
		},
		AfterScaffold: func(baseDir string) error {
			return maybePromptAndInitGitRepo(baseDir, os.Stdin, os.Stdout)
		},
	})
	if err != nil {
		return err
	}

	printScaffoldSummary(scaffoldSummaryRequest{
		BaseDir: result.BaseDir,
		Dirs:    result.Dirs,
		Created: result.Created,
		Skipped: result.Skipped,
		DryRun:  result.DryRun,
	})
	return nil
}

func validateScaffoldInputs(rawDir, profile, cadence string) (string, error) {
	dir := fsutil.CleanUserPath(rawDir)
	if dir == "" {
		return "", &ui.InputError{Err: fmt.Errorf("--dir cannot be empty")}
	}
	if profile != "" && profile != profileAWSS3 {
		return "", &ui.InputError{Err: fmt.Errorf("unsupported --profile %q (supported: aws-s3)", profile)}
	}
	if cadence != cadenceDaily && cadence != cadenceHourly {
		return "", &ui.InputError{Err: fmt.Errorf("unsupported --capture-cadence %q (supported: daily, hourly)", cadence)}
	}
	return dir, nil
}

func maybePromptAndInitGitRepo(baseDir string, in io.Reader, out io.Writer) error {
	gitDir := filepath.Join(baseDir, ".git")
	if fi, err := os.Stat(gitDir); err == nil && fi.IsDir() {
		return nil
	}

	interactive, err := isInteractiveTTY()
	if err != nil || !interactive {
		return nil
	}
	shouldInit, err := promptInitializeGit(baseDir, in, out)
	if err != nil {
		return err
	}
	if !shouldInit {
		return nil
	}
	if err := gitinfo.InitRepo(baseDir); err != nil {
		return fmt.Errorf("initialize git repository in %s: %w", baseDir, err)
	}
	if _, err := fmt.Fprintf(out, "Initialized git repository at %s\n", baseDir); err != nil {
		return err
	}
	return nil
}

func isInteractiveTTY() (bool, error) {
	inInfo, err := os.Stdin.Stat()
	if err != nil {
		return false, err
	}
	outInfo, err := os.Stdout.Stat()
	if err != nil {
		return false, err
	}
	return (inInfo.Mode()&os.ModeCharDevice) != 0 && (outInfo.Mode()&os.ModeCharDevice) != 0, nil
}

func promptInitializeGit(baseDir string, in io.Reader, out io.Writer) (bool, error) {
	if _, err := fmt.Fprintf(out, "No git repository found in %s. Initialize now? [Y/n]: ", baseDir); err != nil {
		return false, err
	}
	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "" || answer == "y" || answer == "yes", nil
}

func scaffoldProject(baseDir string, overwrite bool, opts scaffoldOptions) (projectapp.ScaffoldResult, error) {
	dirs, files := scaffoldLayout(opts)

	for _, rel := range dirs {
		path := filepath.Join(baseDir, rel)
		if err := fsutil.SafeMkdirAll(path, fsutil.WriteOptions{Perm: 0o700, AllowSymlink: globalAllowSymlinkOut}); err != nil {
			return projectapp.ScaffoldResult{}, fmt.Errorf("create directory %s: %w", path, err)
		}
	}

	var created, skipped []string
	for rel, content := range files {
		full := filepath.Join(baseDir, rel)
		wrote, err := writeScaffoldFile(full, []byte(content), overwrite)
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
	dirs, files := scaffoldLayout(opts)
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

func scaffoldLayout(opts scaffoldOptions) (dirs []string, files map[string]string) {
	dirs = scaffoldDirectories(opts)
	files = scaffoldBaseFiles(opts)
	addProfileScaffoldFiles(files, opts.Profile)
	addWorkflowScaffoldFiles(files, opts)
	return dirs, files
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

func scaffoldBaseFiles(opts scaffoldOptions) map[string]string {
	return map[string]string{
		".gitignore": scaffoldGitignore(),
		"README.md":  scaffoldReadme(opts),
		"cli.yaml":   scaffoldUserConfigExample(),
		"stave.lock": scaffoldLockfile(),
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
		"observations/2026-01-11T00:00:00Z.json": normalizeTemplate(templateObservation),
		"observations/2026-01-18T00:00:00Z.json": strings.ReplaceAll(normalizeTemplate(templateObservation), "2026-01-11T00:00:00Z", "2026-01-18T00:00:00Z"),
		"snapshots/raw/observation.sample.json":  normalizeTemplate(templateObservationSample),
		"controls/control.sample.yaml":           normalizeTemplate(templateControlSample),
		"stave.sample.yaml":                      normalizeTemplate(templateStaveConfigSample),
		"output/.gitkeep":                        "",
	}
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

type scaffoldSummaryRequest struct {
	BaseDir string
	Dirs    []string
	Created []string
	Skipped []string
	DryRun  bool
}

func printScaffoldSummary(req scaffoldSummaryRequest) {
	absBaseDir, err := filepath.Abs(req.BaseDir)
	if err != nil {
		absBaseDir = req.BaseDir
	}
	if req.DryRun {
		fmt.Printf("Dry run: scaffold would be created in %s\n", absBaseDir)
	} else {
		fmt.Printf("Initialized empty Stave project in %s\n", absBaseDir)
	}
	fmt.Println("")
	if req.DryRun {
		fmt.Println("Planned structure:")
	} else {
		fmt.Println("Created structure:")
	}
	printCreatedTree(req.Dirs, req.Created)
	if !req.DryRun {
		fmt.Println("")
		fmt.Printf("Project manifest: %s\n", projectConfigFile)
		fmt.Println("Template reference: stave.sample.yaml")
	}
	if len(req.Skipped) > 0 {
		fmt.Println("")
		fmt.Println("Skipped existing files (use --force to overwrite):")
		for _, rel := range req.Skipped {
			fmt.Printf("  - %s\n", rel)
		}
	}
	if req.DryRun {
		fmt.Println("")
		fmt.Println("No files were written (dry-run).")
	}

	rt := ui.NewRuntime(os.Stdout, os.Stderr)
	rt.Quiet = globalQuiet
	rt.PrintNextSteps(
		"Run `stave doctor` to verify your local environment.",
		"Run `stave apply --observations ./observations` to evaluate with built-in S3 checks.",
		"Run `stave snapshot upcoming --observations ./observations` to see the next snapshot schedule.",
		"Read the generated README.md for the full recommended workflow.",
	)
}

type summaryTreeNode struct {
	children map[string]*summaryTreeNode
	isDir    bool
	isFile   bool
}

func printCreatedTree(dirs, files []string) {
	root := &summaryTreeNode{children: make(map[string]*summaryTreeNode)}
	for _, dir := range dirs {
		addTreePath(root, dir, true)
	}
	for _, file := range files {
		addTreePath(root, file, false)
	}
	printTreeChildren(root, "  ")
}

func addTreePath(root *summaryTreeNode, rel string, isDir bool) {
	clean := strings.Trim(filepath.ToSlash(rel), "/")
	if clean == "" {
		return
	}
	parts := strings.Split(clean, "/")
	node := root
	for i, part := range parts {
		child, ok := node.children[part]
		if !ok {
			child = &summaryTreeNode{children: make(map[string]*summaryTreeNode)}
			node.children[part] = child
		}
		last := i == len(parts)-1
		if last {
			if isDir {
				child.isDir = true
			} else {
				child.isFile = true
			}
		} else {
			child.isDir = true
		}
		node = child
	}
}

func printTreeChildren(node *summaryTreeNode, prefix string) {
	if len(node.children) == 0 {
		return
	}
	names := make([]string, 0, len(node.children))
	for name := range node.children {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		child := node.children[name]
		last := i == len(names)-1
		connector := "|- "
		nextPrefix := prefix + "|  "
		if last {
			connector = "`- "
			nextPrefix = prefix + "   "
		}
		label := name
		if child.isDir || len(child.children) > 0 {
			label += "/"
		}
		fmt.Printf("%s%s%s\n", prefix, connector, label)
		printTreeChildren(child, nextPrefix)
	}
}

func writeScaffoldFile(path string, data []byte, overwrite bool) (bool, error) {
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		}
	}
	opts := fsutil.ConfigWriteOpts()
	opts.Overwrite = overwrite
	opts.AllowSymlink = globalAllowSymlinkOut
	if err := fsutil.SafeWriteFile(path, data, opts); err != nil {
		return false, err
	}
	return true, nil
}
