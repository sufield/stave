package initcmd

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sufield/stave/internal/cli/ui"
)

type scaffoldSummaryRequest struct {
	BaseDir string
	Dirs    []string
	Created []string
	Skipped []string
	DryRun  bool
}

func printScaffoldSummary(w io.Writer, stderr io.Writer, req scaffoldSummaryRequest, quiet bool) {
	if quiet {
		return
	}
	absBaseDir, err := filepath.Abs(req.BaseDir)
	if err != nil {
		absBaseDir = req.BaseDir
	}
	if req.DryRun {
		fmt.Fprintf(w, "Dry run: scaffold would be created in %s\n", absBaseDir)
	} else {
		fmt.Fprintf(w, "Initialized empty Stave project in %s\n", absBaseDir)
	}
	fmt.Fprintln(w)
	if req.DryRun {
		fmt.Fprintln(w, "Planned structure:")
	} else {
		fmt.Fprintln(w, "Created structure:")
	}
	printCreatedTree(w, req.Dirs, req.Created)
	if !req.DryRun {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Project manifest: %s\n", projectConfigFile)
		fmt.Fprintln(w, "Template reference: stave.example.yaml")
	}
	if len(req.Skipped) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Skipped existing files (use --force to overwrite):")
		for _, rel := range req.Skipped {
			fmt.Fprintf(w, "  - %s\n", rel)
		}
	}
	if req.DryRun {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "No files were written (dry-run).")
	}

	rt := ui.NewRuntime(w, stderr)
	rt.Quiet = quiet
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

func printCreatedTree(w io.Writer, dirs, files []string) {
	root := &summaryTreeNode{children: make(map[string]*summaryTreeNode)}
	for _, dir := range dirs {
		addTreePath(root, dir, true)
	}
	for _, file := range files {
		addTreePath(root, file, false)
	}
	printTreeChildren(w, root, "  ")
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

func printTreeChildren(w io.Writer, node *summaryTreeNode, prefix string) {
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
		fmt.Fprintf(w, "%s%s%s\n", prefix, connector, label)
		printTreeChildren(w, child, nextPrefix)
	}
}
