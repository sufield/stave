// validate-embed verifies that every shipping control on disk appears
// in the compiled binary, and vice versa. Catches the b9c722e bug
// class: directories present on disk but absent from the go:embed
// directive, making controls invisible to the binary.
//
// Usage: go run ./internal/tools/validate-embed
//
// Requires: stave binary built (make build).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// exclusions lists control directories that intentionally exist on
// disk but are NOT individual shipping controls (they use different
// schemas or are metadata files). Extend this list — never infer
// exclusions from the embed directive.
var exclusions = map[string]bool{
	"_triage": true,
}

func diskControlIDs(root string) (map[string]bool, error) {
	ids := make(map[string]bool)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if exclusions[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".yaml" {
			return nil
		}
		id, err := extractID(path)
		if err != nil {
			return nil
		}
		if id != "" {
			ids[id] = true
		}
		return nil
	})
	return ids, err
}

func extractID(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if val, ok := strings.CutPrefix(line, "id:"); ok {
			return strings.TrimSpace(val), nil
		}
	}
	return "", nil
}

type compiledControl struct {
	ID string `json:"id"`
}

func binaryControlIDs(binary string) (map[string]bool, error) {
	cmd := exec.Command(binary, "controls", "list", "--built-in", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("stave controls list: %w", err)
	}
	var controls []compiledControl
	if err := json.Unmarshal(out, &controls); err != nil {
		return nil, fmt.Errorf("parse controls list: %w", err)
	}
	ids := make(map[string]bool, len(controls))
	for _, c := range controls {
		ids[c.ID] = true
	}
	return ids, nil
}

// compareIDs returns (disk-only, binary-only) sets.
func compareIDs(disk, binary map[string]bool) ([]string, []string) {
	var diskOnly, binaryOnly []string
	for id := range disk {
		if !binary[id] {
			diskOnly = append(diskOnly, id)
		}
	}
	for id := range binary {
		if !disk[id] {
			binaryOnly = append(binaryOnly, id)
		}
	}
	sort.Strings(diskOnly)
	sort.Strings(binaryOnly)
	return diskOnly, binaryOnly
}

func run() int {
	controlDir := "internal/controls"
	binary := "./stave"

	if len(os.Args) > 1 {
		controlDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		binary = os.Args[2]
	}

	disk, err := diskControlIDs(controlDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "disk scan: %v\n", err)
		return 4
	}

	compiled, err := binaryControlIDs(binary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "binary scan: %v\n", err)
		return 4
	}

	diskOnly, binaryOnly := compareIDs(disk, compiled)

	if len(diskOnly) == 0 && len(binaryOnly) == 0 {
		fmt.Printf("OK: %d controls on disk, %d in binary — sets equal\n", len(disk), len(compiled))
		return 0
	}

	if len(diskOnly) > 0 {
		fmt.Fprintf(os.Stderr, "DISK-NOT-COMPILED (%d) — controls on disk but missing from binary (b9c722e bug class):\n", len(diskOnly))
		for _, id := range diskOnly {
			fmt.Fprintf(os.Stderr, "  %s\n", id)
		}
	}
	if len(binaryOnly) > 0 {
		fmt.Fprintf(os.Stderr, "COMPILED-NOT-ON-DISK (%d) — controls in binary but missing from disk (mirror bug):\n", len(binaryOnly))
		for _, id := range binaryOnly {
			fmt.Fprintf(os.Stderr, "  %s\n", id)
		}
	}

	fmt.Fprintf(os.Stderr, "\n%d discrepancy(ies): disk=%d, binary=%d\n",
		len(diskOnly)+len(binaryOnly), len(disk), len(compiled))
	return 1
}

func main() {
	os.Exit(run())
}
