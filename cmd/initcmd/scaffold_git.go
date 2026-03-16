package initcmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sufield/stave/internal/adapters/gitinfo"
)

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
