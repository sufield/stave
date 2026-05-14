package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Stave is air-gapped by default. The update check is the one feature that
// makes a network call, and it runs only when the operator explicitly asks
// for it via `stave version --check-update`. The default `stave version`
// flow makes no network calls; `--check-update` is opt-in per invocation
// (no persisted preference, no automatic polling on startup).
//
// STAVE_NO_NETWORK=1 short-circuits the check even when the flag is set,
// so operators running in an air-gapped environment can pass the same
// scripts that work elsewhere without surprises.

const (
	githubLatestReleaseURL = "https://api.github.com/repos/sufield/stave/releases/latest"
	updateCheckTimeout     = 3 * time.Second
)

// runUpdateCheck performs the explicit update check and writes a single
// status line to w. Network failures are reported as warnings, not errors —
// the user asked for an opt-in check, not a strict gate.
func runUpdateCheck(ctx context.Context, w io.Writer, current string) {
	if os.Getenv("STAVE_NO_NETWORK") == "1" {
		fmt.Fprintln(w, "Update check skipped: STAVE_NO_NETWORK=1")
		return
	}
	latest, err := fetchLatestRelease(ctx, githubLatestReleaseURL)
	if err != nil {
		fmt.Fprintf(w, "Update check: could not reach GitHub (%v)\n", err)
		return
	}
	if sameVersion(current, latest) {
		fmt.Fprintf(w, "Update check: current version (%s) is the latest.\n", current)
		return
	}
	fmt.Fprintf(w, "Update check: a newer version (%s) is available. You are on %s.\n", latest, current)
	fmt.Fprintln(w, "  Install via:")
	fmt.Fprintln(w, "    curl -fsSL https://raw.githubusercontent.com/sufield/stave/main/install.sh | sh")
}

// fetchLatestRelease GETs the GitHub releases/latest endpoint and returns
// the tag_name field. The url parameter is injectable for tests.
func fetchLatestRelease(ctx context.Context, url string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, updateCheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github API returned %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if body.TagName == "" {
		return "", errors.New("empty tag_name in response")
	}
	return body.TagName, nil
}

// sameVersion compares two version strings ignoring a leading "v".
// Edge cases: an empty/edge build version always reports "newer available."
func sameVersion(current, latest string) bool {
	c := strings.TrimPrefix(strings.TrimSpace(current), "v")
	l := strings.TrimPrefix(strings.TrimSpace(latest), "v")
	if c == "" || c == "edge" {
		return false
	}
	return c == l
}
