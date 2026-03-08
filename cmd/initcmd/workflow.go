package initcmd

import (
	"github.com/sufield/stave/internal/envvar"
)

func scaffoldGitHubActions(opts scaffoldOptions) string {
	return scaffoldGitHubActionsHeader(opts) +
		scaffoldGitHubActionsSetup(opts) +
		scaffoldGitHubActionsEvaluation()
}

func scaffoldGitHubActionsHeader(opts scaffoldOptions) string {
	return `name: stave-ci

on:
  pull_request:
  push:
    branches: [ main ]
` + workflowScheduleBlock(opts.CaptureCadence) + `
  workflow_dispatch:

permissions:
  contents: read

jobs:
  stave:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    env:
      ` + envvar.MaxUnsafe.Name + `: 168h
`
}

func scaffoldGitHubActionsSetup(opts scaffoldOptions) string {
	return `    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.26"
          cache: true

      - name: Install stave CLI
        run: |
          go install github.com/sufield/stave/cmd/stave@latest
          echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"

      - name: Compute snapshot filename convention
        run: |
          echo "SNAPSHOT_FILE=observations/` + githubSnapshotDateFormat(opts.CaptureCadence) + `.json" >> "$GITHUB_ENV"

      - name: Show stave version
        run: stave version
`
}

func scaffoldGitHubActionsEvaluation() string {
	return `

      - name: Validate observations and controls
        run: |
          stave validate \
            --controls ./controls \
            --observations ./observations

      - name: Check snapshot quality gate
        run: |
          stave snapshot quality \
            --observations ./observations \
            --strict

      - name: Evaluate and generate machine-readable output
        run: |
          mkdir -p output
          stave apply \
            --controls ./controls \
            --observations ./observations \
            --format json > output/evaluation.json

      - name: Enforce CI failure policy
        run: |
          stave ci gate \
            --in output/evaluation.json \
            --policy "$(awk -F': ' '/^ci_failure_policy:/ {print $2}' ` + projectConfigFile + ` || echo ` + defaultCIFailurePolicy + `)"

      - name: Generate upcoming snapshot schedule
        run: |
          mkdir -p output
          stave snapshot upcoming \
            --controls ./controls \
            --observations ./observations \
            > output/upcoming.md

      - name: Upload stave artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: stave-output
          path: |
            output/evaluation.json
            output/upcoming.md
`
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

func workflowScheduleBlock(cadence string) string {
	if cadence == cadenceHourly {
		return "  schedule:\n    - cron: \"0 * * * *\""
	}
	return "  schedule:\n    - cron: \"0 2 * * *\""
}

func githubSnapshotDateFormat(cadence string) string {
	if cadence == cadenceHourly {
		return "$(date -u +'%Y-%m-%dT%H:00:00Z')"
	}
	return "$(date -u +'%Y-%m-%dT00:00:00Z')"
}
