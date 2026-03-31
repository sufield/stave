# GitHub Actions + SARIF

Show stave violations as annotations in GitHub PR diffs and in the
repository Security tab.

## Prerequisites

- GitHub repository with Actions enabled
- stave binary (built from source or downloaded from releases)

## Install

Add this workflow file to your repository:

```bash
mkdir -p .github/workflows
cat > .github/workflows/stave.yml << 'EOF'
name: Stave Security Scan
on: [push, pull_request]
permissions:
  security-events: write
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Install stave
        run: |
          git clone https://github.com/sufield/stave.git /tmp/stave
          cd /tmp/stave && make build
          sudo cp /tmp/stave/stave /usr/local/bin/

      - name: Run stave
        run: |
          stave apply \
            --controls controls \
            --observations observations \
            --max-unsafe 7d \
            --now $(date -u +%Y-%m-%dT%H:%M:%SZ) \
            --format sarif > results.sarif || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: stave
EOF
```

## Run

1. Commit the workflow file and your controls/observations directories:

```bash
git add .github/workflows/stave.yml controls/ observations/
git commit -m "Add stave security scan"
git push
```

2. Open a pull request. Stave violations appear as annotations in the
   "Files changed" tab and in the repository's Security > Code scanning
   alerts section.

## What you see

- Each violation is an annotation on the PR diff
- The Security tab shows all findings with severity, control ID, and
  remediation guidance
- Findings persist across commits until resolved
