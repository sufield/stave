# CI Integration

Gate merges on security findings. Stave outputs SARIF, JSON, and
text — compatible with GitHub Code Scanning, GitLab SAST, and
any CI system.

## GitHub Actions with SARIF

Upload findings to GitHub Code Scanning:

```yaml
- name: Evaluate
  run: stave apply --observations ./snapshots/ --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

See [integrations/github-actions-sarif/](../../integrations/github-actions-sarif/)
for a complete workflow.

## CI gate (fail on findings)

```bash
# Exit 3 if violations found, exit 0 if clean
stave ci gate --observations ./snapshots/

# Fail only on new violations (baseline comparison)
stave ci baseline save --observations ./snapshots/
stave ci baseline check --observations ./snapshots/
```

## Pre-commit hook

```bash
# See integrations/pre-commit/ for setup
stave validate --in controls/
```

See [integrations/pre-commit/](../../integrations/pre-commit/) for configuration.

## More integrations

- [Atlantis](../../integrations/atlantis/) — Terraform PR automation
- [Slack webhook](../../integrations/slack-webhook/) — post findings to a channel
- [All integrations](../../integrations/README.md)
