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

See [integrations/github-actions-sarif/](../../internal/integrations/github-actions-sarif/)
for a complete workflow.

## CI gate (fail on findings)

```bash
# doctest:skip — requires evaluation JSON from stave apply
# Exit 3 if violations found, exit 0 if clean
stave ci gate --policy fail_on_any_violation --in output/evaluation.json

# Fail only on new violations (baseline comparison)
stave ci baseline save --in output/evaluation.json
stave ci gate --policy fail_on_new_violation --in output/evaluation.json --baseline output/baseline.json
```

## Pre-commit hook

```bash
# See integrations/pre-commit/ for setup
stave lint --controls testdata/e2e/e2e-01-violation/controls --observations testdata/e2e/e2e-01-violation/observations
```

See [integrations/pre-commit/](../../internal/integrations/pre-commit/) for configuration.

## More integrations

- [Atlantis](../../internal/integrations/atlantis/) — Terraform PR automation
- [Slack webhook](../../internal/integrations/slack-webhook/) — post findings to a channel
- [All integrations](../../internal/integrations/README.md)
