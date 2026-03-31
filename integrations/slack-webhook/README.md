# Slack Webhook

Send stave violation alerts to a Slack channel from CI.

## Prerequisites

- Slack workspace with a configured incoming webhook
- GitHub Actions (or any CI that runs shell commands)
- stave binary installed

## Install

1. Create a Slack incoming webhook at https://api.slack.com/messaging/webhooks

2. Add the webhook URL as a GitHub Actions secret named `SLACK_WEBHOOK`

3. Add this workflow to your repository:

```bash
mkdir -p .github/workflows
cat > .github/workflows/stave-slack.yml << 'EOF'
name: Stave + Slack
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

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
            --format json > findings.json || true

      - name: Notify Slack
        if: always()
        run: |
          VIOLATIONS=$(jq '.summary.violations' findings.json)
          if [ "$VIOLATIONS" -gt 0 ]; then
            COMMIT=$(git rev-parse --short HEAD)
            curl -s -X POST "${{ secrets.SLACK_WEBHOOK }}" \
              -H 'Content-type: application/json' \
              -d "{
                \"text\": \"Stave found $VIOLATIONS violation(s) in commit $COMMIT\",
                \"blocks\": [{
                  \"type\": \"section\",
                  \"text\": {
                    \"type\": \"mrkdwn\",
                    \"text\": \"*Stave Security Scan*\nCommit: \`$COMMIT\`\nViolations: *$VIOLATIONS*\nRun: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}\"
                  }
                }]
              }"
          fi
EOF
```

## Run

```bash
git add .github/workflows/stave-slack.yml
git commit -m "Add stave Slack notifications"
git push
```

## What you see

When stave finds violations, a Slack message appears in your channel
with the violation count, commit hash, and a link to the CI run.
Zero violations = no message (no noise when things are clean).
