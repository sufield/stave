#!/bin/bash
# Provisioner script for the Stave DigitalOcean 1-Click App image.
# Runs on the build droplet (s-2vcpu-2gb); the resulting snapshot
# runs on any droplet size >= snapshot disk (so the $6 s-1vcpu-1gb
# production target is fine).
#
# Mirrors stave-workspace/Dockerfile's install steps in shell form
# — same pinned versions, same /opt/stave/ tree, same convenience
# symlinks, same MOTD intent. One source of truth for what an
# adopter gets, two delivery formats (Docker image, DO snapshot).
#
# Environment (from Packer's `environment_vars`):
#   STAVE_REF    git ref to build — branch, tag, or commit. Empty = main.
#                For a marketplace submission, pin to a release tag.
#   GO_VERSION   Go toolchain to install. Must match go.mod.

set -euo pipefail

STAVE_REF="${STAVE_REF:-main}"
GO_VERSION="${GO_VERSION:-1.26.4}"
STEAMPIPE_VERSION="1.0.0"

echo "── System packages ─────────────────────────────────────────"
apt-get update
apt-get install -y --no-install-recommends \
    ca-certificates curl wget git jq unzip bash-completion sudo less
rm -rf /var/lib/apt/lists/*

echo "── Go ${GO_VERSION} ────────────────────────────────────────"
curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz
rm -f /tmp/go.tar.gz
cat >/etc/profile.d/go.sh <<'EOF'
export PATH="/usr/local/go/bin:${PATH}"
EOF
chmod 0644 /etc/profile.d/go.sh
export PATH="/usr/local/go/bin:${PATH}"
go version

echo "── Steampipe ${STEAMPIPE_VERSION} ──────────────────────────"
curl -fsSL "https://github.com/turbot/steampipe/releases/download/v${STEAMPIPE_VERSION}/steampipe_linux_amd64.tar.gz" \
    -o /tmp/steampipe.tar.gz
tar -xzf /tmp/steampipe.tar.gz -C /usr/local/bin steampipe
rm -f /tmp/steampipe.tar.gz
steampipe --version

# Steampipe plugin install requires running as a non-root user. The
# 1-Click image's default login is root (DO convention), but we
# pre-install the AWS plugin in /root's steampipe dir so the user's
# first `steampipe query` works out of the box. Other plugins
# (gcp / kubernetes / azure) are left for the user to add — keeps
# image size lean.
HOME=/root steampipe plugin install aws

echo "── Stave (ref: ${STAVE_REF}) ───────────────────────────────"
git clone https://github.com/sufield/stave.git /opt/stave
cd /opt/stave
git checkout "${STAVE_REF}"

# `make build` runs sync-schemas + sync-controls + sync-alternatives
# before `go build` so the embedded mirrors match canonical sources.
# Replicate that here, then build both binaries.
make sync-schemas sync-controls sync-alternatives
go build -trimpath -ldflags="-s -w" -o /usr/local/bin/stave     ./cmd/stave
go build -trimpath -ldflags="-s -w" -o /usr/local/bin/stave-mcp ./cmd/mcp
stave version
stave-mcp --hosted </dev/null >/dev/null 2>&1 || true  # sanity-start

echo "── Environment + symlinks ──────────────────────────────────"
cat >/etc/profile.d/stave.sh <<'EOF'
export STAVE_CONTROLS=/opt/stave/controls
export STAVE_CHAINS=/opt/stave/chains
EOF
chmod 0644 /etc/profile.d/stave.sh

# Convenience home symlinks for the default `root` user — mirror
# the Coder workspace layout so the START-HERE commands are
# identical across both distribution channels.
ln -sfn /opt/stave/examples       /root/examples
ln -sfn /opt/stave/chains         /root/chains
ln -sfn /opt/stave/docs/workflows /root/guides
cp /opt/stave/docs/workflows/START-HERE.md /root/START-HERE.md

# Per-demo `obs` symlink → fixtures/writeup-config/observations,
# so the short path `~/examples/demo-*/obs` in START-HERE and the
# MOTD actually resolves to a real observations directory.
for d in /opt/stave/examples/demo-*; do
    if [ -d "$d/fixtures/writeup-config/observations" ]; then
        ln -sfn fixtures/writeup-config/observations "$d/obs"
    fi
done

echo "── MOTD ────────────────────────────────────────────────────"
# DO's image-validator (img_check.sh) checks for /etc/update-motd.d/
# entries; place the Stave banner with a high number so it appears
# after any DO/Ubuntu welcome blocks.
cat >/etc/update-motd.d/99-stave <<'MOTD'
#!/bin/sh
# Stave 1-Click App welcome banner.
printf '\n'
printf '  \033[1mStave Security Evaluation Droplet\033[0m\n'
printf '\n'
printf '  Quick start:\n'
printf '    bash ~/examples/demo-ai-security/run.sh\n'
printf '\n'
printf '  Visualizers:\n'
printf '    stave-mcp --demo-dashboard    --observations ~/examples/demo-ai-security/obs\n'
printf '    stave-mcp --render-scorecard  --observations ~/examples/demo-ai-security/obs --frameworks hipaa\n'
printf '    stave-mcp --render-chains     --observations ~/examples/demo-ai-security/obs\n'
printf '\n'
printf '  Your own AWS (configure `aws configure` first):\n'
printf '    mkdir -p ~/obs && steampipe query "select * from aws_s3_bucket" --output json > ~/obs/s3.json\n'
printf '    stave apply --observations ~/obs/\n'
printf '\n'
printf '  Guides:    ls ~/guides/        (start: cat ~/START-HERE.md)\n'
printf '\n'
MOTD
chmod +x /etc/update-motd.d/99-stave

# Some Ubuntu cloud images keep the noisy default greeting on. The
# DO marketplace style guide encourages product-specific banners as
# the FIRST thing on SSH; disable the chatty defaults.
for f in 10-help-text 50-motd-news 80-livepatch 90-updates-available 91-contract-ua-esm-status 95-hwe-eol; do
    if [ -f "/etc/update-motd.d/$f" ]; then
        chmod -x "/etc/update-motd.d/$f"
    fi
done

echo "── Done ────────────────────────────────────────────────────"
