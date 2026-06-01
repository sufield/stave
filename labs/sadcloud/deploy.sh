#!/usr/bin/env bash
# SadCloud lab deployment.
# Runs in the fixture-refresh CI job (credentialed, gated).
#
# Prerequisites:
#   - Terraform installed
#   - AWS credentials configured (sandbox account)
#   - SadCloud repo cloned at vendor-repo/sadcloud/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SADCLOUD_DIR="$SCRIPT_DIR/vendor-repo/sadcloud/sadcloud"

if [ ! -d "$SADCLOUD_DIR" ]; then
    echo "Clone SadCloud first: git clone https://github.com/nccgroup/sadcloud.git $SCRIPT_DIR/vendor-repo/sadcloud"
    exit 1
fi

cd "$SADCLOUD_DIR"
terraform init -input=false
terraform apply -auto-approve -input=false
