#!/usr/bin/env bash
# Tear down SadCloud lab. MUST run same day as deploy (costs money).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SADCLOUD_DIR="$SCRIPT_DIR/vendor-repo/sadcloud/sadcloud"

if [ ! -d "$SADCLOUD_DIR" ]; then
    echo "SadCloud directory not found at $SADCLOUD_DIR" >&2
    exit 1
fi

cd "$SADCLOUD_DIR"
terraform destroy -auto-approve -input=false
