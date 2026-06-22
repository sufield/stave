#!/usr/bin/env bash
#
# capture-fixture.sh — Deploy a vulnerable lab, capture observations, tear down.
#
# This is the ONLY script that uses AWS credentials. It runs inside the
# fixture-refresh CI job (gated environment, manual approval required)
# or manually by a maintainer. Stave's evaluation is never in this script;
# it runs air-gapped against the committed observations.
#
# Usage:
#   ./scripts/capture-fixture.sh sadcloud
#   ./scripts/capture-fixture.sh all
#
# Each lab has a directory under ctf/<vendor>/ (sadcloud's automated capture
# experiment -> ctf/nccgroup/automated) with:
#   deploy.sh     — terraform apply (or equivalent)
#   collect.sh    — run the collector, write observations/
#   destroy.sh    — terraform destroy
#   manifest.json — ground-truth expectations (updated by this script)
#
# The three scripts are lab-specific. This script orchestrates them
# and computes the observations hash for the manifest.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Vendor labs live under <repo-root>/ctf/<vendor>/ (e.g. sadcloud -> ctf/nccgroup),
# each with deploy.sh / collect.sh / destroy.sh / manifest.json. Map the lab
# name to its directory; KNOWN_LABS drives the "all" target.
CTF_DIR="$(cd "$REPO_ROOT/../ctf" && pwd)"
KNOWN_LABS=(sadcloud)

resolve_lab_dir() {
    case "$1" in
        sadcloud) echo "$CTF_DIR/nccgroup/automated" ;;
        *)        echo "" ;;
    esac
}

compute_obs_hash() {
    local obs_dir="$1"
    # sha256 over the sorted list of per-file sha256s
    find "$obs_dir" -name '*.json' -type f | sort | \
        xargs sha256sum | awk '{print $1}' | \
        sha256sum | awk '{print $1}'
}

run_lab() {
    local lab="$1"
    local lab_dir; lab_dir="$(resolve_lab_dir "$lab")"

    if [ -z "$lab_dir" ] || [ ! -d "$lab_dir" ]; then
        echo "ERROR: unknown lab '$lab' (dir: ${lab_dir:-<unmapped>})" >&2
        echo "Known labs: ${KNOWN_LABS[*]}" >&2
        return 1
    fi

    echo "=== $lab: deploy ==="
    if [ -x "$lab_dir/deploy.sh" ]; then
        bash "$lab_dir/deploy.sh"
    else
        echo "  SKIP: no deploy.sh (using existing infrastructure)"
    fi

    echo "=== $lab: collect ==="
    if [ -x "$lab_dir/collect.sh" ]; then
        bash "$lab_dir/collect.sh"
    else
        echo "  SKIP: no collect.sh (using existing observations)"
    fi

    echo "=== $lab: compute hash ==="
    local obs_dir="$lab_dir/observations"
    if [ ! -d "$obs_dir" ] || [ -z "$(ls "$obs_dir"/*.json 2>/dev/null)" ]; then
        echo "  ERROR: no observations in $obs_dir" >&2
        return 1
    fi
    local hash
    hash=$(compute_obs_hash "$obs_dir")
    echo "  sha256: $hash"

    # Update manifest if it exists
    local manifest="$lab_dir/manifest.json"
    if [ -f "$manifest" ] && command -v jq >/dev/null 2>&1; then
        local tmp
        tmp=$(mktemp)
        jq --arg hash "$hash" '.observations.sha256 = $hash' "$manifest" > "$tmp" && mv "$tmp" "$manifest"
        echo "  manifest updated"
    fi

    echo "=== $lab: destroy ==="
    if [ -x "$lab_dir/destroy.sh" ]; then
        bash "$lab_dir/destroy.sh"
    else
        echo "  SKIP: no destroy.sh"
    fi

    echo "=== $lab: done ==="
    echo ""
}

main() {
    local target="${1:-all}"

    if [ "$target" = "all" ]; then
        for lab in "${KNOWN_LABS[@]}"; do
            run_lab "$lab"
        done
    else
        run_lab "$target"
    fi
}

main "$@"
