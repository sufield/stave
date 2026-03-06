#!/usr/bin/env bash
set -uo pipefail

# Run only S3 e2e cases using the existing scripts/e2e.sh runner.
# Strategy: temporarily move non-S3 cases out of testdata/e2e, run scripts/e2e.sh, then restore.

BIN="${BIN:-./stave}"

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "FAIL: missing dependency: $1" >&2; exit 1; }
}

need jq
need rg
[[ -x "$BIN" ]] || { echo "FAIL: binary not found/executable: $BIN (build first: make build)" >&2; exit 1; }

root="testdata/e2e"
[[ -d "$root" ]] || { echo "FAIL: missing: $root" >&2; exit 1; }

# Ensure there is at least one S3 case
if ! find "$root" -mindepth 1 -maxdepth 1 -type d -name 'e2e-s3-*' | rg -q .; then
  echo "FAIL: no S3 cases found under $root" >&2
  exit 1
fi

tmp="$(mktemp -d)"
moved=()

restore() {
  for d in "${moved[@]}"; do
    base="$(basename "$d")"
    if [[ -d "$tmp/$base" ]]; then
      mv "$tmp/$base" "$root/"
    fi
  done
  rm -rf "$tmp"
}

trap restore EXIT

# Move non-selected dirs aside
for d in "$root"/*; do
  [[ -d "$d" ]] || continue
  base="$(basename "$d")"
  if [[ "$base" == e2e-s3-* ]]; then
    continue
  fi
  mv "$d" "$tmp/$base"
  moved+=("$d")
done

# Run normal runner (now it sees only e2e-s3-*).
set +e
./scripts/e2e.sh
status=$?
set -e

exit "$status"
