#!/usr/bin/env bash
# Entrypoint for the Capital One Demo B image. Runs the Soufflé+Z3 reachability
# proof; with `verify`, also diffs against the committed expected output.
set -euo pipefail
spec=/demo/iam-foothold-internet-reach

echo "Capital One — Demo B: internet-facing role -> sensitive resource (Soufflé + Z3)"
echo

trim() { sed -E 's/[[:space:]]+$//'; }   # run.sh pads with printf; ignore trailing space

if [[ "${1:-}" == "verify" ]]; then
  bash "$spec/run.sh" | tee /tmp/out.txt
  if diff <(trim < /tmp/out.txt) <(trim < "$spec/expected/output.txt") >/dev/null; then
    echo
    echo "MATCHES committed expected output — both engines agree."
  else
    echo
    echo "DIFFERS from expected output" >&2
    exit 1
  fi
else
  bash "$spec/run.sh"
fi
