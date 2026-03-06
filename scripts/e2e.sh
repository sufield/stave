#!/usr/bin/env bash
set -euo pipefail

BIN="${BIN:-./stave}"

fail() { echo "FAIL: $*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1"
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  else
    shasum -a 256 "$file" | awk '{print $1}'
  fi
}

run_case() {
  local case_dir="$1"
  local name
  name="$(basename "$case_dir")"

  local inv="$case_dir/controls"
  local obs="$case_dir/observations"
  local now="2026-01-11T00:00:00Z"

  local out="$case_dir/output.json"
  local err="$case_dir/err.txt"

  rm -f "$out" "$err"
  rm -rf "$case_dir/outdir"

  set +e
  if [[ -f "$case_dir/command.txt" ]]; then
    # Custom command: substitute $CASE_DIR and run
    local cmd_content
    cmd_content="$(tr '\n' ' ' < "$case_dir/command.txt")"
    cmd_content="${cmd_content//\$CASE_DIR/$case_dir}"
    # shellcheck disable=SC2086
    "$BIN" $cmd_content >"$out" 2>"$err"
  else
    local extra=()
    if [[ -f "$case_dir/args.txt" ]]; then
      # Read args and substitute $CASE_DIR with actual case directory
      local args_content
      args_content="$(tr '\n' ' ' < "$case_dir/args.txt")"
      args_content="${args_content//\$CASE_DIR/$case_dir}"
      # shellcheck disable=SC2206
      extra=($args_content)
    fi

    "$BIN" evaluate \
      --controls "$inv" \
      --observations "$obs" \
      --max-unsafe 168h \
      --now "$now" \
      ${extra[*]+"${extra[@]}"} \
      >"$out" 2>"$err"
  fi
  local code=$?
  set -e

  if [[ -f "$case_dir/expected.exit" ]]; then
    local expected_code
    expected_code="$(tr -d ' \n\r\t' < "$case_dir/expected.exit")"
    [[ "$code" == "$expected_code" ]] || fail "$name exit=$code expected=$expected_code"
  fi

  if [[ -f "$case_dir/expected.err.txt" ]]; then
    local pat
    pat="$(cat "$case_dir/expected.err.txt")"
    grep -qi -- "$pat" "$err" || fail "$name stderr missing pattern: $pat"
  fi

  if [[ -f "$case_dir/expected.summary.json" ]]; then
    # compare only summary keys (order-independent)
    local exp_summary act_summary
    exp_summary="$(jq -S '.' "$case_dir/expected.summary.json")"
    act_summary="$(jq -S '.summary' "$out")"
    [[ "$act_summary" == "$exp_summary" ]] || fail "$name summary mismatch
expected: $exp_summary
actual:   $act_summary"
  fi

  if [[ -f "$case_dir/expected.findings.count" ]]; then
    local exp_count act_count
    exp_count="$(tr -d ' \n\r\t' < "$case_dir/expected.findings.count")"
    act_count="$(jq '.findings | length' "$out")"
    [[ "$act_count" == "$exp_count" ]] || fail "$name findings=$act_count expected=$exp_count"
  fi

  if [[ -f "$case_dir/expected.outfile" ]]; then
    local outfile_rel outfile_path
    outfile_rel="$(tr -d ' \n\r\t' < "$case_dir/expected.outfile")"
    outfile_path="$case_dir/$outfile_rel"
    [[ -f "$outfile_path" ]] || fail "$name --out file missing: $outfile_path"
    local file_summary
    file_summary="$(jq -S '.summary' "$outfile_path")"
    [[ "$file_summary" == "$exp_summary" ]] || fail "$name --out file summary mismatch"
  fi

  if [[ -f "$case_dir/expected.input_hashes.json" ]]; then
    local exp_hashes act_hashes
    exp_hashes="$(jq -S '.' "$case_dir/expected.input_hashes.json")"
    act_hashes="$(jq -S '.run.input_hashes' "$out")"
    [[ "$act_hashes" == "$exp_hashes" ]] || fail "$name input_hashes mismatch
expected: $exp_hashes
actual:   $act_hashes"
  fi

  if [[ -f "$case_dir/expected.source_evidence.json" ]]; then
    # Build actual source_evidence map keyed by invariant_id from findings
    local exp_se act_se
    exp_se="$(jq -S '.' "$case_dir/expected.source_evidence.json")"
    act_se="$(jq -S '[.findings[] | select(.evidence.source_evidence != null) | {(.invariant_id): .evidence.source_evidence}] | add // {}' "$out")"
    [[ "$act_se" == "$exp_se" ]] || fail "$name source_evidence mismatch
expected: $exp_se
actual:   $act_se"
  fi

  if [[ -f "$case_dir/expected.out.json" ]]; then
    # Full byte-level golden comparison (N2): canonical jq -S normalization
    # Strip extensions (contains git state that varies between environments)
    diff -u <(jq -S 'del(.extensions)' "$case_dir/expected.out.json") \
            <(jq -S 'del(.extensions)' "$out") \
      || fail "$name full output mismatch (see diff above)"
  fi

  if [[ -f "$case_dir/expected.generated.path" && -f "$case_dir/expected.generated.sha256" ]]; then
    local generated_rel generated_path exp_sha act_sha
    generated_rel="$(tr -d ' \n\r\t' < "$case_dir/expected.generated.path")"
    generated_path="$case_dir/$generated_rel"
    [[ -f "$generated_path" ]] || fail "$name generated file missing: $generated_path"
    exp_sha="$(tr -d ' \n\r\t' < "$case_dir/expected.generated.sha256")"
    act_sha="$(sha256_file "$generated_path")"
    [[ "$act_sha" == "$exp_sha" ]] || fail "$name generated file hash mismatch
expected: $exp_sha
actual:   $act_sha"
  fi

  echo "OK: $name"
}

main() {
  need jq
  [[ -x "$BIN" ]] || fail "binary not found/executable: $BIN (build first: make build)"

  local root="testdata/e2e"
  [[ -d "$root" ]] || fail "missing: $root"

  local cases=()
  while IFS= read -r -d '' d; do cases+=("$d"); done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)

  [[ "${#cases[@]}" -gt 0 ]] || fail "no cases found under $root"

  for c in "${cases[@]}"; do
    run_case "$c"
  done

  echo "ALL OK"
}

main "$@"
