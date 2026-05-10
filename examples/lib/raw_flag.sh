#!/usr/bin/env bash
# Source this from any example/run.sh that wants to honour the
# convention `bash run.sh --raw`. Sets FMT_RAW=1 and removes
# --raw from the positional args before the caller proceeds.
#
# Usage:
#   source "$example_root/lib/raw_flag.sh"
#   parse_raw_flag "$@"
#   set -- "${RAW_FLAG_ARGS[@]}"
#
# After the call, FMT_RAW is 0 or 1 and the positional args
# carry whatever else the caller supplied (fixture paths,
# observation directories, etc.).

# shellcheck disable=SC2034  # exported for sourcing scripts

parse_raw_flag() {
    FMT_RAW=0
    RAW_FLAG_ARGS=()
    local arg
    for arg in "$@"; do
        if [[ "$arg" == "--raw" ]]; then
            FMT_RAW=1
        else
            RAW_FLAG_ARGS+=("$arg")
        fi
    done
    export FMT_RAW
}
