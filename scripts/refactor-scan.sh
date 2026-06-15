#!/usr/bin/env bash
#
# refactor-scan.sh — find remaining Go modernization candidates and track burn-down.
#
# Two tiers of category:
#   - RATCHETED (genuine targets that should trend to zero): each match is a real
#     refactor. Gated against a committed baseline so the count can only go down,
#     never up (mirrors `make lint-debt`).
#   - INFORMATIONAL (wide nets that are mostly legitimate code): listed for triage
#     only, NEVER gated — the goal is improving code, not pressuring "fixes" on
#     false positives.
#
# Allocation-elimination patterns NOT covered here (hugeParam, rangeValCopy,
# perfsprint, unused, ...) are already enforced by `make lint` — keep that green.
#
# Usage: scripts/refactor-scan.sh [list|count|check|update-baseline]
#   list             (default) per-category counts; full file:line list for
#                    ratcheted categories, counts only for informational ones.
#   count            one line per category: "<key> <count>".
#   check            compare ratcheted counts to the baseline; exit 1 if any grew.
#   update-baseline  write current ratcheted counts to the baseline file.
#
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$script_dir/.." && pwd)
cd "$root"

BASELINE="${REFACTOR_BASELINE:-docs/audits/refactor-scan-baseline}"

# key <TAB> ratchet(1/0) <TAB> label <TAB> ERE detector. Production Go only;
# _test.go and vendored/generated trees excluded in scan().
CATEGORIES=$(cat <<'EOF'
casing-eqfold	1	ToLower/ToUpper compared with ==/!= -> strings.EqualFold	strings\.To(Lower|Upper)\([^)]*\)[[:space:]]*(==|!=)|(==|!=)[[:space:]]*strings\.To(Lower|Upper)\(
casing-trim	1	ToLower(TrimSpace(...)) -> toLowerTrim fast path	strings\.ToLower\(strings\.TrimSpace
split-cut	1	SplitN(...,2) / Split(...)[0|1] -> strings.Cut	strings\.SplitN\([^)]*,[[:space:]]*2\)|strings\.Split\([^)]*\)\[[01]\]
set-bool	0	map[T]bool set candidate -> map[T]struct{} (skip JSON-tagged / real bool)	map\[[^]]*\]bool
empty-slice	0	make([]T, 0) -> nil slice (skip the emptyIfNil JSON pattern)	make\(\[\][^,]*,[[:space:]]*0\)
wide-tolower	0	strings.ToLower( wide net (triage: storage vs comparison)	strings\.ToLower\(
wide-split	0	strings.Split( wide net (triage: needs all parts?)	strings\.Split\(
wide-join	0	strings.Join( wide net (triage: display/serialization?)	strings\.Join\(
EOF
)

# grep --exclude-dir matches by basename, so "tools" covers internal/tools.
scan() { # $1 = ERE
	grep -rnE "$1" --include='*.go' --exclude='*_test.go' \
		--exclude-dir=vendor --exclude-dir=examples --exclude-dir=experiments \
		--exclude-dir=reasoning --exclude-dir=tools . 2>/dev/null || true
}
count() { scan "$1" | wc -l | tr -d ' '; }
baseline_of() { [ -f "$BASELINE" ] && awk -v k="$1" '$1==k {print $2}' "$BASELINE" || true; }

GREW=0
DROPPED=0

_count() { printf '%s\t%s\n' "$1" "$(count "$4")"; }

_list() {
	local key="$1" ratchet="$2" label="$3" pat="$4" n
	n=$(count "$pat")
	printf '\n== %-13s %4s   %s\n' "$key" "$n" "$label"
	if [ "$ratchet" = "1" ] && [ "$n" -gt 0 ]; then
		scan "$pat" | sed 's/^/   /'
	fi
}

_check() {
	local key="$1" ratchet="$2" pat="$4" n base
	[ "$ratchet" = "1" ] || return 0
	n=$(count "$pat")
	base=$(baseline_of "$key")
	if [ -z "$base" ]; then
		printf '  %-14s %3s  (no baseline)\n' "$key" "$n"
		return 0
	fi
	printf '  %-14s %3s  (baseline %s)' "$key" "$n" "$base"
	if [ "$n" -gt "$base" ]; then echo "  GROWN"; GREW=1
	elif [ "$n" -lt "$base" ]; then echo "  dropped"; DROPPED=1
	else echo "  ok"; fi
}

_baseline_line() { [ "$2" = "1" ] && printf '%s\t%s\n' "$1" "$(count "$4")" || true; }

each() {
	local fn="$1"
	while IFS=$'\t' read -r key ratchet label pat; do
		[ -n "${key:-}" ] || continue
		"$fn" "$key" "$ratchet" "$label" "$pat"
	done <<<"$CATEGORIES"
}

case "${1:-list}" in
list)
	echo "Refactor candidates (production Go; _test/vendor/examples/experiments/reasoning/tools excluded)."
	echo "Ratcheted categories show full file:line lists; informational ones show counts only."
	each _list
	;;
count) each _count ;;
update-baseline)
	mkdir -p "$(dirname "$BASELINE")"
	each _baseline_line >"$BASELINE"
	echo "wrote ratcheted baseline -> $BASELINE"; cat "$BASELINE"
	;;
check)
	had=0; [ -f "$BASELINE" ] && had=1
	echo "Ratcheted refactor burn-down (baseline: $BASELINE)"
	each _check
	if [ "$had" -eq 0 ]; then
		echo; echo "No baseline yet — establish one: make refactor-scan-update"
	elif [ "$GREW" -eq 1 ]; then
		echo; echo "ERROR: a ratcheted category grew. Refactor the new site(s) (see the plan),"
		echo "       or if intentional, justify and run: make refactor-scan-update"
	elif [ "$DROPPED" -eq 1 ]; then
		echo; echo "Counts dropped — tighten the ratchet: make refactor-scan-update && git add $BASELINE"
	else
		echo; echo "No change. Ratchet holds."
	fi
	exit "$GREW"
	;;
*) echo "usage: $0 [list|count|check|update-baseline]" >&2; exit 2 ;;
esac
