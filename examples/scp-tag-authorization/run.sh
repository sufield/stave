#!/usr/bin/env bash
# TAG-INTEGRITY-001 — four-layer conjunction + bypass-path attribution.
# Soufflé names the bypass path; Z3 proves scheme-complete = AND of four.
#   complete        : all four hold                       -> NONE / sat   (PASS)
#   rcp_missing     : RCP session-tag block absent        -> session-tag-injection / unsat (FAIL)
#   mutation_wrongop: mutation lock present-but-wrong-op  -> self-tag-exemption / unsat    (FAIL)
#   enforce_missing : no enforcement SCP                  -> no-enforcement / unsat         (FAIL)
set -uo pipefail; cd "$(dirname "$0")"; HERE=$(pwd)
build() {
  local d="$1"; mkdir -p "$d"; : > "$d/layer_holds.facts"
  local a=true b=true r=true c=true   # 001 002 rcp 003
  case "$(basename "$1")" in
    facts-complete)        : ;;
    facts-rcp_missing)     r=false ;;
    facts-mutation_wrongop) b=false ;;   # exists but StringNotEquals -> collector says not-holds
    facts-enforce_missing) a=false ;;
  esac
  [ "$a" = true ] && echo "scp-tag-001" >> "$d/layer_holds.facts"
  [ "$b" = true ] && echo "scp-tag-002" >> "$d/layer_holds.facts"
  [ "$r" = true ] && echo "rcp-tag-001" >> "$d/layer_holds.facts"
  [ "$c" = true ] && echo "scp-tag-003" >> "$d/layer_holds.facts"
  printf '(declare-const l_001 Bool)(assert (= l_001 %s))\n(declare-const l_002 Bool)(assert (= l_002 %s))\n(declare-const l_rcp Bool)(assert (= l_rcp %s))\n(declare-const l_003 Bool)(assert (= l_003 %s))\n' "$a" "$b" "$r" "$c" > "$d/facts.smt2"
}
for s in complete rcp_missing mutation_wrongop enforce_missing; do
  d="$HERE/facts-$s"; build "$d"; mkdir -p "$d/out"
  souffle "$HERE/scheme.dl" -F "$d" -D "$d/out" 2>/dev/null
  path=$(cut -f1 "$d/out/scheme_bypassable.csv" 2>/dev/null); path=${path%%$'\n'*}; path=${path:-NONE}
  z3o=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null); z3v=${z3o%%$'\n'*}
  printf '%-16s souffle=%-22s z3=%-5s\n' "$s" "$path" "$z3v"
done
