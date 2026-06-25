#!/usr/bin/env bash
#
# COGNITO-SSO-005 reasoning spec — trap-triplet over both graph engines.
# Build the pool's federation graph per scenario, run Soufflé and Z3, print
# whether a ghost-identity-with-privileges chain exists. The two engines must
# agree on every scenario.
#
#   vuln : external IdPs + no PreSignUp + PartnerIdP sensitive mapping -> GHOST (FAIL)
#   fp   : external IdP + PreSignUp PRESENT + sensitive mapping        -> NONE  (PASS)
#   fn   : two IdPs, only PartnerIdP has sensitive mapping, no gate    -> GHOST (FAIL, names PartnerIdP)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/pool_has_external_idp.facts"; : > "$d/pool_missing_presignup.facts"; : > "$d/sensitive_attribute_mapped.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'us-east-1_ABC\tCorpIdP\n'                              >> "$d/pool_has_external_idp.facts"
      printf 'us-east-1_ABC\tPartnerIdP\n'                           >> "$d/pool_has_external_idp.facts"
      printf 'us-east-1_ABC\n'                                       >> "$d/pool_missing_presignup.facts"
      printf 'us-east-1_ABC\tPartnerIdP\tcustom:role\tgroups\n'      >> "$d/sensitive_attribute_mapped.facts" ;;
    facts-fp)
      # PreSignUp present -> pool_missing_presignup empty -> chain broken
      printf 'us-east-1_DEF\tCorpIdP\n'                              >> "$d/pool_has_external_idp.facts"
      printf 'us-east-1_DEF\tCorpIdP\tcustom:role\tgroups\n'         >> "$d/sensitive_attribute_mapped.facts" ;;
    facts-fn)
      printf 'us-east-1_GHI\tCorpIdP\n'                              >> "$d/pool_has_external_idp.facts"
      printf 'us-east-1_GHI\tPartnerIdP\n'                           >> "$d/pool_has_external_idp.facts"
      printf 'us-east-1_GHI\n'                                       >> "$d/pool_missing_presignup.facts"
      printf 'us-east-1_GHI\tPartnerIdP\tcustom:accessLevel\trole\n' >> "$d/sensitive_attribute_mapped.facts" ;;
  esac
  {
    echo "(define-fun pool_has_external_idp ((pool String)(idp String)) Bool (or"
    awk -F'\t' '{printf "  (and (= pool \"%s\") (= idp \"%s\"))\n",$1,$2}' "$d/pool_has_external_idp.facts"; echo "  false))"
    echo "(define-fun pool_missing_presignup ((pool String)) Bool (or"
    awk -F'\t' '{printf "  (= pool \"%s\")\n",$1}' "$d/pool_missing_presignup.facts"; echo "  false))"
    echo "(define-fun sensitive_attribute_mapped ((pool String)(idp String)(attr String)(claim String)) Bool (or"
    awk -F'\t' '{printf "  (and (= pool \"%s\") (= idp \"%s\") (= attr \"%s\") (= claim \"%s\"))\n",$1,$2,$3,$4}' "$d/sensitive_attribute_mapped.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/ghost_identity.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/ghost_identity.csv" ] && echo GHOST || echo NONE)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-5s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
