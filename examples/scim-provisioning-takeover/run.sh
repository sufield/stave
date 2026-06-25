#!/usr/bin/env bash
#
# SCIM-004 reasoning spec — trap-triplet over both graph engines.
# Build the SCIM deployment graph per scenario, run Soufflé and Z3, print whether
# the provisioning-takeover chain exists. The two engines must agree.
#
#   vuln : public endpoint (authType NONE) + overpriv handler + token in env var -> TAKEOVER (FAIL)
#   fp   : authed endpoint + scoped handler + secured token                       -> NONE     (PASS)
#   fn   : AWS_IAM auth but Principal:* resource policy (effectively public) +
#          overpriv handler + secret with no resource policy                      -> TAKEOVER (FAIL)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  for r in scim_endpoint_public scim_handler_serves_api scim_handler_overprivileged scim_token_reachable; do : > "$d/$r.facts"; done
  case "$(basename "$1")" in
    facts-vuln)
      printf 'api1\t/v2/scim/Users\n'                 >> "$d/scim_endpoint_public.facts"
      printf 'scim-provisioner\tapi1\n'               >> "$d/scim_handler_serves_api.facts"
      printf 'scim-provisioner\tscim-handler-role\n'  >> "$d/scim_handler_overprivileged.facts"
      printf 'env:SCIM_BEARER_TOKEN\tlambda-env\n'    >> "$d/scim_token_reachable.facts" ;;
    facts-fp)
      # endpoint authed, handler scoped, token secured -> only the wiring fact present
      printf 'scim-provisioner\tapi2\n'               >> "$d/scim_handler_serves_api.facts" ;;
    facts-fn)
      # AWS_IAM + Principal:* resource policy => collector marks the endpoint public
      printf 'api3\t/v2/scim/Users\n'                 >> "$d/scim_endpoint_public.facts"
      printf 'scim-provisioner\tapi3\n'               >> "$d/scim_handler_serves_api.facts"
      printf 'scim-provisioner\tscim-handler-role\n'  >> "$d/scim_handler_overprivileged.facts"
      printf 'secret:scim-token\tno-resource-policy\n' >> "$d/scim_token_reachable.facts" ;;
  esac
  {
    echo "(define-fun scim_endpoint_public ((api String)(path String)) Bool (or"
    awk -F'\t' '{printf "  (and (= api \"%s\") (= path \"%s\"))\n",$1,$2}' "$d/scim_endpoint_public.facts"; echo "  false))"
    echo "(define-fun scim_handler_serves_api ((lam String)(api String)) Bool (or"
    awk -F'\t' '{printf "  (and (= lam \"%s\") (= api \"%s\"))\n",$1,$2}' "$d/scim_handler_serves_api.facts"; echo "  false))"
    echo "(define-fun scim_handler_overprivileged ((lam String)(role String)) Bool (or"
    awk -F'\t' '{printf "  (and (= lam \"%s\") (= role \"%s\"))\n",$1,$2}' "$d/scim_handler_overprivileged.facts"; echo "  false))"
    echo "(define-fun scim_token_reachable ((tok String)(via String)) Bool (or"
    awk -F'\t' '{printf "  (and (= tok \"%s\") (= via \"%s\"))\n",$1,$2}' "$d/scim_token_reachable.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/takeover.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/scim_provisioning_takeover.csv" ] && echo TAKEOVER || echo NONE)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-8s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
