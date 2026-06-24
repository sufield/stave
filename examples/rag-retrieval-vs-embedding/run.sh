#!/usr/bin/env bash
#
# RAG-003 reasoning spec — trap-triplet over both engines (Soufflé set-difference
# + Z3 existence). retrieval must be a strict read-only subset of embedding.
#
#   vuln : retrieval has s3:* (wildcard) embedding lacks                  -> VIOLATION (FAIL)
#   fp   : retrieval read-only subset + bedrock:Retrieve only             -> NONE      (PASS)
#   fn   : retrieval has secretsmanager via an attached managed policy    -> VIOLATION (FAIL)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/retrieval_perm.facts"; : > "$d/embedding_perm.facts"
  printf 's3\tPutObject\ns3\tDeleteObject\nsecretsmanager\tPutSecretValue\n' > "$d/write_action.facts"  # 1-col used; pad col2
  : > "$d/write_action.facts"
  printf 'PutObject\nDeleteObject\nStartIngestionJob\n' >> "$d/write_action.facts"
  case "$(basename "$1")" in
    facts-vuln)
      # embedding: scoped read+write on the source prefix
      printf 's3\tGetObject\tsupport-docs\ns3\tPutObject\tsupport-docs\n' >> "$d/embedding_perm.facts"
      # retrieval: s3:* on everything (wildcard the embedding role lacks) + bedrock:Retrieve
      printf 's3\t*\t*\nbedrock\tRetrieve\tkb\n'                          >> "$d/retrieval_perm.facts" ;;
    facts-fp)
      printf 's3\tGetObject\tproduct-docs\ns3\tPutObject\tproduct-docs\naoss\tWrite\tcollection\n' >> "$d/embedding_perm.facts"
      # retrieval: read-only subset + design-intended bedrock:Retrieve
      printf 's3\tGetObject\tproduct-docs\nbedrock\tRetrieve\tkb\n'        >> "$d/retrieval_perm.facts" ;;
    facts-fn)
      printf 's3\tGetObject\tinternal-docs\n'                             >> "$d/embedding_perm.facts"
      # retrieval looks identical on s3 BUT an attached managed policy adds secretsmanager
      printf 's3\tGetObject\tinternal-docs\nbedrock\tRetrieve\tkb\nsecretsmanager\tGetSecretValue\t*\n' >> "$d/retrieval_perm.facts" ;;
  esac
  {
    echo "(define-fun retrieval_perm ((s String)(a String)(r String)) Bool (or"
    awk -F'\t' '{printf "  (and (= s \"%s\")(= a \"%s\")(= r \"%s\"))\n",$1,$2,$3}' "$d/retrieval_perm.facts"; echo "  false))"
    echo "(define-fun embedding_perm ((s String)(a String)(r String)) Bool (or"
    awk -F'\t' '{printf "  (and (= s \"%s\")(= a \"%s\")(= r \"%s\"))\n",$1,$2,$3}' "$d/embedding_perm.facts"; echo "  false))"
    echo "(define-fun write_action ((a String)) Bool (or"
    awk -F'\t' '{printf "  (= a \"%s\")\n",$1}' "$d/write_action.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/broader.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/violation.csv" ] && echo BROADER || echo SUBSET)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-7s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
