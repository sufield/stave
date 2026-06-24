#!/usr/bin/env python3
# Translate SIR jsonl triples -> Soufflé facts dir + a .dl program.
# Sanitizes predicate names (dots -> underscores) for both .facts files and decls.
import json, sys, os, re

jsonl, outdir = sys.argv[1], sys.argv[2]
factsdir = os.path.join(outdir, "facts")
os.makedirs(factsdir, exist_ok=True)

def san(p): return re.sub(r"[^A-Za-z0-9_]", "_", p)

preds = {}  # sanitized -> list of (subj,obj)
for line in open(jsonl):
    line = line.strip()
    if not line: continue
    o = json.loads(line)
    p = o.get("predicate", "")
    if not p: continue
    preds.setdefault(san(p), []).append((o.get("subject", ""), str(o.get("object", ""))))

for p, tuples in preds.items():
    with open(os.path.join(factsdir, p + ".facts"), "w") as fh:
        for s, v in tuples:
            fh.write(f"{s}\t{v}\n")

# Ensure the two predicates the consumer rule needs are always declared,
# even if a given fixture didn't emit them (avoids souffle unknown-relation).
for needed in ("auto_prop_ai_knowledge_base_target_bucket_arn",
               "auto_prop_storage_tags_data_classification"):
    preds.setdefault(needed, [])
    fp = os.path.join(factsdir, needed + ".facts")
    if not os.path.exists(fp): open(fp, "w").close()

with open(os.path.join(outdir, "prog.dl"), "w") as dl:
    dl.write("// auto-generated from SIR jsonl\n")
    for p in sorted(preds):
        dl.write(f".decl {p}(subject:symbol, object:symbol)\n.input {p}\n")
    # ---- Task 3 consumer: a verdict the curated boolean predicates cannot express ----
    # Join a Bedrock knowledge base to a PHI-classified bucket BY ARN. The curated
    # has_* predicates are booleans; only the auto_prop_* string facts carry the
    # target-bucket ARN and the classification value needed to make this join.
    dl.write("""
.decl kb_ingests_phi(kb:symbol, phi_bucket:symbol)
.output kb_ingests_phi
kb_ingests_phi(KB, B) :-
  auto_prop_ai_knowledge_base_target_bucket_arn(KB, B),
  auto_prop_storage_tags_data_classification(B, \"phi\").
""")
print(f"{len(preds)} predicates -> {factsdir}")
